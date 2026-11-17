#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "behavior assertions"
)]

use super::*;
use crate::approval::mainnet_fixtures::{ATTESTATION_KEY, MainnetConsentFixture};
use crate::approval::{AttestedApprover, MainnetPresenceReceipt};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[test]
#[serial_test::serial]
fn canonical_first_consent_uses_signed_facts() {
    let fixture = MainnetConsentFixture::new("canonical-ceremony");
    let policy = fixture.current_policy();
    let (mut entry, intent) = fixture.intent_payment(120_000);
    entry.created_at_unix_ms -= 60_000;
    entry.expires_at_unix_ms -= 60_000;
    let (store, blob) = fixture.intent_consent(&entry, &intent);
    let blob: [u8; 32] = URL_SAFE_NO_PAD
        .decode(blob.unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let receipt = store
        .get(&entry.approval_nonce)
        .unwrap()
        .mainnet_presence
        .clone()
        .unwrap();
    let consent = receipt.verified_at_unix_ms();
    drop(store);
    let admission = fixture.authority().admit().unwrap();
    let store = PendingApprovalStore::open(fixture.store_path()).unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let observed = requests.clone();
    let guard = crate::policy::state_lock::lock_requests::observe(move |_| {
        observed.fetch_add(1, Ordering::SeqCst);
    });
    let verify = |store: &PendingApprovalStore, proof: &[u8; 32], at| {
        verify_intent_consent_admitted(
            store,
            fixture.profile(),
            fixture.name(),
            &entry.approval_nonce,
            proof,
            &intent,
            &policy,
            at,
            &admission,
        )
    };
    for at in [
        consent,
        entry.expires_at_unix_ms - 1,
        entry.expires_at_unix_ms,
        consent + 119_999,
    ] {
        let result = verify(&store, &blob, at);
        assert!(
            result.is_ok(),
            "signed shortened interval verifies at {at}: {result:?}"
        );
        let witness = result.unwrap();
        assert_eq!(
            witness.subject(),
            *intent.digest().as_bytes(),
            "full intent subject"
        );
        assert_eq!(witness.subject_kind(), SubjectKind::IntentDigest);
        assert_eq!(
            witness.created_at_ms(),
            entry.created_at_unix_ms,
            "signed creation survives restart"
        );
        assert_eq!(
            witness.expires_at_ms(),
            entry.expires_at_unix_ms,
            "signed waiting end survives restart"
        );
        assert_eq!(
            witness.consent_at_ms(),
            consent,
            "receipt time survives restart"
        );
        assert_eq!(
            witness.execution_expires_at_ms(),
            consent + 120_000,
            "execution uses signed interval"
        );
        assert_eq!(
            witness.challenge_subject(),
            Some(super::super::mainnet_consent_subject(&entry, &fixture.binding()).unwrap())
        );
    }
    for at in [consent - 1, consent + 120_000, consent + 120_001] {
        assert_eq!(
            verify(&store, &blob, at).unwrap_err().code(),
            "approval.expired",
            "exclusive execution boundaries"
        );
    }
    let mut wrong = blob;
    wrong[0] ^= 1;
    assert_eq!(
        verify(&store, &wrong, consent).unwrap_err().code(),
        "approval.attestation_invalid",
        "HMAC is verified"
    );
    assert_eq!(
        requests.load(Ordering::SeqCst),
        0,
        "admitted verification takes no extra lock"
    );
    drop(guard);
    drop(store);

    for label in [
        "policy",
        "assertion",
        "challenge-subject",
        "lifetime",
        "subject-kind",
    ] {
        let mut altered_entry = entry.clone();
        let mut wire = serde_json::to_value(&receipt).unwrap();
        match label {
            "policy" => wire["policy_digest_hex"] = "77".repeat(32).into(),
            "assertion" => {
                let client = wire["assertion"]["client_data_json"]
                    .as_array_mut()
                    .unwrap();
                assert_eq!(client.pop().unwrap(), serde_json::json!(b'}'));
                client.extend(b",\"extra\":1}".iter().map(|byte| serde_json::json!(byte)));
            }
            "lifetime" => altered_entry.expires_at_unix_ms = consent,
            "challenge-subject" => {
                let super::super::ApprovalKind::PaymentSimulated {
                    envelope_xdr_b64,
                    envelope_sha256_hex,
                    ..
                } = &mut altered_entry.kind
                else {
                    unreachable!()
                };
                *envelope_xdr_b64 = crate::approval::fixtures::payment_envelope(
                    intent.base().source(),
                    crate::approval::mainnet_fixtures::ALLOWED_DESTINATION,
                    "XLM",
                    10,
                    None,
                    100,
                    19,
                );
                *envelope_sha256_hex = crate::hex::encode(
                    &crate::approval::subject::approval_subject_classic(envelope_xdr_b64),
                );
            }
            "subject-kind" => altered_entry.subject_kind = SubjectKind::EnvelopeText,
            _ => unreachable!(),
        }
        let altered: MainnetPresenceReceipt = serde_json::from_value(wire).unwrap();
        let approver = AttestedApprover::MainnetPasskey {
            credential_id_b64url: altered.credential_id_b64url(),
        };
        let proof = crate::approval::attestation::compute_attestation_v6(
            &ATTESTATION_KEY,
            &fixture.binding(),
            &entry.approval_nonce,
            intent.digest().as_bytes(),
            &entry.process_uid,
            &altered_entry.attested_lifetime(),
            &approver,
            &altered,
        );
        let mut forged =
            PendingApprovalStore::open(fixture.home().join(format!("{label}.toml"))).unwrap();
        forged
            .insert(altered_entry, entry.created_at_unix_ms)
            .unwrap();
        forged
            .record_mainnet_attestation_at(
                &entry.approval_nonce,
                proof,
                approver,
                altered,
                None,
                entry.created_at_unix_ms,
            )
            .unwrap();
        let expected = match label {
            "policy" => "approval.presence_policy_unavailable",
            "assertion" | "challenge-subject" => "approval.presence_invalid",
            "lifetime" => "approval.expired",
            _ => "approval.wrong_kind",
        };
        assert_eq!(
            verify(&forged, &proof, consent).unwrap_err().code(),
            expected,
            "first consent refuses {label}"
        );
    }
}
