#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test assertions and cryptographic fixtures"
)]

use super::*;
use crate::approval::{fixtures, mainnet_fixtures::*, witness::*};
use serial_test::serial;
use sha2::Digest as _;
use stellar_agent_test_support::webauthn::{TestAuthenticator, fixture_authenticator};

const NAME: &str = "inspection-test";

fn result(entry: &PendingApproval, now: u64, fixture: &MainnetConsentFixture) -> Inspection {
    inspect_stored_approval(
        InspectionEntry::Pending(entry),
        now,
        NAME,
        fixture.profile(),
        None,
    )
    .unwrap()
}

fn consent(fixture: &MainnetConsentFixture, entry: &PendingApproval) -> PendingApproval {
    let (store, _) = fixture.consent(entry);
    store.get(&entry.approval_nonce).unwrap().clone()
}

fn resign(entry: &mut PendingApproval, binding: &AttestationBinding<'_>) {
    let subject = approval_view_subject(entry, binding).unwrap();
    let blob = crate::approval::compute_attestation_v5(
        &ATTESTATION_KEY,
        binding,
        &entry.approval_nonce,
        &subject,
        &entry.process_uid,
        &entry.attested_lifetime(),
        entry.attested_approver.as_ref().unwrap(),
        entry.mainnet_presence.as_ref().unwrap(),
    );
    entry.attestation_blob_b64 = Some(URL_SAFE_NO_PAD.encode(blob));
}

fn unsupported() -> Vec<PendingApproval> {
    let uid = "123".to_owned();
    let rp = crate::approval::presence::MAINNET_APPROVAL_RP_ID.to_owned();
    vec![
        PendingApproval::new_passkey_pending(
            [0; 32],
            vec![1; 32],
            "CAAAA...AAAAA".into(),
            vec![1],
            [0; 32],
            rp.clone(),
            uid.clone(),
            1000,
        )
        .unwrap(),
        PendingApproval::new_register_passkey_pending(
            "CAAAA...AAAAA".into(),
            vec![1],
            [0; 32],
            rp,
            [0; 32],
            uid.clone(),
            1000,
        )
        .unwrap(),
        PendingApproval::new_toolset_first_invoke_gate_pending(
            "demo".into(),
            "install".into(),
            "1.0.0".into(),
            "a".repeat(64),
            "sign-payment".into(),
            ALLOWED_DESTINATION.into(),
            "XLM".into(),
            1,
            2,
            uid.clone(),
            1000,
        )
        .unwrap(),
        PendingApproval::new_trustline_clawback_opt_in_pending(
            Caip2::Testnet.network_passphrase().into(),
            "USD".into(),
            ALLOWED_DESTINATION.into(),
            uid,
            1000,
        )
        .unwrap(),
        fixtures::rule_proposal_pending(),
        fixtures::mpp_pending(),
    ]
}

#[test]
#[serial]
fn approval_status_context_precedence() {
    let fixture = MainnetConsentFixture::new(NAME);
    let mut entry = consent(&fixture, &fixture.payment(60_000));
    let now = entry
        .mainnet_presence
        .as_ref()
        .unwrap()
        .verified_at_unix_ms();
    let key = &fixture.profile().attestation_key_id;
    keyring_core::Entry::new(&key.service, &key.account)
        .unwrap()
        .delete_credential()
        .unwrap();
    for unsupported in unsupported() {
        assert!(
            matches!(
                InspectionContext::for_entry(
                    InspectionEntry::Pending(&unsupported),
                    NAME,
                    fixture.profile(),
                    None
                ),
                Ok(None)
            ),
            "unsupported skips context"
        );
    }
    let valid_blob = entry.attestation_blob_b64.clone();
    for malformed in [
        None,
        Some("éø".into()),
        Some(URL_SAFE_NO_PAD.encode([1; 31])),
    ] {
        entry.attestation_blob_b64 = malformed;
        assert_eq!(
            result(&entry, now, &fixture).reason,
            InspectionReason::AttestationInvalid,
            "structure precedes key loading"
        );
    }
    entry.attestation_blob_b64 = valid_blob;
    assert_eq!(result(&entry, now, &fixture), Inspection::unavailable());
    keyring_core::Entry::new(&key.service, &key.account)
        .unwrap()
        .set_password(&URL_SAFE_NO_PAD.encode(ATTESTATION_KEY))
        .unwrap();
    entry.attestation_version = 99;
    assert_eq!(result(&entry, now, &fixture), Inspection::unavailable());
    let mut reversed = entry.clone();
    reversed.expires_at_unix_ms = reversed.created_at_unix_ms - 1;
    assert_eq!(
        result(&reversed, now, &fixture).reason,
        InspectionReason::AttestationInvalid,
        "reversed lifetime precedes unavailable provenance"
    );
    entry.attestation_version = 5;
    let blob = entry.attestation_blob_b64.take();
    assert_eq!(
        result(&entry, now, &fixture).reason,
        InspectionReason::AttestationInvalid
    );
    entry.attestation_blob_b64 = blob;
    let receipt = entry.mainnet_presence.take();
    assert_eq!(
        result(&entry, now, &fixture).reason,
        InspectionReason::AttestationInvalid
    );
    entry.mainnet_presence = receipt;
    let mut wrong_destination = entry.clone();
    if let ApprovalKind::PaymentSimulated { summary_to, .. } = &mut wrong_destination.kind {
        *summary_to = format!("{}A", &ALLOWED_DESTINATION[..55]);
    }
    assert_eq!(
        result(&wrong_destination, now, &fixture).reason,
        InspectionReason::AttestationInvalid,
        "invalid stored destination refuses use"
    );
    std::fs::write(fixture.policy_path(), "invalid signed policy").unwrap();
    assert_eq!(result(&entry, now, &fixture), Inspection::unavailable());
}

#[test]
#[serial]
fn inspection_testnet_hmac_and_bindings() {
    let fixture = MainnetConsentFixture::new(NAME);
    let mut profile = fixture.profile().clone();
    profile.chain_id = Caip2::Testnet;
    for mut entry in supported_entries(&fixture, Caip2::Testnet) {
        entry.attested_approver = Some(AttestedApprover::Local);
        entry.attestation_version = 4;
        let binding = AttestationBinding::new(NAME, profile.chain_id.caip2_str());
        let subject = approval_view_subject(&entry, &binding).unwrap();
        let blob = crate::approval::compute_attestation_v4(
            &ATTESTATION_KEY,
            &binding,
            &entry.approval_nonce,
            &subject,
            &entry.process_uid,
            &entry.attested_lifetime(),
            &AttestedApprover::Local,
        );
        entry.attestation_blob_b64 = Some(URL_SAFE_NO_PAD.encode(blob));
        std::fs::write(fixture.policy_path(), "policy must not be read on testnet").unwrap();
        let inspect = |entry: &PendingApproval, name| {
            inspect_stored_approval(
                InspectionEntry::Pending(entry),
                entry.created_at_unix_ms,
                name,
                &profile,
                None,
            )
            .unwrap()
        };
        assert!(
            inspect(&entry, NAME).valid,
            "testnet verifies without policy"
        );
        assert_eq!(
            inspect(&entry, "another-profile").reason,
            InspectionReason::AttestationInvalid
        );
        entry.attestation_blob_b64 = Some(URL_SAFE_NO_PAD.encode([0; 32]));
        assert_eq!(
            inspect(&entry, NAME).reason,
            InspectionReason::AttestationInvalid,
            "HMAC cannot be bypassed"
        );
    }
}

fn x402(chain: Caip2) -> PendingApproval {
    use stellar_xdr::*;
    let account = |byte| {
        ScVal::Address(ScAddress::Account(AccountId(
            PublicKey::PublicKeyTypeEd25519(Uint256([byte; 32])),
        )))
    };
    let root = SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
            contract_address: ScAddress::Contract(ContractId(Hash([3; 32]))),
            function_name: "transfer".try_into().unwrap(),
            args: vec![account(4), account(5), ScVal::from(10_i128)]
                .try_into()
                .unwrap(),
        }),
        sub_invocations: vec![].try_into().unwrap(),
    };
    PendingApproval::new_x402_pending(
        &sha2::Sha256::digest(chain.network_passphrase().as_bytes()).into(),
        &root,
        None,
        crate::approval::process_uid_for_attestation().unwrap(),
        60_000,
    )
    .unwrap()
}

fn supported_entries(fixture: &MainnetConsentFixture, chain: Caip2) -> [PendingApproval; 4] {
    let source = stellar_strkey::ed25519::PublicKey([1; 32]).to_string();
    let uid = crate::approval::process_uid_for_attestation().unwrap();
    [
        fixture.payment(60_000),
        fixtures::claim_pending(&source, [9; 32], None, 100, 7, uid.clone(), 60_000),
        fixtures::trustline_pending(&source, "USD", &source, Some(100), 100, 7, uid, 60_000),
        x402(chain),
    ]
}

#[test]
#[serial]
fn inspection_crypto_and_reason_precedence() {
    let mut fixture = MainnetConsentFixture::new(NAME);
    for pending in supported_entries(&fixture, Caip2::Mainnet) {
        let mut entry = consent(&fixture, &pending);
        let now = entry
            .mainnet_presence
            .as_ref()
            .unwrap()
            .verified_at_unix_ms();
        assert!(result(&entry, now, &fixture).valid, "all four kinds verify");
        let original = entry.clone();
        let mut receipt = serde_json::to_value(entry.mainnet_presence.as_ref().unwrap()).unwrap();
        let bytes = receipt["assertion"]["client_data_json"]
            .as_array_mut()
            .unwrap();
        bytes.pop().unwrap();
        bytes.extend(b",\"extra\":1}".iter().map(|b| serde_json::json!(b)));
        entry.mainnet_presence = Some(serde_json::from_value(receipt).unwrap());
        resign(&mut entry, &fixture.binding());
        assert_eq!(
            result(&entry, now, &fixture).reason,
            InspectionReason::AttestationInvalid,
            "signed assertion is rechecked even with valid HMAC"
        );
        assert_eq!(
            result(&entry, entry.expires_at_unix_ms, &fixture).reason,
            InspectionReason::Expired
        );
        assert_eq!(
            result(&original, original.created_at_unix_ms - 1, &fixture).reason,
            InspectionReason::WindowClosed
        );
    }
    let entry = consent(&fixture, &fixture.payment(60_000));
    let now = entry
        .mainnet_presence
        .as_ref()
        .unwrap()
        .verified_at_unix_ms();
    let other = TestAuthenticator::from_seed([42; 32], vec![77; 32]);
    fixture.sign_policy(&[&other]);
    assert_eq!(
        result(&entry, now, &fixture).reason,
        InspectionReason::PolicyResigned,
        "policy change precedes credential removal"
    );
}

fn durable(fixture: &MainnetConsentFixture, canonical: bool) -> (ApprovalFacts, u64) {
    durable_kind(fixture, canonical, ApprovedKind::Payment)
}

fn durable_kind(
    fixture: &MainnetConsentFixture,
    canonical: bool,
    kind: ApprovedKind,
) -> (ApprovalFacts, u64) {
    use crate::approval::{ClassicIntent, IntentAsset, IntentBase, IntentPayload, MemoFact};
    let index = match kind {
        ApprovedKind::Payment => 0,
        ApprovedKind::Claim => 1,
        ApprovedKind::Trustline => 2,
        ApprovedKind::X402Payment => 3,
    };
    let mut pending = supported_entries(fixture, Caip2::Mainnet)[index].clone();
    let (entry, subject) = if canonical {
        let (payment, payment_intent) = fixture.intent_payment(60_000);
        let source = stellar_strkey::ed25519::PublicKey([1; 32])
            .to_string()
            .to_string();
        let intent = match kind {
            ApprovedKind::Payment => {
                pending = payment;
                payment_intent
            }
            ApprovedKind::Claim | ApprovedKind::Trustline => {
                let payload = if kind == ApprovedKind::Claim {
                    IntentPayload::Claim {
                        balance_id: format!("00000000{}", crate::hex::encode(&[9; 32])),
                        asset: IntentAsset::Native,
                        amount_stroops: 10,
                        claimant: source.clone(),
                    }
                } else {
                    IntentPayload::Trustline {
                        issuer: source.clone(),
                        code: "USD".into(),
                        limit_stroops: 100,
                    }
                };
                ClassicIntent::new(
                    IntentBase::new(
                        Caip2::Mainnet.caip2_str().into(),
                        source,
                        fixture.current_policy().digest(),
                        100,
                        MemoFact::None,
                    )
                    .unwrap(),
                    payload,
                )
                .unwrap()
            }
            ApprovedKind::X402Payment => panic!("x402 has no classic canonical intent"),
        };
        pending.subject_kind = SubjectKind::IntentDigest;
        let (store, _) = fixture.intent_consent(&pending, &intent);
        (
            store.get(&pending.approval_nonce).unwrap().clone(),
            *intent.digest().as_bytes(),
        )
    } else {
        let entry = consent(fixture, &pending);
        let subject = approval_view_subject(&entry, &fixture.binding()).unwrap();
        (entry, subject)
    };
    let receipt = entry.mainnet_presence.clone().unwrap();
    let now = receipt.verified_at_unix_ms();
    let record = ApprovalRecordFacts {
        id: [1; 32],
        operation_id: [2; 16],
        nonce: entry.approval_nonce.clone(),
        disposition: ApprovalDisposition::Pending,
        consumed_at_ms: None,
        revoked_at_ms: None,
        kind,
        subject_kind: entry.subject_kind,
        subject,
        intent_digest: subject,
        created_at_ms: entry.created_at_unix_ms,
        expires_at_ms: entry.expires_at_unix_ms,
        rule_ttl_ms: 60_000,
        consent: Some(ApprovalConsentFacts {
            consent_at_ms: now,
            execution_expires_at_ms: now + 60_000,
            receipt_sha256: receipt.digest().unwrap(),
            payload: Some(ApprovalPayloadFacts {
                attestation: URL_SAFE_NO_PAD
                    .decode(entry.attestation_blob_b64.as_ref().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap(),
                receipt,
                process_uid: entry.process_uid.clone(),
                challenge_subject: canonical
                    .then(|| approval_view_subject(&entry, &fixture.binding()).unwrap()),
                outbox_row: None,
            }),
        }),
    };
    (ApprovalFacts::new(NAME.into(), Caip2::Mainnet, record), now)
}

#[test]
#[serial]
fn inspection_durable_proof_clocks_and_cleanup() {
    let fixture = MainnetConsentFixture::new(NAME);
    for (canonical, kind) in [
        (false, ApprovedKind::Payment),
        (false, ApprovedKind::Claim),
        (false, ApprovedKind::Trustline),
        (false, ApprovedKind::X402Payment),
        (true, ApprovedKind::Payment),
        (true, ApprovedKind::Claim),
        (true, ApprovedKind::Trustline),
    ] {
        let (facts, now) = durable_kind(&fixture, canonical, kind);
        let inspect = |facts: &ApprovalFacts, at| {
            inspect_stored_approval(
                InspectionEntry::Durable(facts),
                at,
                NAME,
                fixture.profile(),
                None,
            )
            .unwrap()
        };
        assert!(
            inspect(&facts, now).valid,
            "retained V5 and V6 proof verifies"
        );
        assert_eq!(
            serde_json::to_value(inspect(&facts, now)).unwrap(),
            serde_json::json!({"valid":true, "reason":"ok"}),
            "verification exposes no proof material"
        );
        assert_eq!(
            inspect(
                &ApprovalFacts::new(
                    "different-profile".into(),
                    Caip2::Mainnet,
                    facts.record().clone()
                ),
                now
            )
            .reason,
            InspectionReason::AttestationInvalid
        );
        assert_eq!(
            inspect(
                &ApprovalFacts::new(NAME.into(), Caip2::Testnet, facts.record().clone()),
                now
            )
            .reason,
            InspectionReason::AttestationInvalid
        );
        assert_eq!(
            inspect(&facts, now + 60_000).reason,
            InspectionReason::Expired
        );
        let mut record = facts.record().clone();
        record.consent.as_mut().unwrap().payload = None;
        let released = ApprovalFacts::new(NAME.into(), Caip2::Mainnet, record.clone());
        assert_eq!(
            inspect(&released, now),
            Inspection::unavailable(),
            "released proof is never reconstructed"
        );
        record.disposition = ApprovalDisposition::Consumed;
        let consumed = ApprovalFacts::new(NAME.into(), Caip2::Mainnet, record.clone());
        assert_eq!(
            inspect(&consumed, u64::MAX).reason,
            InspectionReason::Consumed
        );
        record.disposition = ApprovalDisposition::Revoked;
        let revoked = ApprovalFacts::new(NAME.into(), Caip2::Mainnet, record);
        assert_eq!(inspect(&revoked, 0).reason, InspectionReason::Revoked);
        let mut record = facts.record().clone();
        record.subject[0] ^= 1;
        assert_eq!(
            inspect(
                &ApprovalFacts::new(NAME.into(), Caip2::Mainnet, record),
                now
            )
            .reason,
            InspectionReason::AttestationInvalid
        );
        let mut record = facts.record().clone();
        record.consent.as_mut().unwrap().consent_at_ms += 1;
        assert_eq!(
            inspect(
                &ApprovalFacts::new(NAME.into(), Caip2::Mainnet, record),
                now
            )
            .reason,
            InspectionReason::AttestationInvalid
        );
    }
}

#[test]
#[serial]
fn inspection_policy_kind_and_window_boundaries() {
    let mut fixture = MainnetConsentFixture::new(NAME);
    let mut entry = consent(&fixture, &fixture.payment(60_000));
    let now = entry
        .mainnet_presence
        .as_ref()
        .unwrap()
        .verified_at_unix_ms();
    let other = TestAuthenticator::from_seed([42; 32], vec![77; 32]);
    fixture.sign_policy(&[&other]);
    let policy = fixture.current_policy();
    let mut receipt = serde_json::to_value(entry.mainnet_presence.as_ref().unwrap()).unwrap();
    receipt["policy_digest_hex"] = crate::hex::encode(&policy.digest()).into();
    receipt["policy_sequence"] = policy.sequence().into();
    entry.mainnet_presence = Some(serde_json::from_value(receipt).unwrap());
    resign(&mut entry, &fixture.binding());
    assert_eq!(
        result(&entry, now, &fixture).reason,
        InspectionReason::CredentialRemoved,
        "membership is checked before cryptography"
    );
    assert_eq!(
        result(&entry, entry.expires_at_unix_ms, &fixture).reason,
        InspectionReason::Expired,
        "expiry precedes policy and credential checks"
    );
    let mut profile = fixture.profile().clone();
    profile.chain_id = Caip2::Testnet;
    assert_eq!(
        inspect_stored_approval(InspectionEntry::Pending(&entry), now, NAME, &profile, None)
            .unwrap()
            .reason,
        InspectionReason::AttestationInvalid,
        "mainnet layout cannot verify on testnet"
    );
    let mut mismatched = entry.clone();
    mismatched.attestation_version = 6;
    assert_eq!(
        result(&mismatched, now, &fixture).reason,
        InspectionReason::CredentialRemoved,
        "membership still precedes a known layout mismatch"
    );
    fixture.sign_policy(&[&fixture_authenticator()]);
    let entry = consent(&fixture, &fixture.payment(60_000));
    let now = entry
        .mainnet_presence
        .as_ref()
        .unwrap()
        .verified_at_unix_ms();
    let mut mismatched = entry.clone();
    mismatched.attestation_version = 6;
    assert_eq!(
        result(&mismatched, now, &fixture).reason,
        InspectionReason::KindMismatch,
        "a known layout must match the stored subject kind"
    );
    for window in [
        ExecutionWindow {
            consent_at_ms: now + 1,
            expires_at_ms: now + 10,
        },
        ExecutionWindow {
            consent_at_ms: now - 1,
            expires_at_ms: now,
        },
    ] {
        assert_eq!(
            inspect_stored_approval(
                InspectionEntry::Pending(&entry),
                now,
                NAME,
                fixture.profile(),
                Some(window)
            )
            .unwrap()
            .reason,
            InspectionReason::WindowClosed,
            "external bounds can only narrow consent"
        );
    }
    let (facts, _) = durable(&fixture, true);
    let mut record = facts.record().clone();
    record.created_at_ms = u64::MAX - 60_000;
    record.expires_at_ms = u64::MAX;
    let consent = record.consent.as_mut().unwrap();
    consent.consent_at_ms = u64::MAX - 1000;
    consent.execution_expires_at_ms = u64::MAX;
    let mut receipt = serde_json::to_value(&consent.payload.as_ref().unwrap().receipt).unwrap();
    receipt["issued_at_unix_ms"] = (u64::MAX - 2000).into();
    receipt["verified_at_unix_ms"] = consent.consent_at_ms.into();
    receipt["expires_at_unix_ms"] = u64::MAX.into();
    consent.payload.as_mut().unwrap().receipt = serde_json::from_value(receipt).unwrap();
    let facts = ApprovalFacts::new(NAME.into(), Caip2::Mainnet, record);
    assert_eq!(
        inspect_stored_approval(
            InspectionEntry::Durable(&facts),
            u64::MAX - 500,
            NAME,
            fixture.profile(),
            None
        )
        .unwrap()
        .reason,
        InspectionReason::WindowClosed,
        "execution overflow refuses without saturation"
    );
}

#[test]
#[serial]
fn inspection_read_lock_between_processes() {
    use std::io::{BufRead as _, Write as _};
    const CHILD: &str = "APPROVAL_INSPECTION_CHILD";
    if let Some(path) = std::env::var_os(CHILD) {
        let _store = crate::approval::PendingApprovalStore::open(path.into()).unwrap();
        std::io::stdout()
            .write_all(b"inspection-lock-held\n")
            .unwrap();
        std::io::stdout().flush().unwrap();
        std::io::stdin().read_line(&mut String::new()).unwrap();
        return;
    }
    let fixture = MainnetConsentFixture::new(NAME);
    let entry = consent(&fixture, &fixture.payment(60_000));
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "approval::inspection::tests::inspection_read_lock_between_processes",
            "--nocapture",
        ])
        .env(CHILD, fixture.store_path())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut output = std::io::BufReader::new(child.stdout.take().unwrap());
    loop {
        let mut line = String::new();
        assert!(
            output.read_line(&mut line).unwrap() > 0,
            "child acquired the sidecar"
        );
        if line.contains("inspection-lock-held") {
            break;
        }
    }
    let refused = read_pending_approval(&fixture.store_path(), &entry.approval_nonce);
    child.stdin.take().unwrap().write_all(b"release\n").unwrap();
    assert!(child.wait().unwrap().success());
    assert!(
        matches!(refused, Err(ref error) if error.code() == "approval.store_open_failed"),
        "a separate process excludes inbox reads"
    );
    assert!(
        read_pending_approval(&fixture.store_path(), &entry.approval_nonce)
            .unwrap()
            .is_some(),
        "read succeeds after sidecar release"
    );
}

#[test]
#[serial]
fn approval_status_consumes_nothing_and_compares_pin() {
    let fixture = MainnetConsentFixture::new(NAME);
    let entry = consent(&fixture, &fixture.payment(60_000));
    let now = entry
        .mainnet_presence
        .as_ref()
        .unwrap()
        .verified_at_unix_ms();
    let inbox_before = std::fs::read(fixture.store_path()).unwrap();
    let audit_before = std::fs::read(fixture.audit_path()).unwrap();
    let window_path = crate::profile::schema::default_policy_window_state_path_for(NAME);
    let pin_ref =
        crate::policy::pin::PinScope::for_profile(&window_path, fixture.profile()).pin_entry_ref();
    let pin = keyring_core::Entry::new(&pin_ref.service, &pin_ref.account).unwrap();
    let pin_before = pin.get_password().unwrap();
    for _ in 0..2 {
        assert!(result(&entry, now, &fixture).valid);
    }
    assert_eq!(
        std::fs::read(fixture.store_path()).unwrap(),
        inbox_before,
        "inspection preserves inbox bytes"
    );
    assert_eq!(
        std::fs::read(fixture.audit_path()).unwrap(),
        audit_before,
        "inspection adds no audit row"
    );
    let blob = URL_SAFE_NO_PAD
        .decode(entry.attestation_blob_b64.as_ref().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let mut store = crate::approval::PendingApprovalStore::open(fixture.store_path()).unwrap();
    let expected = ApprovalExpectation {
        kind: ApprovedKind::Payment,
        subject: approval_view_subject(&entry, &fixture.binding()).unwrap(),
    };
    let policy = fixture.current_policy();
    assert!(
        verify_approval(
            &store,
            fixture.profile(),
            NAME,
            &entry.approval_nonce,
            &blob,
            &expected,
            &policy,
            now
        )
        .is_ok()
    );
    let wrong = ApprovalExpectation {
        subject: [0; 32],
        ..expected
    };
    assert!(
        verify_approval(
            &store,
            fixture.profile(),
            NAME,
            &entry.approval_nonce,
            &blob,
            &wrong,
            &policy,
            now
        )
        .is_err(),
        "commit keeps independent subject"
    );
    assert!(
        store
            .consume(
                &entry.approval_nonce,
                &"a".repeat(64),
                crate::approval::ConsumedOutcome::Confirmed
            )
            .unwrap()
    );
    assert_eq!(
        verify_approval(
            &store,
            fixture.profile(),
            NAME,
            &entry.approval_nonce,
            &blob,
            &expected,
            &policy,
            now
        )
        .unwrap_err()
        .code(),
        "approval.consumed",
        "a second commit cannot reuse consumed proof"
    );
    drop(store);
    let new_body = fixture.policy_body(2, &[&fixture_authenticator()]);
    fixture.write_signed(&new_body);
    assert_eq!(
        result(&entry, now, &fixture).reason,
        InspectionReason::PolicyResigned
    );
    assert_eq!(
        pin.get_password().unwrap(),
        pin_before,
        "inspection must not advance the policy pin"
    );
}

#[test]
#[serial]
fn approval_status_strict_open_first_duplicate_and_tombstones() {
    let fixture = MainnetConsentFixture::new(NAME);
    let entry = consent(&fixture, &fixture.payment(60_000));
    let mut second = entry.clone();
    second.kind = ApprovalKind::Rejected {
        original_kind_name: "PaymentSimulated".into(),
    };
    second.attestation_blob_b64 = None;
    second.mainnet_presence = None;
    second.attested_approver = None;
    second.attestation_version = 4;
    #[derive(serde::Serialize)]
    struct File<'a> {
        pending: Vec<&'a PendingApproval>,
    }
    let raw = toml::to_string(&File {
        pending: vec![&entry, &second],
    })
    .unwrap();
    std::fs::write(fixture.store_path(), &raw).unwrap();
    let loaded = read_pending_approval(&fixture.store_path(), &entry.approval_nonce)
        .unwrap()
        .unwrap();
    assert_eq!(
        loaded.kind, entry.kind,
        "status selects the first duplicate"
    );
    assert_eq!(
        std::fs::read_to_string(fixture.store_path()).unwrap(),
        raw,
        "read never collects expired entries"
    );
    let now = u64::MAX;
    assert_eq!(
        result(&second, now, &fixture).reason,
        InspectionReason::Rejected,
        "tombstone precedes expiry and absent proof"
    );
    let locked = crate::approval::PendingApprovalStore::open(fixture.store_path()).unwrap();
    assert_eq!(
        read_pending_approval(&fixture.store_path(), "é")
            .unwrap_err()
            .code(),
        "approval.store_open_failed"
    );
    drop(locked);
    for bad in [
        raw.replace(&entry.approval_nonce, "short"),
        raw.replace("mainnet_passkey", "unknown_kind"),
        raw.replace("signature_compact =", "unknown_receipt_field ="),
    ] {
        std::fs::write(fixture.store_path(), bad).unwrap();
        assert_eq!(
            read_pending_approval(&fixture.store_path(), &entry.approval_nonce)
                .unwrap_err()
                .code(),
            "approval.store_open_failed",
            "strict decoding remains strict"
        );
    }
}

#[test]
fn approval_status_open_failure_matrix() {
    for (error, class) in [
        (ApprovalError::WriterLocked, "lock"),
        (
            ApprovalError::Permission {
                detail: "é秘密".into(),
            },
            "permission",
        ),
        (
            ApprovalError::Toml {
                detail: "é秘密".into(),
            },
            "decoding",
        ),
        (
            ApprovalError::InvalidEntry {
                detail: "é秘密".into(),
            },
            "entry decoding",
        ),
        (
            ApprovalError::InvalidNonceLength {
                expected: 22,
                actual: 1,
            },
            "nonce decoding",
        ),
        (
            ApprovalError::Io {
                kind: std::io::ErrorKind::PermissionDenied,
                source: std::io::Error::other("é秘密"),
            },
            "I/O",
        ),
    ] {
        let mapped = store_open_error(&error);
        assert_eq!(
            mapped.code(),
            "approval.store_open_failed",
            "all status open failures share the wire code"
        );
        assert_eq!(
            mapped.message(),
            format!("approval store open failed: {class}"),
            "only safe cause classes are displayed"
        );
    }
}

#[test]
#[serial]
fn inspection_capacity_preserves_lifecycle() {
    let fixture = MainnetConsentFixture::new(NAME);
    let template = fixture.payment(60_000);
    let mut entries = Vec::new();
    for index in 0_u128..4096 {
        let mut entry = template.clone();
        entry.approval_nonce = URL_SAFE_NO_PAD.encode(index.to_be_bytes());
        entry.attestation_version = 99;
        entry.attestation_blob_b64 = Some(URL_SAFE_NO_PAD.encode([1; 32]));
        entry.attested_approver = Some(AttestedApprover::Local);
        if index == 0 {
            entry.created_at_unix_ms = 0;
            entry.expires_at_unix_ms = 1;
        }
        entries.push(entry);
    }
    #[derive(serde::Serialize)]
    struct File<'a> {
        pending: &'a [PendingApproval],
    }
    let raw = toml::to_string(&File { pending: &entries }).unwrap();
    // Opening an absent inbox establishes only its parent and sidecar.
    drop(crate::approval::PendingApprovalStore::open(fixture.store_path()).unwrap());
    std::fs::write(fixture.store_path(), &raw).unwrap();
    for index in [0, 1, 4095] {
        let selected =
            read_pending_approval(&fixture.store_path(), &entries[index].approval_nonce).unwrap();
        assert_eq!(
            std::fs::read_to_string(fixture.store_path()).unwrap(),
            raw,
            "inspection never reclaims capacity"
        );
        assert!(
            selected.is_some(),
            "expired and unusable records stay selectable"
        );
    }
    let mut store = crate::approval::PendingApprovalStore::open(fixture.store_path()).unwrap();
    store
        .insert(template.clone(), template.created_at_unix_ms)
        .unwrap();
    assert_eq!(
        store.len(),
        4096,
        "admission reclaims only the expired entry"
    );
    assert!(store.get(&entries[0].approval_nonce).is_none());
    assert!(store.get(&entries[1].approval_nonce).is_some());
    assert!(
        store
            .reject(
                &entries[1].approval_nonce,
                template.created_at_unix_ms,
                60_000
            )
            .unwrap(),
        "accepted unusable provenance keeps rejection access"
    );
}
