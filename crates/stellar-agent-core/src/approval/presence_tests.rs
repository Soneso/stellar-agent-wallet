//! Tests of the mainnet presence ceremony: the challenge, the assertion
//! checks, the receipt, the attester's mainnet path and the stored record.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics acceptable in unit tests"
)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serial_test::serial;
use stellar_agent_test_support::webauthn::{
    FLAG_AT, FLAG_BE, FLAG_BS, FLAG_ED, FLAG_UP, FLAG_UV, TestAssertion, TestAuthenticator,
    authenticator_data, fixture_authenticator,
};

use super::*;
use crate::approval::attest::{ConsentAudit, ConsentAuthorization, Surface, attest_and_persist};
use crate::approval::attestation::{
    AttestationScope, AttestedApprover, compute_attestation_v4, compute_attestation_v5,
    verify_attestation,
};
use crate::approval::mainnet_fixtures::{ATTESTATION_KEY, MainnetConsentFixture};
use crate::approval::store::{DEFAULT_TTL_MS, PendingApprovalStore};
use crate::approval::{fixtures, process_uid_for_attestation};
use crate::mainnet::verified_policy::MainnetBody;
use crate::policy::v1::{PolicyDocument, PolicyEngineV1, ScopeId};

/// A change to one consent fact of the challenge preimage.
type FactEdit = Box<dyn Fn(&mut Facts)>;
/// The `clientDataJSON` text of a refused assertion for a challenge.
type ClientData = fn(&str) -> String;
/// A change to the wire form of an assertion.
type WireEdit = fn(&mut MainnetAssertionWire);
/// A change to a stored pending entry's TOML table.
type TableEdit = fn(&mut toml_edit::Table);

const ORIGIN: &str = "http://localhost:4100";
const PROFILE: &str = "main";
const ISSUER: &str = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";

fn engine() -> Arc<PolicyEngineV1> {
    Arc::new(PolicyEngineV1::new(
        PolicyDocument {
            version: 1,
            scope: ScopeId::AllProfiles,
            rules: Vec::new(),
            signature: None,
        },
        PROFILE.to_owned(),
    ))
}

fn credential_of(authenticator: &TestAuthenticator) -> MainnetApprovalCredential {
    MainnetApprovalCredential::from_raw(
        authenticator.credential_id(),
        &authenticator.public_key_sec1(),
    )
    .unwrap()
}

/// A verified mainnet policy for [`PROFILE`] at sequence 7 whose canonical
/// bytes are empty and whose owner is `[9; 32]`.
fn policy_with(credentials: &[&TestAuthenticator]) -> VerifiedPolicy {
    policy_at(7, b"", [9; 32], credentials)
}

fn policy_at(
    sequence: i64,
    canonical: &[u8],
    owner: [u8; 32],
    credentials: &[&TestAuthenticator],
) -> VerifiedPolicy {
    VerifiedPolicy::from_verified(
        sequence,
        canonical,
        owner,
        engine(),
        Some(MainnetBody {
            profile: PROFILE.to_owned(),
            endpoint_host: "rpc.example.invalid".to_owned(),
            installation_nonce_sha256: [3; 32],
            classic_max_fee_per_op_stroops: 500,
            authorization_ttl_seconds: Some(60),
            cross_check_thresholds: None,
            approval_credentials: credentials.iter().map(|a| credential_of(a)).collect(),
            approval_origin: None,
            approval_cert_spki_sha256: None,
        }),
    )
}

fn binding() -> AttestationBinding<'static> {
    AttestationBinding::new(PROFILE, MAINNET_CHAIN_ID)
}

fn now_ms() -> u64 {
    crate::timefmt::now_unix_ms().unwrap()
}

fn payment_of(amount: i64) -> PendingApproval {
    let source = stellar_strkey::ed25519::PublicKey([1; 32]).to_string();
    fixtures::payment_pending(
        &source,
        crate::approval::mainnet_fixtures::ALLOWED_DESTINATION,
        "XLM",
        amount,
        None,
        100,
        7,
        process_uid_for_attestation().unwrap(),
        DEFAULT_TTL_MS,
    )
}

fn payment() -> PendingApproval {
    payment_of(10)
}

fn opt_in(network: &str) -> PendingApproval {
    PendingApproval::new_trustline_clawback_opt_in_pending(
        network.to_owned(),
        "USDC".to_owned(),
        ISSUER.to_owned(),
        process_uid_for_attestation().unwrap(),
        DEFAULT_TTL_MS,
    )
    .unwrap()
}

fn issue(entry: &PendingApproval, policy: &VerifiedPolicy) -> PendingMainnetPresence {
    issue_mainnet_presence(entry, &binding(), policy, ORIGIN, now_ms(), Instant::now()).unwrap()
}

fn input(assertion: &TestAssertion) -> AssertionInput {
    AssertionInput::new(
        assertion.credential_id.clone(),
        assertion.authenticator_data.clone(),
        assertion.client_data_json.clone(),
        assertion.signature_compact.clone(),
    )
    .unwrap()
}

/// Issues a challenge for a payment under `policy`, has `sign` produce the
/// assertion over its challenge, and verifies it now.
fn verify_signed(
    policy: &VerifiedPolicy,
    sign: impl FnOnce(&[u8; 32]) -> TestAssertion,
) -> Result<VerifiedMainnetPresence, WalletError> {
    let pending = issue(&payment(), policy);
    let assertion = sign(&pending.challenge);
    verify_mainnet_presence(pending, input(&assertion), now_ms(), Instant::now())
}

fn code<T: std::fmt::Debug>(result: Result<T, WalletError>) -> String {
    result.unwrap_err().code().to_owned()
}

// ── Challenge ───────────────────────────────────────────────────────────────

/// The owned inputs of one challenge, so each field can be varied alone.
#[derive(Clone)]
struct Facts {
    random: [u8; 32],
    request_id: String,
    entry: PendingApproval,
    profile: String,
    chain: String,
    subject: [u8; 32],
    policy: VerifiedPolicy,
    origin: String,
    issued: u64,
    expires: u64,
}

impl Facts {
    fn challenge(&self) -> [u8; 32] {
        let binding = AttestationBinding::new(&self.profile, &self.chain);
        mainnet_presence_challenge(&ChallengeFacts {
            random: &self.random,
            request_id: &self.request_id,
            entry: &self.entry,
            binding: &binding,
            subject: &self.subject,
            policy: &self.policy,
            rp_id: MAINNET_APPROVAL_RP_ID,
            expected_origin: &self.origin,
            layout: ChallengeLayout::Legacy,
            issued_at_unix_ms: self.issued,
            expires_at_unix_ms: self.expires,
        })
        .unwrap()
    }
}

/// The challenge follows the documented layout with a frozen vector, and
/// every consent field it lists changes it. A receipt for one entry does not
/// verify over an entry that differs only in its subject.
#[test]
fn presence_challenge_binds_every_consent_field() {
    let policy = policy_with(&[&fixture_authenticator()]);
    let mut entry = opt_in(MAINNET_CHAIN_ID);
    "bm9uY2U".clone_into(&mut entry.approval_nonce);
    "1000".clone_into(&mut entry.process_uid);
    entry.created_at_unix_ms = 1_000;
    entry.expires_at_unix_ms = 2_000_000;
    let subject = mainnet_consent_subject(&entry, &binding()).unwrap();
    let base = Facts {
        random: [1; 32],
        request_id: "00000000-0000-4000-8000-000000000001".to_owned(),
        entry: entry.clone(),
        profile: PROFILE.to_owned(),
        chain: MAINNET_CHAIN_ID.to_owned(),
        subject,
        policy: policy.clone(),
        origin: ORIGIN.to_owned(),
        issued: 5_000,
        expires: 65_000,
    };
    assert_eq!(
        crate::hex::encode(&approval_view_digest(&entry, &binding()).unwrap()),
        "222d207e1cb41099b23a312cc11e9c98e7b6769a24379f64b84441cddb3f0120"
    );
    assert_eq!(
        crate::hex::encode(&base.challenge()),
        "2f60f36c17ce1bc6a6eaac0cbc5062b3afed68c1d91ec7a434723e8f805d35a4"
    );
    assert_eq!(
        crate::hex::encode(&mainnet_consent_view_digest(&entry, &binding(), &policy).unwrap()),
        "9292abb6c68083708af06c1d8cf9795593bbe968206e6897d314ac3c0870c4f9"
    );

    let variants: Vec<(&str, FactEdit)> = vec![
        ("random", Box::new(|f| f.random[0] ^= 1)),
        ("request id", Box::new(|f| f.request_id.push('0'))),
        ("nonce", Box::new(|f| f.entry.approval_nonce.push('A'))),
        ("profile", Box::new(|f| f.profile.push('x'))),
        (
            "chain",
            Box::new(|f| "stellar:testnet".clone_into(&mut f.chain)),
        ),
        ("kind", Box::new(|f| f.entry.kind = payment().kind)),
        ("subject", Box::new(|f| f.subject[0] ^= 1)),
        ("process uid", Box::new(|f| f.entry.process_uid.push('1'))),
        ("created", Box::new(|f| f.entry.created_at_unix_ms += 1)),
        ("expires", Box::new(|f| f.entry.expires_at_unix_ms += 1)),
        (
            "policy sequence",
            Box::new(|f| f.policy = policy_at(8, b"", [9; 32], &[&fixture_authenticator()])),
        ),
        (
            "policy digest",
            Box::new(|f| f.policy = policy_at(7, b"x", [9; 32], &[&fixture_authenticator()])),
        ),
        (
            "policy owner",
            Box::new(|f| f.policy = policy_at(7, b"", [10; 32], &[&fixture_authenticator()])),
        ),
        (
            "origin",
            Box::new(|f| "http://localhost:4101".clone_into(&mut f.origin)),
        ),
        ("issued", Box::new(|f| f.issued += 1)),
        ("challenge expiry", Box::new(|f| f.expires += 1)),
    ];
    let reference = base.challenge();
    for (label, vary) in variants {
        let mut varied = base.clone();
        vary(&mut varied);
        assert_ne!(varied.challenge(), reference, "{label}");
    }

    let policy = policy_with(&[&fixture_authenticator()]);
    let consented = payment_of(10);
    let pending = issue(&consented, &policy);
    let assertion = fixture_authenticator().assert(
        pending.challenge,
        ORIGIN,
        MAINNET_APPROVAL_RP_ID,
        FLAG_UP | FLAG_UV,
        1,
    );
    let receipt = verify_mainnet_presence(pending, input(&assertion), now_ms(), Instant::now())
        .unwrap()
        .into_parts()
        .receipt;
    assert!(verify_receipt(&consented, &receipt, &binding(), &policy, now_ms()).is_ok());
    let mut other = payment_of(11);
    other.approval_nonce.clone_from(&consented.approval_nonce);
    other.process_uid.clone_from(&consented.process_uid);
    other.created_at_unix_ms = consented.created_at_unix_ms;
    other.expires_at_unix_ms = consented.expires_at_unix_ms;
    assert_ne!(
        mainnet_consent_subject(&other, &binding()).unwrap(),
        mainnet_consent_subject(&consented, &binding()).unwrap()
    );
    assert_eq!(
        code(verify_receipt(
            &other,
            &receipt,
            &binding(),
            &policy,
            now_ms()
        )),
        "approval.presence_invalid"
    );
}

/// The subject of each supported kind, and the refusal of every other.
#[test]
fn consent_subject_covers_supported_kinds_only() {
    let payment = payment();
    let ApprovalKind::PaymentSimulated {
        envelope_xdr_b64, ..
    } = &payment.kind
    else {
        unreachable!()
    };
    assert_eq!(
        mainnet_consent_subject(&payment, &binding()).unwrap(),
        crate::approval::subject::approval_subject_classic(envelope_xdr_b64)
    );
    assert_eq!(
        mainnet_consent_subject(&opt_in(MAINNET_CHAIN_ID), &binding()).unwrap(),
        crate::approval::attestation::compute_trustline_clawback_opt_in_digest(
            MAINNET_CHAIN_ID,
            "USDC",
            ISSUER
        )
    );
    assert_eq!(
        code(mainnet_consent_subject(
            &opt_in("stellar:testnet"),
            &binding()
        )),
        "approval.binding_mismatch"
    );
    let gate = PendingApproval::new_toolset_first_invoke_gate_pending(
        "toolset".to_owned(),
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        "1.0.0".to_owned(),
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_owned(),
        "sign-payment".to_owned(),
        "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
        "XLM".to_owned(),
        0,
        1,
        process_uid_for_attestation().unwrap(),
        DEFAULT_TTL_MS,
    )
    .unwrap();
    let error = mainnet_consent_subject(&gate, &binding()).unwrap_err();
    assert_eq!(error.code(), "approval.wrong_kind");
    assert!(
        error.to_string().contains(UNSUPPORTED_KIND_MESSAGE),
        "{error}"
    );
}

// ── Issue ───────────────────────────────────────────────────────────────────

/// The issuer refuses another chain, a policy that cannot authorize the
/// profile, an origin of another shape, and an entry that is not live and
/// unattested; the challenge lives for the shorter of 120 seconds and the
/// entry's remaining life.
#[test]
fn issue_refuses_unusable_inputs_and_bounds_the_challenge() {
    let policy = policy_with(&[&fixture_authenticator()]);
    let entry = payment();
    let now = now_ms() + 1_000;
    let issue_with = |entry: &PendingApproval,
                      binding: &AttestationBinding<'_>,
                      policy: &VerifiedPolicy,
                      origin: &str| {
        issue_mainnet_presence(entry, binding, policy, origin, now, Instant::now())
    };
    assert_eq!(
        code(issue_with(
            &entry,
            &AttestationBinding::new(PROFILE, "stellar:testnet"),
            &policy,
            ORIGIN
        )),
        "approval.binding_mismatch"
    );
    let no_mainnet = VerifiedPolicy::from_verified(7, b"", [9; 32], engine(), None);
    let no_credentials = policy_with(&[]);
    for refused in [&no_mainnet, &no_credentials] {
        assert_eq!(
            code(issue_with(&entry, &binding(), refused, ORIGIN)),
            "approval.presence_policy_unavailable"
        );
    }
    assert_eq!(
        code(issue_with(
            &entry,
            &AttestationBinding::new("other", MAINNET_CHAIN_ID),
            &policy,
            ORIGIN
        )),
        "approval.presence_policy_unavailable"
    );
    for origin in [
        "https://localhost:4100",
        "http://localhost",
        "http://localhost:",
        "http://localhost:0",
        "http://localhost:04100",
        "http://localhost:65536",
        "http://localhost:4100/",
        "http://127.0.0.1:4100",
        "http://LOCALHOST:4100",
        "http://localhost:+4100",
    ] {
        assert_eq!(
            code(issue_with(&entry, &binding(), &policy, origin)),
            "approval.presence_invalid",
            "{origin}"
        );
    }
    assert!(is_mainnet_presence_origin("http://localhost:1"));
    assert!(is_mainnet_presence_origin("http://localhost:65535"));

    let mut future = payment();
    future.created_at_unix_ms = now + 60_000;
    future.expires_at_unix_ms = future.created_at_unix_ms + DEFAULT_TTL_MS;
    let mut expired = payment();
    expired.expires_at_unix_ms = now;
    for refused in [future, expired] {
        assert_eq!(
            code(issue_with(&refused, &binding(), &policy, ORIGIN)),
            "approval.expired"
        );
    }
    let mut attested = payment();
    attested.attestation_blob_b64 = Some(URL_SAFE_NO_PAD.encode([1; 32]));
    assert_eq!(
        code(issue_with(&attested, &binding(), &policy, ORIGIN)),
        "approval.already_attested"
    );

    let full = issue_with(&entry, &binding(), &policy, ORIGIN).unwrap();
    let options = full.options();
    assert_eq!(
        options.expires_at_unix_ms,
        now + MAINNET_PRESENCE_CHALLENGE_TTL_MS
    );
    assert_eq!(options.timeout_ms, 120_000);
    assert_eq!(options.rp_id, MAINNET_APPROVAL_RP_ID);
    assert_eq!(
        options.allow_credentials,
        vec![fixture_authenticator().credential_id_b64url()]
    );
    assert_eq!(options.request_id, full.request_id());
    assert_eq!(options.challenge, URL_SAFE_NO_PAD.encode(full.challenge));
    assert_eq!(full.approval_nonce(), entry.approval_nonce);
    assert_eq!(full.expected_origin(), ORIGIN);
    assert!(is_canonical_uuid_v4(full.request_id()));

    let mut short = payment();
    short.expires_at_unix_ms = now + 30_000;
    let bounded = issue_with(&short, &binding(), &policy, ORIGIN).unwrap();
    assert_eq!(bounded.options().expires_at_unix_ms, now + 30_000);
    assert_eq!(bounded.options().timeout_ms, 30_000);
    let again = issue_with(&entry, &binding(), &policy, ORIGIN).unwrap();
    assert_ne!(
        again.challenge, full.challenge,
        "every issue draws fresh randomness"
    );
}

// ── Assertion checks ────────────────────────────────────────────────────────

/// UP and UV are both required, BS requires BE, and the reserved, AT and ED
/// bits refuse.
#[test]
fn presence_requires_up_uv_and_valid_backup_flags() {
    let authenticator = fixture_authenticator();
    let policy = policy_with(&[&authenticator]);
    let with_flags = |flags: u8| {
        verify_signed(&policy, |challenge| {
            authenticator.assert(*challenge, ORIGIN, MAINNET_APPROVAL_RP_ID, flags, 1)
        })
    };
    for accepted in [
        FLAG_UP | FLAG_UV,
        FLAG_UP | FLAG_UV | FLAG_BE,
        FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS,
    ] {
        assert!(with_flags(accepted).is_ok(), "{accepted:#04x}");
    }
    for refused in [
        0,
        FLAG_UP,
        FLAG_UV,
        FLAG_UP | FLAG_UV | FLAG_BS,
        FLAG_UP | FLAG_UV | 0x02,
        FLAG_UP | FLAG_UV | 0x20,
        FLAG_UP | FLAG_UV | FLAG_AT,
        FLAG_UP | FLAG_UV | FLAG_ED,
    ] {
        assert_eq!(
            code(with_flags(refused)),
            "approval.presence_invalid",
            "{refused:#04x}"
        );
    }
}

/// `clientDataJSON` must name `webauthn.get`, the challenge and the exact
/// expected origin, with `crossOrigin` absent or `false` and no
/// `topOrigin`; the authenticator data must carry the `localhost` RP-ID
/// hash. The signature covers the original bytes, whatever their member
/// order or spacing.
#[test]
fn presence_checks_origin_rp_and_original_json() {
    let authenticator = fixture_authenticator();
    let policy = policy_with(&[&authenticator]);
    let flags = FLAG_UP | FLAG_UV;
    let raw = |rp_id: &'static str, json: fn(&str) -> String| {
        verify_signed(&policy, |challenge| {
            let encoded = URL_SAFE_NO_PAD.encode(challenge);
            authenticator.sign_raw(
                authenticator_data(rp_id, flags, 1),
                json(&encoded).into_bytes(),
            )
        })
    };
    let accepted: [fn(&str) -> String; 3] = [
        |c| {
            format!(
                r#"{{"type":"webauthn.get","challenge":"{c}","origin":"http://localhost:4100"}}"#
            )
        },
        |c| {
            format!(
                r#"{{ "origin" : "http://localhost:4100", "crossOrigin": false, "challenge":"{c}", "type":"webauthn.get", "other": [1, {{"x": null}}] }}"#
            )
        },
        |c| {
            format!(
                r#"{{"type":"webauthn.get","challenge":"{c}","origin":"http://localhost:4100","crossOrigin":false}}"#
            )
        },
    ];
    for (index, json) in accepted.into_iter().enumerate() {
        assert!(
            raw(MAINNET_APPROVAL_RP_ID, json).is_ok(),
            "accepted {index}"
        );
    }
    let refused: [(&str, ClientData); 10] = [
        ("other origin", |c| {
            format!(
                r#"{{"type":"webauthn.get","challenge":"{c}","origin":"http://localhost:4101"}}"#
            )
        }),
        ("https origin", |c| {
            format!(
                r#"{{"type":"webauthn.get","challenge":"{c}","origin":"https://localhost:4100"}}"#
            )
        }),
        ("create type", |c| {
            format!(
                r#"{{"type":"webauthn.create","challenge":"{c}","origin":"http://localhost:4100"}}"#
            )
        }),
        ("cross origin", |c| {
            format!(
                r#"{{"type":"webauthn.get","challenge":"{c}","origin":"http://localhost:4100","crossOrigin":true}}"#
            )
        }),
        ("cross origin text", |c| {
            format!(
                r#"{{"type":"webauthn.get","challenge":"{c}","origin":"http://localhost:4100","crossOrigin":"false"}}"#
            )
        }),
        ("cross origin null", |c| {
            format!(
                r#"{{"type":"webauthn.get","challenge":"{c}","origin":"http://localhost:4100","crossOrigin":null}}"#
            )
        }),
        ("top origin", |c| {
            format!(
                r#"{{"type":"webauthn.get","challenge":"{c}","origin":"http://localhost:4100","topOrigin":"http://localhost:4100"}}"#
            )
        }),
        ("duplicate origin", |c| {
            format!(
                r#"{{"type":"webauthn.get","challenge":"{c}","origin":"http://localhost:4101","origin":"http://localhost:4100"}}"#
            )
        }),
        ("other challenge", |_| {
            format!(
                r#"{{"type":"webauthn.get","challenge":"{}","origin":"http://localhost:4100"}}"#,
                URL_SAFE_NO_PAD.encode([0; 32])
            )
        }),
        ("not json", |c| format!("type=webauthn.get&challenge={c}")),
    ];
    for (label, json) in refused {
        assert_eq!(
            code(raw(MAINNET_APPROVAL_RP_ID, json)),
            "approval.presence_invalid",
            "{label}"
        );
    }
    assert_eq!(
        code(raw("example.com", accepted[0])),
        "approval.presence_invalid",
        "another RP-ID hash"
    );
    assert_eq!(
        code(verify_signed(&policy, |challenge| {
            let mut assertion =
                authenticator.assert(*challenge, ORIGIN, MAINNET_APPROVAL_RP_ID, flags, 1);
            assertion.client_data_json.push(b' ');
            assertion
        })),
        "approval.presence_invalid",
        "bytes changed after signing"
    );
    assert_eq!(
        code(verify_signed(&policy, |challenge| {
            let mut assertion =
                authenticator.assert(*challenge, ORIGIN, MAINNET_APPROVAL_RP_ID, flags, 1);
            assertion.authenticator_data.push(0);
            assertion
        })),
        "approval.presence_invalid",
        "authenticator data beyond 37 bytes"
    );
}

/// The verifier uses the key the policy signs for the selected credential
/// ID: each listed credential verifies under its own key, a signature by
/// another key under a listed ID refuses, and a credential the policy does
/// not list refuses although the operator-credential store holds it.
#[test]
#[serial]
fn presence_uses_the_signed_key_for_the_selected_id() {
    let fixture = MainnetConsentFixture::new(PROFILE);
    let own = fixture_authenticator();
    let second = TestAuthenticator::from_seed([0x33; 32], vec![0x44; 20]);
    let unlisted = TestAuthenticator::from_seed([0x55; 32], vec![0x66; 32]);
    let policy = policy_with(&[&own, &second]);
    for authenticator in [&own, &second] {
        let verified = verify_signed(&policy, |challenge| {
            authenticator.assert(
                *challenge,
                ORIGIN,
                MAINNET_APPROVAL_RP_ID,
                FLAG_UP | FLAG_UV,
                1,
            )
        })
        .unwrap();
        assert_eq!(
            verified.credential_fingerprint(),
            credential_of(authenticator).fingerprint()
        );
    }
    assert_eq!(
        code(verify_signed(&policy, |challenge| {
            let mut assertion = second.assert(
                *challenge,
                ORIGIN,
                MAINNET_APPROVAL_RP_ID,
                FLAG_UP | FLAG_UV,
                1,
            );
            assertion.credential_id = own.credential_id().to_vec();
            assertion
        })),
        "approval.presence_invalid",
        "a listed ID signed by another key"
    );

    let store = crate::approval::operator_credentials::OperatorApprovalCredentialStore::new(
        crate::approval::operator_credentials::default_operator_approval_credentials_path(PROFILE)
            .unwrap(),
    );
    store
        .enroll(
            crate::approval::operator_credentials::OperatorApprovalCredential {
                credential_id_b64url: unlisted.credential_id_b64url(),
                public_key_sec1_b64: unlisted.public_key_sec1_b64url(),
                rp_id: MAINNET_APPROVAL_RP_ID.to_owned(),
                label: "unlisted".to_owned(),
                registered_at_unix_ms: now_ms(),
                sign_count: None,
                source: crate::approval::OperatorCredentialSource::Enrolled,
            },
        )
        .unwrap();
    assert!(
        store
            .find_by_credential_id(&unlisted.credential_id_b64url())
            .unwrap()
            .is_some()
    );
    assert_eq!(
        code(verify_signed(&policy, |challenge| {
            unlisted.assert(
                *challenge,
                ORIGIN,
                MAINNET_APPROVAL_RP_ID,
                FLAG_UP | FLAG_UV,
                1,
            )
        })),
        "approval.presence_invalid",
        "a credential only the operator store holds"
    );
    drop(fixture);
}

/// Counters are recorded only: zero, repeated and decreasing counters all
/// verify with fresh challenges, while an assertion for one challenge never
/// verifies against another.
#[test]
fn counter_values_do_not_replace_fresh_challenges() {
    let authenticator = fixture_authenticator();
    let policy = policy_with(&[&authenticator]);
    for count in [5, 5, 0, 3] {
        let verified = verify_signed(&policy, |challenge| {
            authenticator.assert(
                *challenge,
                ORIGIN,
                MAINNET_APPROVAL_RP_ID,
                FLAG_UP | FLAG_UV,
                count,
            )
        })
        .unwrap();
        let parts = verified.into_parts();
        let stored =
            verify_receipt(&parts.entry, &parts.receipt, &binding(), &policy, now_ms()).unwrap();
        assert_eq!(stored.facts.sign_count, count);
    }
    let first = issue(&payment(), &policy);
    let replayed = authenticator.assert(
        first.challenge,
        ORIGIN,
        MAINNET_APPROVAL_RP_ID,
        FLAG_UP | FLAG_UV,
        9,
    );
    let second = issue(&payment(), &policy);
    assert_eq!(
        code(verify_mainnet_presence(
            second,
            input(&replayed),
            now_ms(),
            Instant::now()
        )),
        "approval.presence_invalid"
    );
}

/// The verifier refuses outside the challenge's life on either clock and a
/// wall clock before issuance.
#[test]
fn verify_refuses_outside_the_challenge_life() {
    let authenticator = fixture_authenticator();
    let policy = policy_with(&[&authenticator]);
    let entry = payment();
    let issued_ms = now_ms();
    let issued = Instant::now();
    let attempt = |now_ms: u64, now: Instant| {
        let pending =
            issue_mainnet_presence(&entry, &binding(), &policy, ORIGIN, issued_ms, issued).unwrap();
        let assertion = authenticator.assert(
            pending.challenge,
            ORIGIN,
            MAINNET_APPROVAL_RP_ID,
            FLAG_UP | FLAG_UV,
            1,
        );
        verify_mainnet_presence(pending, input(&assertion), now_ms, now)
    };
    let ttl = MAINNET_PRESENCE_CHALLENGE_TTL_MS;
    assert!(attempt(issued_ms, issued).is_ok());
    assert!(attempt(issued_ms + ttl - 1, issued).is_ok());
    for (label, now_ms, now) in [
        ("wall expiry", issued_ms + ttl, issued),
        ("wall before issue", issued_ms - 1, issued),
        (
            "monotonic expiry",
            issued_ms,
            issued + Duration::from_millis(ttl),
        ),
    ] {
        assert_eq!(
            code(attempt(now_ms, now)),
            "approval.presence_expired",
            "{label}"
        );
    }
}

/// Each receipt field refuses during decoding at one byte over its bound.
#[test]
fn receipt_wire_bounds_reject_before_construction() {
    let policy = policy_with(&[&fixture_authenticator()]);
    let receipt = verified_receipt(&policy, &payment());
    let wire = serde_json::to_value(&receipt).unwrap();
    for (field, bound) in [
        ("request_id", RECEIPT_REQUEST_ID_MAX_BYTES),
        ("random_b64url", RECEIPT_RANDOM_MAX_BYTES),
        ("policy_digest_hex", RECEIPT_HEX_MAX_BYTES),
        ("policy_owner_hex", RECEIPT_HEX_MAX_BYTES),
        ("expected_origin", RECEIPT_ORIGIN_MAX_BYTES),
    ] {
        let mut at_bound = wire.clone();
        at_bound[field] = serde_json::json!("x".repeat(bound));
        assert!(
            serde_json::from_value::<ReceiptWire>(at_bound).is_ok(),
            "{field}"
        );
        let mut oversized = wire.clone();
        oversized[field] = serde_json::json!("x".repeat(bound + 1));
        let error = serde_json::from_str::<ReceiptWire>(&oversized.to_string())
            .err()
            .unwrap();
        assert!(
            error.to_string().contains("string exceeds its byte bound"),
            "{field}: {error}"
        );
    }
    for (field, bound) in [
        ("credential_id", CREDENTIAL_ID_MAX_BYTES),
        ("authenticator_data", MAINNET_AUTHENTICATOR_DATA_BYTES),
        ("client_data_json", MAINNET_CLIENT_DATA_JSON_MAX_BYTES),
        ("signature_compact", RECEIPT_SIGNATURE_BYTES),
    ] {
        let mut at_bound = wire.clone();
        at_bound["assertion"][field] = serde_json::json!(vec![0_u8; bound]);
        assert!(
            serde_json::from_value::<ReceiptWire>(at_bound).is_ok(),
            "{field}"
        );
        let mut oversized = wire.clone();
        oversized["assertion"][field] = serde_json::json!(vec![0_u8; bound + 1]);
        let error = serde_json::from_str::<ReceiptWire>(&oversized.to_string())
            .err()
            .unwrap();
        assert!(
            error.to_string().contains("array exceeds its byte bound"),
            "{field}: {error}"
        );
    }
    let mut at_bound = receipt;
    at_bound
        .assertion
        .client_data_json
        .resize(MAINNET_CLIENT_DATA_JSON_MAX_BYTES, b' ');
    assert!(
        serde_json::from_str::<MainnetPresenceReceipt>(&serde_json::to_string(&at_bound).unwrap())
            .is_ok()
    );
}

/// The store caps the receipt's serialized span before decoding its fields.
#[test]
#[serial]
fn pending_store_caps_serialized_presence_receipt() {
    let fixture = MainnetConsentFixture::new(PROFILE);
    let entry = fixture.payment(DEFAULT_TTL_MS);
    let (store, _) = fixture.consent(&entry);
    drop(store);
    let raw = std::fs::read_to_string(fixture.store_path()).unwrap();
    let padding = " ".repeat(MAINNET_PRESENCE_RECEIPT_MAX_BYTES);
    let oversized = raw.replace(
        "client_data_json = [",
        &format!("client_data_json = [{padding}"),
    );
    assert_ne!(raw, oversized);
    std::fs::write(fixture.store_path(), oversized).unwrap();
    let error = PendingApprovalStore::open(fixture.store_path()).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("mainnet_presence exceeds its serialized byte bound"),
        "{error}"
    );
    std::fs::write(fixture.store_path(), raw).unwrap();
    assert!(PendingApprovalStore::open(fixture.store_path()).is_ok());
}

/// The wire form decodes canonical, bounded fields and normalizes the
/// signature to low S; padding, noncanonical text, out-of-bound lengths,
/// non-DER signatures and unknown members refuse.
#[test]
fn assertion_wire_decodes_canonical_bounded_fields() {
    let authenticator = fixture_authenticator();
    let assertion = authenticator.assert(
        [7; 32],
        ORIGIN,
        MAINNET_APPROVAL_RP_ID,
        FLAG_UP | FLAG_UV,
        1,
    );
    let wire = |assertion: &TestAssertion| MainnetAssertionWire {
        credential_id_b64url: URL_SAFE_NO_PAD.encode(&assertion.credential_id),
        authenticator_data_b64url: URL_SAFE_NO_PAD.encode(&assertion.authenticator_data),
        client_data_json_b64url: URL_SAFE_NO_PAD.encode(&assertion.client_data_json),
        signature_der_b64url: URL_SAFE_NO_PAD.encode(&assertion.signature_der),
    };
    let decoded = wire(&assertion).decode().unwrap();
    assert_eq!(decoded.credential_id, assertion.credential_id);
    assert_eq!(decoded.authenticator_data, assertion.authenticator_data);
    assert_eq!(decoded.client_data_json, assertion.client_data_json);
    assert_eq!(decoded.signature_compact, assertion.signature_compact);

    let signature = p256::ecdsa::Signature::from_slice(&assertion.signature_compact).unwrap();
    let (r, s) = signature.split_scalars();
    let high = p256::ecdsa::Signature::from_scalars(r, -*s).unwrap();
    assert!(high.normalize_s().is_some(), "the negated S is high");
    let mut high_s = assertion.clone();
    high_s.signature_der = high.to_der().as_bytes().to_vec();
    assert_eq!(
        wire(&high_s).decode().unwrap().signature_compact,
        assertion.signature_compact
    );

    let edits: [(&str, WireEdit); 9] = [
        ("padded id", |w| w.credential_id_b64url.push_str("==")),
        ("noncanonical id", |w| {
            w.credential_id_b64url.pop();
            w.credential_id_b64url.push('h');
        }),
        ("short id", |w| {
            w.credential_id_b64url = URL_SAFE_NO_PAD.encode([1; 15])
        }),
        ("long id", |w| {
            w.credential_id_b64url = URL_SAFE_NO_PAD.encode([1; 65])
        }),
        ("short authenticator data", |w| {
            w.authenticator_data_b64url = URL_SAFE_NO_PAD.encode([1; 36]);
        }),
        ("long client data", |w| {
            w.client_data_json_b64url = URL_SAFE_NO_PAD.encode([b' '; 1025]);
        }),
        ("empty client data", |w| w.client_data_json_b64url.clear()),
        ("compact signature", |w| {
            w.signature_der_b64url = URL_SAFE_NO_PAD.encode([1; 64]);
        }),
        ("standard alphabet", |w| {
            w.signature_der_b64url =
                base64::engine::general_purpose::STANDARD_NO_PAD.encode([0xfb; 70]);
        }),
    ];
    for (label, edit) in edits {
        let mut edited = wire(&assertion);
        edit(&mut edited);
        assert_eq!(
            code(edited.decode()),
            "approval.presence_invalid",
            "{label}"
        );
    }
    let unknown = serde_json::json!({
        "credential_id_b64url": "WlpaWlpaWlpaWlpaWlpaWg",
        "authenticator_data_b64url": "AA",
        "client_data_json_b64url": "AA",
        "signature_der_b64url": "AA",
        "extra": 1,
    });
    assert!(serde_json::from_value::<MainnetAssertionWire>(unknown).is_err());
    assert_eq!(
        format!("{:?}", wire(&assertion)),
        "MainnetAssertionWire { .. }"
    );
}

/// Credential encodings are canonical and validated, and the fingerprint
/// follows its documented layout.
#[test]
fn approval_credential_encoding_is_canonical() {
    use stellar_agent_test_support::webauthn::{
        FIXTURE_CREDENTIAL_ID_B64URL, FIXTURE_PUBLIC_KEY_B64URL,
    };
    let credential = MainnetApprovalCredential::from_encoded(
        FIXTURE_CREDENTIAL_ID_B64URL,
        FIXTURE_PUBLIC_KEY_B64URL,
    )
    .unwrap();
    assert_eq!(credential.credential_id(), &[0x5a; 16]);
    assert_eq!(
        credential.credential_id_b64url(),
        FIXTURE_CREDENTIAL_ID_B64URL
    );
    assert_eq!(
        credential.public_key_sec1_b64url(),
        FIXTURE_PUBLIC_KEY_B64URL
    );
    assert_eq!(
        credential.fingerprint(),
        "sha256:b9f6bc940fc4bfce78f0b0704bb397d4e6bdd68b7240f580236c4d356927443d"
    );
    assert_eq!(
        credential.policy_entry_toml(),
        format!(
            "{{ credential_id_b64url = \"{FIXTURE_CREDENTIAL_ID_B64URL}\", public_key_sec1_b64url = \"{FIXTURE_PUBLIC_KEY_B64URL}\" }}"
        )
    );
    let debug = format!("{credential:?}");
    assert!(
        !debug.contains(FIXTURE_CREDENTIAL_ID_B64URL) && !debug.contains(FIXTURE_PUBLIC_KEY_B64URL)
    );

    let key = fixture_authenticator().public_key_sec1();
    let mut compressed = key[..33].to_vec();
    compressed[0] = 0x02 | (key[64] & 1);
    let mut off_curve = key;
    off_curve[64] ^= 1;
    for (label, id, public_key, expected) in [
        (
            "padded id",
            format!("{FIXTURE_CREDENTIAL_ID_B64URL}=="),
            FIXTURE_PUBLIC_KEY_B64URL.to_owned(),
            ApprovalCredentialError::CredentialId,
        ),
        (
            "short id",
            URL_SAFE_NO_PAD.encode([1; 15]),
            FIXTURE_PUBLIC_KEY_B64URL.to_owned(),
            ApprovalCredentialError::CredentialId,
        ),
        (
            "long id",
            URL_SAFE_NO_PAD.encode([1; 65]),
            FIXTURE_PUBLIC_KEY_B64URL.to_owned(),
            ApprovalCredentialError::CredentialId,
        ),
        (
            "noncanonical id",
            "WlpaWlpaWlpaWlpaWlpaWh".to_owned(),
            FIXTURE_PUBLIC_KEY_B64URL.to_owned(),
            ApprovalCredentialError::CredentialId,
        ),
        (
            "compressed key",
            FIXTURE_CREDENTIAL_ID_B64URL.to_owned(),
            URL_SAFE_NO_PAD.encode(&compressed),
            ApprovalCredentialError::PublicKey,
        ),
        (
            "off-curve key",
            FIXTURE_CREDENTIAL_ID_B64URL.to_owned(),
            URL_SAFE_NO_PAD.encode(off_curve),
            ApprovalCredentialError::PublicKey,
        ),
        (
            "padded key",
            FIXTURE_CREDENTIAL_ID_B64URL.to_owned(),
            format!("{FIXTURE_PUBLIC_KEY_B64URL}="),
            ApprovalCredentialError::PublicKey,
        ),
    ] {
        assert_eq!(
            MainnetApprovalCredential::from_encoded(&id, &public_key).unwrap_err(),
            expected,
            "{label}"
        );
    }
}

// ── Receipt ─────────────────────────────────────────────────────────────────

fn verified_receipt(policy: &VerifiedPolicy, entry: &PendingApproval) -> MainnetPresenceReceipt {
    let pending = issue(entry, policy);
    let assertion = fixture_authenticator().assert(
        pending.challenge,
        ORIGIN,
        MAINNET_APPROVAL_RP_ID,
        FLAG_UP | FLAG_UV,
        1,
    );
    verify_mainnet_presence(pending, input(&assertion), now_ms(), Instant::now())
        .unwrap()
        .into_parts()
        .receipt
}

/// A version 5 attestation binds its receipt: another ceremony's receipt
/// for the same entry gives another blob, and the scope admits a receipt
/// only with the mainnet passkey approver of the same credential.
#[test]
fn presence_receipt_is_bound_by_v5() {
    let policy = policy_with(&[&fixture_authenticator()]);
    let entry = payment();
    let first = verified_receipt(&policy, &entry);
    let second = verified_receipt(&policy, &entry);
    assert_ne!(first.digest(), second.digest());
    let approver = AttestedApprover::MainnetPasskey {
        credential_id_b64url: first.credential_id_b64url(),
    };
    let lifetime = entry.attested_lifetime();
    let subject = mainnet_consent_subject(&entry, &binding()).unwrap();
    let blob = |receipt: &MainnetPresenceReceipt| {
        compute_attestation_v5(
            &ATTESTATION_KEY,
            &binding(),
            &entry.approval_nonce,
            &subject,
            &entry.process_uid,
            &lifetime,
            &approver,
            receipt,
        )
    };
    assert_ne!(blob(&first), blob(&second));
    let scope = |receipt| AttestationScope::pending(5, lifetime, Some(&approver), Some(receipt));
    assert!(verify_attestation(
        &ATTESTATION_KEY,
        &binding(),
        &entry.approval_nonce,
        &subject,
        &entry.process_uid,
        &scope(&first).unwrap(),
        &blob(&first)
    ));
    assert!(!verify_attestation(
        &ATTESTATION_KEY,
        &binding(),
        &entry.approval_nonce,
        &subject,
        &entry.process_uid,
        &scope(&second).unwrap(),
        &blob(&first)
    ));
    let v4 = compute_attestation_v4(
        &ATTESTATION_KEY,
        &binding(),
        &entry.approval_nonce,
        &subject,
        &entry.process_uid,
        &lifetime,
        &AttestedApprover::Local,
    );
    assert_ne!(v4, blob(&first));

    let other_id = AttestedApprover::MainnetPasskey {
        credential_id_b64url: URL_SAFE_NO_PAD.encode([1; 16]),
    };
    assert!(
        AttestationScope::pending(5, lifetime, Some(&AttestedApprover::Local), Some(&first))
            .is_none()
    );
    assert!(AttestationScope::pending(5, lifetime, Some(&approver), None).is_none());
    assert!(AttestationScope::pending(5, lifetime, Some(&other_id), Some(&first)).is_none());
    assert!(
        AttestationScope::pending(4, lifetime, Some(&AttestedApprover::Local), Some(&first))
            .is_none()
    );
    assert!(AttestationScope::pending(4, lifetime, Some(&approver), None).is_none());
    assert!(AttestationScope::pending(4, lifetime, Some(&AttestedApprover::Local), None).is_some());
}

/// A receipt verifies only within its documented time relations.
#[test]
fn stored_receipt_times_are_bounded() {
    let policy = policy_with(&[&fixture_authenticator()]);
    let entry = payment();
    let receipt = verified_receipt(&policy, &entry);
    assert!(verify_receipt(&entry, &receipt, &binding(), &policy, now_ms()).is_ok());
    assert_eq!(
        code(verify_receipt(
            &entry,
            &receipt,
            &binding(),
            &policy,
            receipt.verified_at_unix_ms - 1
        )),
        "approval.presence_invalid",
        "verified after now"
    );
    let mut short = entry.clone();
    short.expires_at_unix_ms = receipt.expires_at_unix_ms - 1;
    assert_eq!(
        code(verify_receipt(
            &short,
            &receipt,
            &binding(),
            &policy,
            now_ms()
        )),
        "approval.presence_invalid",
        "challenge outlives the entry"
    );
    let other_policy = policy_at(8, b"", [9; 32], &[&fixture_authenticator()]);
    assert_eq!(
        code(verify_receipt(
            &entry,
            &receipt,
            &binding(),
            &other_policy,
            now_ms()
        )),
        "approval.presence_policy_unavailable"
    );
    for (label, edit) in [
        (
            "verified at expiry",
            (|r: &mut MainnetPresenceReceipt| r.verified_at_unix_ms = r.expires_at_unix_ms)
                as fn(&mut MainnetPresenceReceipt),
        ),
        ("verified before issue", |r| {
            r.verified_at_unix_ms = r.issued_at_unix_ms - 1
        }),
        ("window too long", |r| {
            r.issued_at_unix_ms = r.expires_at_unix_ms - MAINNET_PRESENCE_CHALLENGE_TTL_MS - 1
        }),
        ("malformed request id", |r| r.request_id.push('x')),
        ("uppercase digest", |r| {
            r.policy_digest_hex.make_ascii_uppercase()
        }),
        ("other origin", |r| {
            "http://localhost:4101".clone_into(&mut r.expected_origin)
        }),
    ] {
        let mut edited = receipt.clone();
        edit(&mut edited);
        assert!(
            verify_receipt(&entry, &edited, &binding(), &policy, now_ms()).is_err(),
            "{label}"
        );
    }
}

// ── The attester's mainnet path ─────────────────────────────────────────────

fn consent_rows(path: &std::path::Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .filter(|row| row["kind"] == "approval_attested")
        .collect()
}

/// A standard approver on a mainnet binding refuses for every attestable
/// kind and surface before the key is read: no row, nothing persisted.
#[test]
#[serial]
fn standard_mainnet_attestation_records_nothing() {
    let fixture = MainnetConsentFixture::new(PROFILE);
    let source = stellar_strkey::ed25519::PublicKey([1; 32]).to_string();
    let uid = process_uid_for_attestation().unwrap();
    let entries = [
        payment(),
        fixtures::claim_pending(&source, [9; 32], None, 100, 7, uid.clone(), DEFAULT_TTL_MS),
        fixtures::trustline_pending(
            &source,
            "USD",
            &source,
            Some(100),
            100,
            7,
            uid,
            DEFAULT_TTL_MS,
        ),
        opt_in(MAINNET_CHAIN_ID),
    ];
    for entry in entries {
        for (surface, approver) in [
            (Surface::Cli, AttestedApprover::Local),
            (Surface::Serve, AttestedApprover::Local),
            (Surface::CliMainnetConfirm, AttestedApprover::Local),
            (
                Surface::ServeRemote,
                AttestedApprover::Remote {
                    credential_id_b64url: "AAECAw".to_owned(),
                },
            ),
        ] {
            let mut store = PendingApprovalStore::open(fixture.store_path()).unwrap();
            if store.get(&entry.approval_nonce).is_none() {
                store.insert(entry.clone(), now_ms()).unwrap();
            }
            let mut writer = fixture.audit_writer();
            let error = attest_and_persist(
                &mut store,
                &entry,
                &ATTESTATION_KEY,
                &fixture.binding(),
                surface,
                ConsentAudit::Writer(&mut writer),
                ConsentAuthorization::Standard(&approver),
                |_, _| panic!("no grant"),
            )
            .unwrap_err();
            assert_eq!(error.code(), "approval.presence_required", "{surface:?}");
            drop(store);
            let reopened = PendingApprovalStore::open(fixture.store_path()).unwrap();
            let stored = reopened.get(&entry.approval_nonce).unwrap();
            assert!(stored.attestation_blob_b64.is_none());
            assert!(stored.mainnet_presence.is_none());
            assert!(consent_rows(&fixture.audit_path()).is_empty());
        }
    }
}

/// The attester refuses a challenged entry whose stored lifetime changed
/// since the challenge, before any receipt or HMAC work, with no row.
#[test]
#[serial]
fn presence_recheck_rejects_changed_entry_lifetime() {
    let fixture = MainnetConsentFixture::new(PROFILE);
    let policy = fixture.current_policy();
    for field in ["created", "expires"] {
        let entry = fixture.payment(DEFAULT_TTL_MS);
        let presence = fixture.presence(&entry, &policy);
        let mut stored = entry.clone();
        if field == "created" {
            stored.created_at_unix_ms -= 1;
        } else {
            stored.expires_at_unix_ms += 1;
        }
        let mut store = PendingApprovalStore::open(fixture.store_path()).unwrap();
        store.insert(stored, now_ms()).unwrap();
        let mut writer = fixture.audit_writer();
        let error = attest_and_persist(
            &mut store,
            &entry,
            &ATTESTATION_KEY,
            &fixture.binding(),
            Surface::Cli,
            ConsentAudit::Writer(&mut writer),
            ConsentAuthorization::Mainnet {
                presence,
                policy: &policy,
            },
            |_, _| panic!("no grant"),
        )
        .unwrap_err();
        assert_eq!(error.code(), "approval.wrong_kind", "{field}");
        assert!(
            store
                .get(&entry.approval_nonce)
                .unwrap()
                .attestation_blob_b64
                .is_none()
        );
        assert!(consent_rows(&fixture.audit_path()).is_empty(), "{field}");
    }
}

/// The mainnet attester refuses the remote surface, another chain, another
/// entry, and a presence verified under a policy other than the current one.
#[test]
#[serial]
fn mainnet_attester_refuses_mismatched_authorization() {
    let mut fixture = MainnetConsentFixture::new(PROFILE);
    let policy = fixture.current_policy();
    let attempt = |fixture: &MainnetConsentFixture,
                   entry: &PendingApproval,
                   presence: VerifiedMainnetPresence,
                   policy: &VerifiedPolicy,
                   binding: &AttestationBinding<'_>,
                   surface: Surface| {
        let mut store = PendingApprovalStore::open(fixture.store_path()).unwrap();
        if store.get(&entry.approval_nonce).is_none() {
            store.insert(entry.clone(), now_ms()).unwrap();
        }
        let mut writer = fixture.audit_writer();
        attest_and_persist(
            &mut store,
            entry,
            &ATTESTATION_KEY,
            binding,
            surface,
            ConsentAudit::Writer(&mut writer),
            ConsentAuthorization::Mainnet { presence, policy },
            |_, _| panic!("no grant"),
        )
    };
    let entry = fixture.payment(DEFAULT_TTL_MS);
    let other = fixture.payment(DEFAULT_TTL_MS);
    let cases: [(
        &str,
        &str,
        PendingApproval,
        VerifiedMainnetPresence,
        AttestationBinding<'_>,
        Surface,
    ); 3] = [
        (
            "remote surface",
            "approval.mainnet_remote_unsupported",
            entry.clone(),
            fixture.presence(&entry, &policy),
            fixture.binding(),
            Surface::ServeRemote,
        ),
        (
            "testnet binding",
            "approval.binding_mismatch",
            entry.clone(),
            fixture.presence(&entry, &policy),
            AttestationBinding::new(PROFILE, "stellar:testnet"),
            Surface::Cli,
        ),
        (
            "another entry",
            "approval.binding_mismatch",
            other.clone(),
            fixture.presence(&entry, &policy),
            fixture.binding(),
            Surface::Cli,
        ),
    ];
    for (label, expected, target, presence, binding, surface) in cases {
        assert_eq!(
            code(attempt(
                &fixture, &target, presence, &policy, &binding, surface
            )),
            expected,
            "{label}"
        );
    }
    assert!(consent_rows(&fixture.audit_path()).is_empty());

    let presence = fixture.presence(&entry, &policy);
    fixture.sign_policy(&[&fixture_authenticator()]);
    assert_eq!(
        code(attempt(
            &fixture,
            &entry,
            presence,
            &policy,
            &fixture.binding(),
            Surface::Cli
        )),
        "approval.presence_policy_unavailable",
        "the policy was signed again since the challenge"
    );
    assert!(consent_rows(&fixture.audit_path()).is_empty());
}

/// The attester checks both challenge clocks immediately before the row: a
/// presence verified within its life whose wall or monotonic deadline has
/// passed by the attest records nothing.
#[test]
#[serial]
fn presence_expires_on_both_clocks() {
    let fixture = MainnetConsentFixture::new(PROFILE);
    let policy = fixture.current_policy();
    let authenticator = fixture_authenticator();
    let ttl = MAINNET_PRESENCE_CHALLENGE_TTL_MS;
    let past = Instant::now()
        .checked_sub(Duration::from_millis(ttl + 1_000))
        .expect("the monotonic clock reaches back past one challenge life");
    for (label, issued_ms, issued) in [
        ("wall", now_ms() - ttl - 5, Instant::now()),
        ("monotonic", now_ms(), past),
    ] {
        let mut entry = fixture.payment(DEFAULT_TTL_MS);
        entry.created_at_unix_ms -= 2 * ttl;
        let pending = issue_mainnet_presence(
            &entry,
            &fixture.binding(),
            &policy,
            &MainnetConsentFixture::origin(),
            issued_ms,
            issued,
        )
        .unwrap();
        let assertion = authenticator.assert(
            pending.challenge,
            &MainnetConsentFixture::origin(),
            MAINNET_APPROVAL_RP_ID,
            FLAG_UP | FLAG_UV,
            1,
        );
        let presence =
            verify_mainnet_presence(pending, input(&assertion), issued_ms, issued).unwrap();
        let mut store = PendingApprovalStore::open(fixture.store_path()).unwrap();
        store.insert(entry.clone(), now_ms()).unwrap();
        let mut writer = fixture.audit_writer();
        let error = attest_and_persist(
            &mut store,
            &entry,
            &ATTESTATION_KEY,
            &fixture.binding(),
            Surface::Cli,
            ConsentAudit::Writer(&mut writer),
            ConsentAuthorization::Mainnet {
                presence,
                policy: &policy,
            },
            |_, _| panic!("no grant"),
        )
        .unwrap_err();
        assert_eq!(error.code(), "approval.presence_expired", "{label}");
        assert!(
            store
                .get(&entry.approval_nonce)
                .unwrap()
                .attestation_blob_b64
                .is_none(),
            "{label}"
        );
        assert!(consent_rows(&fixture.audit_path()).is_empty(), "{label}");
    }
}

/// A proof stays live on entry and expires while the audit lock is held.
#[test]
#[serial]
fn presence_expires_while_audit_outbox_is_locked() {
    for draining in [false, true] {
        attest_with_held_outbox(true, draining);
    }
}

/// Releasing the audit lock within the proof's life permits consent.
#[test]
#[serial]
fn presence_persists_after_audit_outbox_unlocks() {
    for draining in [false, true] {
        attest_with_held_outbox(false, draining);
    }
}

fn attest_with_held_outbox(expire: bool, draining: bool) {
    use crate::audit_log::{
        BindingHistory,
        outbox::{AuditOutbox, outbox_lock_path},
        tip_anchor::InMemoryTipAnchorStore,
        writer::AuditWriter,
    };
    let fixture = MainnetConsentFixture::new(PROFILE);
    let policy = fixture.current_policy();
    let mut entry = fixture.payment(DEFAULT_TTL_MS);
    let ttl = Duration::from_millis(MAINNET_PRESENCE_CHALLENGE_TTL_MS);
    entry.created_at_unix_ms -= MAINNET_PRESENCE_CHALLENGE_TTL_MS;
    let anchors = Arc::new(InMemoryTipAnchorStore::new());
    let mut writer = AuditWriter::open_with_tip_anchor(
        fixture.audit_path(),
        None,
        anchors.clone(),
        BindingHistory::NotRecorded,
    )
    .unwrap();
    let outbox = AuditOutbox::for_log(&fixture.audit_path(), anchors);
    let lock =
        crate::audit_log::test_helpers::hold_audit_lock(&outbox_lock_path(&fixture.audit_path()))
            .unwrap();
    let mut store = PendingApprovalStore::open(fixture.store_path()).unwrap();
    store.insert(entry.clone(), now_ms()).unwrap();
    let before = std::fs::read(fixture.store_path()).unwrap();
    let issued = if expire {
        Instant::now() - ttl + Duration::from_secs(1)
    } else {
        Instant::now()
    };
    let issued_ms = now_ms();
    let pending = issue_mainnet_presence(
        &entry,
        &fixture.binding(),
        &policy,
        &MainnetConsentFixture::origin(),
        issued_ms,
        issued,
    )
    .unwrap();
    let assertion = fixture_authenticator().assert(
        pending.challenge,
        &MainnetConsentFixture::origin(),
        MAINNET_APPROVAL_RP_ID,
        FLAG_UP | FLAG_UV,
        1,
    );
    let presence = verify_mainnet_presence(pending, input(&assertion), issued_ms, issued).unwrap();
    let release_at = if expire {
        presence.deadline + Duration::from_millis(100)
    } else {
        Instant::now() + Duration::from_millis(100)
    };
    let release = std::thread::spawn(move || {
        std::thread::sleep(release_at.saturating_duration_since(Instant::now()));
        drop(lock);
    });
    assert!(
        Instant::now() < presence.deadline,
        "proof is alive at entry"
    );
    let result = attest_and_persist(
        &mut store,
        &entry,
        &ATTESTATION_KEY,
        &fixture.binding(),
        Surface::Cli,
        if draining {
            ConsentAudit::Writer(&mut writer)
        } else {
            ConsentAudit::Outbox(&outbox)
        },
        ConsentAuthorization::Mainnet {
            presence,
            policy: &policy,
        },
        |_, _| panic!("no grant"),
    );
    release.join().unwrap();
    let stored = store.get(&entry.approval_nonce).unwrap();
    if expire {
        assert_eq!(result.unwrap_err().code(), "approval.presence_expired");
        assert!(stored.attestation_blob_b64.is_none());
        assert!(stored.mainnet_presence.is_none());
        assert_eq!(stored.kind.kind_name(), entry.kind.kind_name());
        assert_eq!(std::fs::read(fixture.store_path()).unwrap(), before);
        assert!(consent_rows(&fixture.audit_path()).is_empty());
        assert!(consent_rows(outbox.path()).is_empty());
    } else {
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(stored.attestation_version, 5);
        assert!(stored.mainnet_presence.is_some());
        assert!(stored.attestation_blob_b64.is_some());
        let row_path = if draining {
            fixture.audit_path()
        } else {
            outbox.path().to_owned()
        };
        assert_eq!(consent_rows(&row_path).len(), 1);
        drop(store);
        let reopened = PendingApprovalStore::open(fixture.store_path()).unwrap();
        assert!(
            reopened
                .get(&entry.approval_nonce)
                .unwrap()
                .mainnet_presence
                .is_some()
        );
    }
}

/// The consent row carries the ceremony's request ID, the mainnet chain and
/// the presence facts, and no credential ID, key, client data or signature.
#[test]
#[serial]
fn mainnet_presence_audit_is_correlated_and_redacted() {
    let fixture = MainnetConsentFixture::new(PROFILE);
    let entry = fixture.payment(DEFAULT_TTL_MS);
    let policy = fixture.current_policy();
    let (store, surfaced) = fixture.consent(&entry);
    assert!(surfaced.is_some());
    let stored = store.get(&entry.approval_nonce).unwrap();
    let receipt = stored.mainnet_presence.clone().unwrap();
    let rows = consent_rows(&fixture.audit_path());
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row["request_id"], receipt.request_id());
    assert_eq!(row["chain_id"], MAINNET_CHAIN_ID);
    assert_eq!(row["approval_kind"], "PaymentSimulated");
    assert_eq!(row["gated_tool"], "stellar_pay_commit");
    assert_eq!(row["origin"], "cli");
    let presence = &row["mainnet_presence"];
    let credential = credential_of(&fixture_authenticator());
    assert_eq!(presence["credential_fingerprint"], credential.fingerprint());
    assert_eq!(
        presence["receipt_sha256_hex"],
        crate::hex::encode(&receipt.digest().unwrap())
    );
    let challenge = receipt
        .challenge_for(&entry, &fixture.binding(), &policy, None)
        .unwrap();
    assert_eq!(
        presence["challenge_sha256_hex"],
        crate::hex::encode(&challenge)
    );
    assert_eq!(
        presence["policy_digest_hex"],
        crate::hex::encode(&policy.digest())
    );
    assert_eq!(presence["policy_sequence"], 1);
    assert_eq!(presence["rp_id"], MAINNET_APPROVAL_RP_ID);
    assert_eq!(presence["webauthn_origin"], MainnetConsentFixture::origin());
    assert_eq!(presence["user_present"], true);
    assert_eq!(presence["user_verified"], true);
    assert_eq!(presence["sign_count"], 1);
    assert_eq!(
        presence["verified_at_unix_ms"],
        receipt.verified_at_unix_ms()
    );

    let text = std::fs::read_to_string(fixture.audit_path()).unwrap();
    for secret in [
        credential.credential_id_b64url(),
        credential.public_key_sec1_b64url(),
        URL_SAFE_NO_PAD.encode(&receipt.assertion.client_data_json),
        URL_SAFE_NO_PAD.encode(&receipt.assertion.signature_compact),
        crate::hex::encode(&receipt.assertion.signature_compact),
        receipt.random_b64url.clone(),
    ] {
        assert!(!text.contains(&secret), "the row carries no ceremony bytes");
    }
    let debug = format!("{receipt:?}");
    assert!(!debug.contains(&credential.credential_id_b64url()));
    assert!(!debug.contains(&receipt.random_b64url));
}

/// The stored record round-trips through the file, and a record whose
/// version, approver and receipt do not belong together refuses to load.
#[test]
#[serial]
fn mainnet_presence_store_round_trip_and_partial_record_refusal() {
    let fixture = MainnetConsentFixture::new(PROFILE);
    let entry = fixture.payment(DEFAULT_TTL_MS);
    let (store, _) = fixture.consent(&entry);
    let original = store.get(&entry.approval_nonce).unwrap().clone();
    drop(store);
    let reopened = PendingApprovalStore::open(fixture.store_path()).unwrap();
    let loaded = reopened.get(&entry.approval_nonce).unwrap();
    assert_eq!(loaded.attestation_version, 5);
    assert_eq!(loaded.mainnet_presence, original.mainnet_presence);
    assert_eq!(loaded.attestation_blob_b64, original.attestation_blob_b64);
    assert!(matches!(
        loaded.attested_approver,
        Some(AttestedApprover::MainnetPasskey { .. })
    ));
    drop(reopened);

    let text = std::fs::read_to_string(fixture.store_path()).unwrap();
    let edits: [(&str, TableEdit); 7] = [
        ("version 5 with a local approver and no receipt", |t| {
            t.remove("mainnet_presence").unwrap();
            t.remove("attested_approver").unwrap();
            t["attested_approver"]["kind"] = toml_edit::value("local");
        }),
        ("receipt removed", |t| {
            t.remove("mainnet_presence").unwrap();
        }),
        ("version 4 with a receipt", |t| {
            t["attestation_version"] = toml_edit::value(4);
        }),
        ("local approver with a receipt", |t| {
            t.remove("attested_approver").unwrap();
            t["attested_approver"]["kind"] = toml_edit::value("local");
        }),
        ("approver for another credential", |t| {
            t["attested_approver"]["credential_id_b64url"] =
                toml_edit::value(URL_SAFE_NO_PAD.encode([1; 16]));
        }),
        ("unknown receipt field", |t| {
            t["mainnet_presence"]["extra"] = toml_edit::value(1);
        }),
        ("receipt version", |t| {
            t["mainnet_presence"]["version"] = toml_edit::value(3);
        }),
    ];
    for (label, edit) in edits {
        let mut doc: toml_edit::DocumentMut = text.parse().unwrap();
        let tables = doc["pending"].as_array_of_tables_mut().unwrap();
        let table = tables
            .iter_mut()
            .find(|t| t["approval_nonce"].as_str() == Some(entry.approval_nonce.as_str()))
            .unwrap();
        edit(table);
        std::fs::write(fixture.store_path(), doc.to_string()).unwrap();
        assert!(
            PendingApprovalStore::open(fixture.store_path()).is_err(),
            "{label}"
        );
    }
    std::fs::write(fixture.store_path(), &text).unwrap();
    assert!(PendingApprovalStore::open(fixture.store_path()).is_ok());
}

// ── Trustline clawback opt-in ───────────────────────────────────────────────

/// On mainnet only a version 5 opt-in with a receipt that verifies under the
/// current policy counts: a genuine version 4 opt-in clears neither
/// verifier, and the mainnet verifier refuses under another policy.
#[test]
#[serial]
fn mainnet_opt_in_requires_signed_presence() {
    let mut fixture = MainnetConsentFixture::new(PROFILE);
    let policy = fixture.current_policy();
    let binding = AttestationBinding::new(PROFILE, MAINNET_CHAIN_ID);

    let legacy = opt_in(MAINNET_CHAIN_ID);
    let mut store = PendingApprovalStore::open(fixture.home().join("legacy.toml")).unwrap();
    store.insert(legacy.clone(), now_ms()).unwrap();
    let digest = crate::approval::attestation::compute_trustline_clawback_opt_in_digest(
        MAINNET_CHAIN_ID,
        "USDC",
        ISSUER,
    );
    let blob = compute_attestation_v4(
        &ATTESTATION_KEY,
        &binding,
        &legacy.approval_nonce,
        &digest,
        &legacy.process_uid,
        &legacy.attested_lifetime(),
        &AttestedApprover::Local,
    );
    store
        .record_trustline_clawback_opt_in_attestation(
            &legacy.approval_nonce,
            blob,
            AttestedApprover::Local,
        )
        .unwrap();
    assert!(!store.verify_attested_trustline_clawback_opt_in(
        &ATTESTATION_KEY,
        &binding,
        MAINNET_CHAIN_ID,
        "USDC",
        ISSUER,
        now_ms()
    ));
    assert!(
        !store
            .verify_mainnet_trustline_clawback_opt_in(
                &ATTESTATION_KEY,
                &binding,
                "USDC",
                ISSUER,
                &policy,
                now_ms()
            )
            .unwrap()
    );

    let presence_opt_in = opt_in(MAINNET_CHAIN_ID);
    let (store, surfaced) = fixture.consent(&presence_opt_in);
    assert!(surfaced.is_none(), "an opt-in surfaces no attestation");
    assert_eq!(
        store
            .get(&presence_opt_in.approval_nonce)
            .unwrap()
            .attestation_version,
        5
    );
    assert!(
        store
            .verify_mainnet_trustline_clawback_opt_in(
                &ATTESTATION_KEY,
                &binding,
                "USDC",
                ISSUER,
                &policy,
                now_ms()
            )
            .unwrap()
    );
    assert!(!store.verify_attested_trustline_clawback_opt_in(
        &ATTESTATION_KEY,
        &binding,
        MAINNET_CHAIN_ID,
        "USDC",
        ISSUER,
        now_ms()
    ));
    assert!(
        !store
            .verify_mainnet_trustline_clawback_opt_in(
                &[0x11; 32],
                &binding,
                "USDC",
                ISSUER,
                &policy,
                now_ms()
            )
            .unwrap(),
        "another key"
    );
    assert!(
        !store
            .verify_mainnet_trustline_clawback_opt_in(
                &ATTESTATION_KEY,
                &binding,
                "EURC",
                ISSUER,
                &policy,
                now_ms()
            )
            .unwrap(),
        "another asset"
    );
    fixture.sign_policy(&[&fixture_authenticator()]);
    assert_eq!(
        code(store.verify_mainnet_trustline_clawback_opt_in(
            &ATTESTATION_KEY,
            &binding,
            "USDC",
            ISSUER,
            &policy,
            now_ms()
        )),
        "approval.presence_policy_unavailable"
    );
}

/// The opt-in verifier checks the assertion even when its version 5 HMAC verifies.
#[test]
#[serial]
fn mainnet_opt_in_reverifies_the_assertion() {
    let fixture = MainnetConsentFixture::new(PROFILE);
    let policy = fixture.current_policy();
    let entry = opt_in(MAINNET_CHAIN_ID);
    let (genuine, _) = fixture.consent(&entry);
    assert!(
        genuine
            .verify_mainnet_trustline_clawback_opt_in(
                &ATTESTATION_KEY,
                &fixture.binding(),
                "USDC",
                ISSUER,
                &policy,
                now_ms(),
            )
            .unwrap()
    );
    let mut receipt = genuine
        .get(&entry.approval_nonce)
        .unwrap()
        .mainnet_presence
        .clone()
        .unwrap();
    receipt.assertion.client_data_json.push(b' ');
    assert!(receipt.is_well_formed());
    let approver = AttestedApprover::MainnetPasskey {
        credential_id_b64url: receipt.credential_id_b64url(),
    };
    let subject = mainnet_consent_subject(&entry, &fixture.binding()).unwrap();
    let blob = compute_attestation_v5(
        &ATTESTATION_KEY,
        &fixture.binding(),
        &entry.approval_nonce,
        &subject,
        &entry.process_uid,
        &entry.attested_lifetime(),
        &approver,
        &receipt,
    );
    assert!(verify_attestation(
        &ATTESTATION_KEY,
        &fixture.binding(),
        &entry.approval_nonce,
        &subject,
        &entry.process_uid,
        &AttestationScope::V5(entry.attested_lifetime(), &approver, &receipt),
        &blob,
    ));
    let mut altered = PendingApprovalStore::open(fixture.home().join("altered.toml")).unwrap();
    altered.insert(entry.clone(), now_ms()).unwrap();
    altered
        .record_mainnet_attestation_at(&entry.approval_nonce, blob, approver, receipt, now_ms())
        .unwrap();
    assert!(
        !altered
            .verify_mainnet_trustline_clawback_opt_in(
                &ATTESTATION_KEY,
                &fixture.binding(),
                "USDC",
                ISSUER,
                &policy,
                now_ms(),
            )
            .unwrap()
    );
}

/// The receipt digest and the version 5 attestation follow their documented
/// layouts, computed here independently of the production builders: the
/// version 1 receipt of a payment, and the version 2 receipts of a payment
/// at a loopback origin with an intent and at the signed origin.
#[test]
fn version_5_layout_matches_independent_hmac() {
    use hmac::{Hmac, KeyInit as _, Mac as _};
    use sha2::{Digest as _, Sha256};
    let lp = |out: &mut Vec<u8>, bytes: &[u8]| {
        out.extend(u32::try_from(bytes.len()).unwrap().to_be_bytes());
        out.extend(bytes);
    };
    let independent_digest =
        |receipt: &MainnetPresenceReceipt, policy: &VerifiedPolicy, origin: &str| {
            let mut preimage = b"stellar-agent-mainnet-presence-receipt:v1".to_vec();
            preimage.extend(receipt.version.to_be_bytes());
            lp(&mut preimage, receipt.request_id.as_bytes());
            preimage.extend(URL_SAFE_NO_PAD.decode(&receipt.random_b64url).unwrap());
            preimage.extend(7_i64.to_be_bytes());
            preimage.extend(policy.digest());
            preimage.extend([9; 32]);
            lp(&mut preimage, origin.as_bytes());
            if receipt.version == 2 {
                match &policy.mainnet().unwrap().approval_cert_spki_sha256 {
                    Some(pin) => {
                        preimage.push(1);
                        preimage.extend(pin);
                        preimage.extend(policy.digest());
                    }
                    None => preimage.push(0),
                }
            }
            preimage.extend(receipt.issued_at_unix_ms.to_be_bytes());
            preimage.extend(receipt.expires_at_unix_ms.to_be_bytes());
            preimage.extend(receipt.verified_at_unix_ms.to_be_bytes());
            for field in [
                &receipt.assertion.credential_id,
                &receipt.assertion.authenticator_data,
                &receipt.assertion.client_data_json,
                &receipt.assertion.signature_compact,
            ] {
                lp(&mut preimage, field);
            }
            <[u8; 32]>::from(Sha256::digest(&preimage))
        };
    let policy = policy_with(&[&fixture_authenticator()]);
    let entry = payment();
    let receipt = verified_receipt(&policy, &entry);
    assert_eq!(receipt.version(), 1);
    let digest = independent_digest(&receipt, &policy, ORIGIN);
    assert_eq!(receipt.digest(), Some(digest));

    let signed = signed_policy();
    for (receipt, policy, origin) in [
        (
            receipt_on(
                &entry,
                &policy,
                PresenceListener::Loopback(ORIGIN),
                Some(&intent_a()),
            ),
            &policy,
            ORIGIN,
        ),
        (signed_receipt(&entry, &signed), &signed, SIGNED_ORIGIN),
    ] {
        assert_eq!(receipt.version(), 2);
        assert_eq!(
            receipt.digest(),
            Some(independent_digest(&receipt, policy, origin)),
            "{origin}"
        );
    }

    let subject = mainnet_consent_subject(&entry, &binding()).unwrap();
    let mut mac = Hmac::<Sha256>::new_from_slice(&ATTESTATION_KEY).unwrap();
    let mut message = b"stellar-agent-approval-attestation:v5".to_vec();
    for field in [
        PROFILE.as_bytes(),
        MAINNET_CHAIN_ID.as_bytes(),
        entry.approval_nonce.as_bytes(),
    ] {
        lp(&mut message, field);
    }
    message.extend(subject);
    lp(&mut message, entry.process_uid.as_bytes());
    lp(&mut message, b"PaymentSimulated");
    message.extend(entry.created_at_unix_ms.to_be_bytes());
    message.extend(entry.expires_at_unix_ms.to_be_bytes());
    message.push(0x02);
    lp(&mut message, receipt.credential_id_b64url().as_bytes());
    message.extend(digest);
    mac.update(&message);
    let expected: [u8; 32] = mac.finalize().into_bytes().into();
    assert_eq!(
        compute_attestation_v5(
            &ATTESTATION_KEY,
            &binding(),
            &entry.approval_nonce,
            &subject,
            &entry.process_uid,
            &entry.attested_lifetime(),
            &AttestedApprover::MainnetPasskey {
                credential_id_b64url: receipt.credential_id_b64url(),
            },
            &receipt,
        ),
        expected
    );
}

// ── Legacy layout guards ────────────────────────────────────────────────────

/// `entry` with the fixed nonce, process UID and lifetime of the frozen
/// vectors.
fn frozen(mut entry: PendingApproval) -> PendingApproval {
    "bm9uY2U".clone_into(&mut entry.approval_nonce);
    "1000".clone_into(&mut entry.process_uid);
    entry.created_at_unix_ms = 1_000;
    entry.expires_at_unix_ms = 2_000_000;
    entry
}

/// An x402 transfer of 10 base units on mainnet.
fn x402_entry() -> PendingApproval {
    use sha2::Digest as _;
    use stellar_xdr::{
        AccountId, ContractId, Hash, InvokeContractArgs, PublicKey, ScAddress, ScVal,
        SorobanAuthorizedFunction, SorobanAuthorizedInvocation, Uint256,
    };
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
        &sha2::Sha256::digest(Caip2::Mainnet.network_passphrase().as_bytes()).into(),
        &root,
        None,
        process_uid_for_attestation().unwrap(),
        DEFAULT_TTL_MS,
    )
    .unwrap()
}

/// An unvalued claim of the balance `[9; 32]`.
fn claim_entry() -> PendingApproval {
    let source = stellar_strkey::ed25519::PublicKey([1; 32]).to_string();
    fixtures::claim_pending(
        &source,
        [9; 32],
        None,
        100,
        7,
        process_uid_for_attestation().unwrap(),
        DEFAULT_TTL_MS,
    )
}

/// The legacy challenge of `entry` under `policy` from the fixed facts of
/// the frozen vectors.
fn legacy_challenge(entry: &PendingApproval, policy: &VerifiedPolicy) -> [u8; 32] {
    Facts {
        random: [1; 32],
        request_id: "00000000-0000-4000-8000-000000000001".to_owned(),
        entry: entry.clone(),
        profile: PROFILE.to_owned(),
        chain: MAINNET_CHAIN_ID.to_owned(),
        subject: mainnet_consent_subject(entry, &binding()).unwrap(),
        policy: policy.clone(),
        origin: ORIGIN.to_owned(),
        issued: 5_000,
        expires: 65_000,
    }
    .challenge()
}

/// The legacy challenge and consent view layouts keep their bytes for an
/// x402 and a claim entry, and the legacy challenge and approval view digest
/// of a payment keep theirs.
#[test]
fn legacy_challenge_vectors_hold() {
    let policy = policy_with(&[&fixture_authenticator()]);
    for (label, entry, challenge, view) in [
        (
            "x402",
            frozen(x402_entry()),
            "a7a61700602fec8e766297f45765e445679ef77b62909c9cb71947c5dcf710b7",
            "dd0d3d2c3e3525aac912231105fa605499b41453ea0b3d45493fc9c8e67e1731",
        ),
        (
            "claim",
            frozen(claim_entry()),
            "7a9213f4a3cb0846cfe8a8df511ff4d94cf3432d8b7b8257d8f810355f8acfed",
            "f4bd9576165b7a398da002724d02f66027056bf2d26bbf39c00661d158e9710e",
        ),
    ] {
        assert_eq!(
            crate::hex::encode(&legacy_challenge(&entry, &policy)),
            challenge,
            "{label} challenge"
        );
        assert_eq!(
            crate::hex::encode(&mainnet_consent_view_digest(&entry, &binding(), &policy).unwrap()),
            view,
            "{label} consent view"
        );
    }
    let payment = frozen(payment());
    assert_eq!(
        crate::hex::encode(&legacy_challenge(&payment, &policy)),
        "6df8e1b662779865fd60d8fcf5a9a5f76bdadfb874482ea6c5c0fae006b4f10a",
        "payment challenge"
    );
    assert_eq!(
        crate::hex::encode(&approval_view_digest(&payment, &binding()).unwrap()),
        "5cf19c471688ef2213dc551a743dfe70178093fe42cbac7c757b12d699135d99",
        "payment approval view"
    );
}

/// A version 1 receipt from fixed inputs keeps its JSON and TOML text and
/// its digest.
#[test]
fn localhost_receipt_version_1_bytes_unchanged() {
    let policy = policy_with(&[&fixture_authenticator()]);
    let assertion = fixture_authenticator().assert(
        [7; 32],
        ORIGIN,
        MAINNET_APPROVAL_RP_ID,
        FLAG_UP | FLAG_UV,
        1,
    );
    let receipt: MainnetPresenceReceipt = serde_json::from_value(serde_json::json!({
        "version": 1,
        "request_id": "00000000-0000-4000-8000-000000000001",
        "random_b64url": URL_SAFE_NO_PAD.encode([1; 32]),
        "policy_sequence": 7,
        "policy_digest_hex": crate::hex::encode(&policy.digest()),
        "policy_owner_hex": crate::hex::encode(&[9; 32]),
        "expected_origin": ORIGIN,
        "issued_at_unix_ms": 5_000,
        "expires_at_unix_ms": 65_000,
        "verified_at_unix_ms": 6_000,
        "assertion": {
            "credential_id": assertion.credential_id,
            "authenticator_data": assertion.authenticator_data,
            "client_data_json": assertion.client_data_json,
            "signature_compact": assertion.signature_compact,
        },
    }))
    .unwrap();
    assert_eq!(
        serde_json::to_string(&receipt).unwrap(),
        "{\"version\":1,\"request_id\":\"00000000-0000-4000-8000-000000000001\",\"random_b64url\":\"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE\",\"policy_sequence\":7,\"policy_digest_hex\":\"af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262\",\"policy_owner_hex\":\"0909090909090909090909090909090909090909090909090909090909090909\",\"expected_origin\":\"http://localhost:4100\",\"issued_at_unix_ms\":5000,\"expires_at_unix_ms\":65000,\"verified_at_unix_ms\":6000,\"assertion\":{\"credential_id\":[90,90,90,90,90,90,90,90,90,90,90,90,90,90,90,90],\"authenticator_data\":[73,150,13,229,136,14,140,104,116,52,23,15,100,118,96,91,143,228,174,185,162,134,50,199,153,92,243,186,131,29,151,99,5,0,0,0,1],\"client_data_json\":[123,34,99,104,97,108,108,101,110,103,101,34,58,34,66,119,99,72,66,119,99,72,66,119,99,72,66,119,99,72,66,119,99,72,66,119,99,72,66,119,99,72,66,119,99,72,66,119,99,72,66,119,99,72,66,119,99,34,44,34,99,114,111,115,115,79,114,105,103,105,110,34,58,102,97,108,115,101,44,34,111,114,105,103,105,110,34,58,34,104,116,116,112,58,47,47,108,111,99,97,108,104,111,115,116,58,52,49,48,48,34,44,34,116,121,112,101,34,58,34,119,101,98,97,117,116,104,110,46,103,101,116,34,125],\"signature_compact\":[238,214,76,215,82,35,85,137,210,69,45,43,111,89,146,26,126,69,205,146,118,244,150,86,37,62,143,50,208,232,115,251,33,95,41,208,156,255,238,190,252,249,203,151,140,179,139,63,9,181,143,144,48,56,42,152,0,93,229,90,6,50,234,193]}}",
        "json"
    );
    assert_eq!(
        toml::to_string(&receipt).unwrap(),
        "version = 1\nrequest_id = \"00000000-0000-4000-8000-000000000001\"\nrandom_b64url = \"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE\"\npolicy_sequence = 7\npolicy_digest_hex = \"af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262\"\npolicy_owner_hex = \"0909090909090909090909090909090909090909090909090909090909090909\"\nexpected_origin = \"http://localhost:4100\"\nissued_at_unix_ms = 5000\nexpires_at_unix_ms = 65000\nverified_at_unix_ms = 6000\n\n[assertion]\ncredential_id = [90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90]\nauthenticator_data = [73, 150, 13, 229, 136, 14, 140, 104, 116, 52, 23, 15, 100, 118, 96, 91, 143, 228, 174, 185, 162, 134, 50, 199, 153, 92, 243, 186, 131, 29, 151, 99, 5, 0, 0, 0, 1]\nclient_data_json = [123, 34, 99, 104, 97, 108, 108, 101, 110, 103, 101, 34, 58, 34, 66, 119, 99, 72, 66, 119, 99, 72, 66, 119, 99, 72, 66, 119, 99, 72, 66, 119, 99, 72, 66, 119, 99, 72, 66, 119, 99, 72, 66, 119, 99, 72, 66, 119, 99, 72, 66, 119, 99, 72, 66, 119, 99, 34, 44, 34, 99, 114, 111, 115, 115, 79, 114, 105, 103, 105, 110, 34, 58, 102, 97, 108, 115, 101, 44, 34, 111, 114, 105, 103, 105, 110, 34, 58, 34, 104, 116, 116, 112, 58, 47, 47, 108, 111, 99, 97, 108, 104, 111, 115, 116, 58, 52, 49, 48, 48, 34, 44, 34, 116, 121, 112, 101, 34, 58, 34, 119, 101, 98, 97, 117, 116, 104, 110, 46, 103, 101, 116, 34, 125]\nsignature_compact = [238, 214, 76, 215, 82, 35, 85, 137, 210, 69, 45, 43, 111, 89, 146, 26, 126, 69, 205, 146, 118, 244, 150, 86, 37, 62, 143, 50, 208, 232, 115, 251, 33, 95, 41, 208, 156, 255, 238, 190, 252, 249, 203, 151, 140, 179, 139, 63, 9, 181, 143, 144, 48, 56, 42, 152, 0, 93, 229, 90, 6, 50, 234, 193]\n",
        "toml"
    );
    assert_eq!(
        crate::hex::encode(&receipt.digest().unwrap()),
        "212f2382d6b609761f915885d431ca4e34487812d965e8d2e4f64e2e37ccd00a",
        "digest"
    );
}

// ── Intent layout and signed origin ─────────────────────────────────────────

use crate::approval::fixtures::intent::fixture as intent_fixture;
use crate::approval::mainnet_fixtures::{SIGNED_CERT_SPKI_SHA256, SIGNED_ORIGIN, SIGNED_RP_ID};

/// The signed approval origin `text`, parsed as the policy loader parses it.
fn approval_origin(text: &str) -> ApprovalOrigin {
    let table: toml_edit::DocumentMut = format!("approval_origin = \"{text}\"").parse().unwrap();
    crate::policy::v1::approval_origin::parse_fields(table.as_table())
        .unwrap()
        .0
        .unwrap()
}

/// A verified policy for [`PROFILE`] at `sequence` with the signed `origin`
/// and `pin`, whose canonical bytes are the three fields' text.
fn signed_policy_at(
    sequence: i64,
    origin: &str,
    pin: [u8; 32],
    credentials: &[&TestAuthenticator],
) -> VerifiedPolicy {
    VerifiedPolicy::from_verified(
        sequence,
        signed_canonical(sequence, origin, &pin).as_bytes(),
        [9; 32],
        engine(),
        Some(MainnetBody {
            profile: PROFILE.to_owned(),
            endpoint_host: "rpc.example.invalid".to_owned(),
            installation_nonce_sha256: [3; 32],
            classic_max_fee_per_op_stroops: 500,
            authorization_ttl_seconds: Some(60),
            cross_check_thresholds: None,
            approval_credentials: credentials.iter().map(|a| credential_of(a)).collect(),
            approval_origin: Some(approval_origin(origin)),
            approval_cert_spki_sha256: Some(pin),
        }),
    )
}

/// The canonical bytes of [`signed_policy_at`].
fn signed_canonical(sequence: i64, origin: &str, pin: &[u8; 32]) -> String {
    format!("{sequence}{origin}{}", crate::hex::encode(pin))
}

/// A verified signed-origin policy at sequence 7 for [`SIGNED_ORIGIN`].
fn signed_policy() -> VerifiedPolicy {
    signed_policy_at(
        7,
        SIGNED_ORIGIN,
        SIGNED_CERT_SPKI_SHA256,
        &[&fixture_authenticator()],
    )
}

/// A mainnet payment-kind intent vector: an account creation.
fn intent_a() -> ClassicIntent {
    intent_fixture("create_account_memo_id")
}

/// Another mainnet payment-kind intent vector: an issued-asset payment.
fn intent_b() -> ClassicIntent {
    intent_fixture("pay_issued_muxed_memo_text")
}

/// A challenge for `entry` under `policy` on `listener` with `intent`,
/// issued now.
fn issue_on(
    entry: &PendingApproval,
    policy: &VerifiedPolicy,
    listener: PresenceListener<'_>,
    intent: Option<&ClassicIntent>,
) -> Result<PendingMainnetPresence, WalletError> {
    issue_mainnet_intent_presence(
        entry,
        &binding(),
        policy,
        listener,
        intent,
        now_ms(),
        Instant::now(),
    )
}

/// `pending` signed at its own RP ID and origin, then verified now.
fn verify_issued(pending: PendingMainnetPresence) -> Result<VerifiedMainnetPresence, WalletError> {
    let assertion = MainnetConsentFixture::sign_issued(&fixture_authenticator(), &pending);
    verify_mainnet_presence(pending, input(&assertion), now_ms(), Instant::now())
}

/// The receipt of a verified ceremony for `entry` under `policy` on
/// `listener` with `intent`.
fn receipt_on(
    entry: &PendingApproval,
    policy: &VerifiedPolicy,
    listener: PresenceListener<'_>,
    intent: Option<&ClassicIntent>,
) -> MainnetPresenceReceipt {
    verify_issued(issue_on(entry, policy, listener, intent).unwrap())
        .unwrap()
        .into_parts()
        .receipt
}

/// The receipt of a signed-origin ceremony for `entry` without an intent.
fn signed_receipt(entry: &PendingApproval, policy: &VerifiedPolicy) -> MainnetPresenceReceipt {
    let identity = ListenerIdentity::capture(policy).unwrap();
    receipt_on(
        entry,
        policy,
        PresenceListener::SignedOrigin(&identity),
        None,
    )
}

/// One named change to a single challenge input.
type FactChange = (&'static str, Box<dyn Fn(&mut IntentFacts)>);

/// The intent-layout facts of one challenge, so each field can be varied
/// alone.
#[derive(Clone)]
struct IntentFacts {
    facts: Facts,
    rp_id: String,
    intent: Option<[u8; 32]>,
    pin: Option<[u8; 32]>,
}

impl IntentFacts {
    fn challenge(&self) -> [u8; 32] {
        let facts = &self.facts;
        let binding = AttestationBinding::new(&facts.profile, &facts.chain);
        mainnet_presence_challenge(&ChallengeFacts {
            random: &facts.random,
            request_id: &facts.request_id,
            entry: &facts.entry,
            binding: &binding,
            subject: &facts.subject,
            policy: &facts.policy,
            rp_id: &self.rp_id,
            expected_origin: &facts.origin,
            layout: ChallengeLayout::Intent {
                intent: self.intent.as_ref(),
                pin: self.pin.as_ref(),
            },
            issued_at_unix_ms: facts.issued,
            expires_at_unix_ms: facts.expires,
        })
        .unwrap()
    }
}

/// The signed-origin facts of a frozen opt-in with intent A.
fn intent_facts() -> IntentFacts {
    let policy = signed_policy();
    let entry = frozen(opt_in(MAINNET_CHAIN_ID));
    IntentFacts {
        facts: Facts {
            random: [1; 32],
            request_id: "00000000-0000-4000-8000-000000000001".to_owned(),
            subject: mainnet_consent_subject(&entry, &binding()).unwrap(),
            entry,
            profile: PROFILE.to_owned(),
            chain: MAINNET_CHAIN_ID.to_owned(),
            policy,
            origin: SIGNED_ORIGIN.to_owned(),
            issued: 5_000,
            expires: 65_000,
        },
        rp_id: SIGNED_RP_ID.to_owned(),
        intent: Some(*intent_a().digest().as_bytes()),
        pin: Some(SIGNED_CERT_SPKI_SHA256),
    }
}

/// `u32be(len(bytes)) || bytes`.
fn lp(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend(u32::try_from(bytes.len()).unwrap().to_be_bytes());
    out.extend(bytes);
}

/// `0x00` for an absent value, `0x01 || value` for a present one.
fn tag(out: &mut Vec<u8>, value: Option<&[u8; 32]>) {
    match value {
        Some(bytes) => {
            out.push(1);
            out.extend(bytes);
        }
        None => out.push(0),
    }
}

/// The intent challenge is SHA-256 over the documented layout, typed out
/// here with its domain literal, with the intent and pin tags present and
/// absent.
#[test]
fn intent_challenge_matches_independent_preimage() {
    use sha2::{Digest as _, Sha256};
    let base = intent_facts();
    let mut bare = base.clone();
    bare.intent = None;
    bare.pin = None;
    for facts in [base, bare] {
        let f = &facts.facts;
        let mut preimage = b"stellar-agent-wallet/intent-challenge/v1".to_vec();
        preimage.extend(f.random);
        lp(&mut preimage, f.request_id.as_bytes());
        lp(&mut preimage, f.entry.approval_nonce.as_bytes());
        lp(&mut preimage, f.profile.as_bytes());
        lp(&mut preimage, f.chain.as_bytes());
        lp(&mut preimage, b"TrustlineClawbackOptIn");
        preimage.extend(f.subject);
        lp(&mut preimage, f.entry.process_uid.as_bytes());
        preimage.extend(1_000_u64.to_be_bytes());
        preimage.extend(2_000_000_u64.to_be_bytes());
        preimage.extend(7_i64.to_be_bytes());
        preimage.extend(f.policy.digest());
        preimage.extend([9; 32]);
        tag(&mut preimage, facts.intent.as_ref());
        lp(&mut preimage, b"approve.example.invalid");
        lp(&mut preimage, b"https://approve.example.invalid:8443");
        tag(&mut preimage, facts.pin.as_ref());
        preimage.extend(5_000_u64.to_be_bytes());
        preimage.extend(65_000_u64.to_be_bytes());
        let independent: [u8; 32] = Sha256::digest(&preimage).into();
        assert_eq!(facts.challenge(), independent);
        assert_ne!(
            facts.facts.challenge(),
            independent,
            "the legacy layout differs"
        );
    }
}

/// Every consent field of the legacy layout, and the intent digest, the RP
/// ID, the origin and the pin, change the intent challenge.
#[test]
fn intent_challenge_binds_every_consent_field() {
    let base = intent_facts();
    let signed = |sequence, canonical: &str, owner| {
        VerifiedPolicy::from_verified(
            sequence,
            canonical.as_bytes(),
            owner,
            engine(),
            signed_policy().mainnet().cloned(),
        )
    };
    let canonical = signed_canonical(7, SIGNED_ORIGIN, &SIGNED_CERT_SPKI_SHA256);
    assert_eq!(
        signed(7, &canonical, [9; 32]).digest(),
        signed_policy().digest()
    );
    let variants: Vec<FactChange> = vec![
        ("random", Box::new(|f| f.facts.random[0] ^= 1)),
        ("request id", Box::new(|f| f.facts.request_id.push('0'))),
        (
            "nonce",
            Box::new(|f| f.facts.entry.approval_nonce.push('A')),
        ),
        ("profile", Box::new(|f| f.facts.profile.push('x'))),
        (
            "chain",
            Box::new(|f| "stellar:testnet".clone_into(&mut f.facts.chain)),
        ),
        ("kind", Box::new(|f| f.facts.entry.kind = payment().kind)),
        ("subject", Box::new(|f| f.facts.subject[0] ^= 1)),
        (
            "process uid",
            Box::new(|f| f.facts.entry.process_uid.push('1')),
        ),
        (
            "created",
            Box::new(|f| f.facts.entry.created_at_unix_ms += 1),
        ),
        (
            "expires",
            Box::new(|f| f.facts.entry.expires_at_unix_ms += 1),
        ),
        (
            "policy sequence",
            Box::new(move |f| f.facts.policy = signed(8, &canonical, [9; 32])),
        ),
        (
            "policy digest",
            Box::new(move |f| f.facts.policy = signed(7, "other", [9; 32])),
        ),
        (
            "policy owner",
            Box::new(move |f| {
                f.facts.policy = signed(
                    7,
                    &signed_canonical(7, SIGNED_ORIGIN, &SIGNED_CERT_SPKI_SHA256),
                    [10; 32],
                );
            }),
        ),
        ("issued", Box::new(|f| f.facts.issued += 1)),
        ("challenge expiry", Box::new(|f| f.facts.expires += 1)),
        (
            "intent digest",
            Box::new(|f| f.intent = Some(*intent_b().digest().as_bytes())),
        ),
        ("intent absent", Box::new(|f| f.intent = None)),
        (
            "rp id",
            Box::new(|f| "other.example.invalid".clone_into(&mut f.rp_id)),
        ),
        (
            "origin",
            Box::new(|f| "https://approve.example.invalid:8444".clone_into(&mut f.facts.origin)),
        ),
        ("pin", Box::new(|f| f.pin = Some([0xac; 32]))),
        ("pin absent", Box::new(|f| f.pin = None)),
    ];
    let reference = base.challenge();
    for (label, vary) in variants {
        let mut varied = base.clone();
        vary(&mut varied);
        assert_ne!(varied.challenge(), reference, "{label}");
    }
}

/// The intent consent view digest follows its documented layout with a
/// frozen vector, binds the intent, and leaves the legacy vectors intact.
#[test]
fn consent_view_digest_binds_the_intent() {
    use sha2::{Digest as _, Sha256};
    let local = policy_with(&[&fixture_authenticator()]);
    let signed = signed_policy();
    let entry = frozen(opt_in(MAINNET_CHAIN_ID));
    let view = |policy: &VerifiedPolicy, intent: Option<&ClassicIntent>| {
        mainnet_intent_consent_view_digest(&entry, &binding(), policy, intent).unwrap()
    };
    assert_eq!(
        crate::hex::encode(&view(&local, None)),
        "9292abb6c68083708af06c1d8cf9795593bbe968206e6897d314ac3c0870c4f9",
        "the legacy view without an intent"
    );
    assert_eq!(
        view(&local, None),
        mainnet_consent_view_digest(&entry, &binding(), &local).unwrap()
    );

    let subject = mainnet_consent_subject(&entry, &binding()).unwrap();
    let independent = |policy: &VerifiedPolicy, intent: Option<&ClassicIntent>| {
        let mut preimage = b"stellar-agent-wallet/intent-consent-view/v1".to_vec();
        lp(&mut preimage, b"bm9uY2U");
        lp(&mut preimage, PROFILE.as_bytes());
        lp(&mut preimage, MAINNET_CHAIN_ID.as_bytes());
        lp(&mut preimage, b"TrustlineClawbackOptIn");
        preimage.extend(subject);
        lp(&mut preimage, b"1000");
        preimage.extend(1_000_u64.to_be_bytes());
        preimage.extend(2_000_000_u64.to_be_bytes());
        preimage.extend(7_i64.to_be_bytes());
        preimage.extend(policy.digest());
        preimage.extend([9; 32]);
        tag(
            &mut preimage,
            intent.map(|intent| *intent.digest().as_bytes()).as_ref(),
        );
        <[u8; 32]>::from(Sha256::digest(&preimage))
    };
    for (policy, intent) in [
        (&local, Some(&intent_a())),
        (&signed, Some(&intent_a())),
        (&signed, None),
    ] {
        assert_eq!(view(policy, intent), independent(policy, intent));
    }
    assert_eq!(
        crate::hex::encode(&view(&local, Some(&intent_a()))),
        "df0cc45076e94a9fd26245e3dd3a9fa469f221930af7f863ecddba7d5b3c7ad3",
        "the intent view"
    );
    assert_ne!(
        view(&local, Some(&intent_a())),
        view(&local, Some(&intent_b()))
    );
    assert_ne!(view(&local, Some(&intent_a())), view(&local, None));
    assert_ne!(
        view(&signed, Some(&intent_a())),
        view(&signed, Some(&intent_b()))
    );
    assert_ne!(view(&signed, Some(&intent_a())), view(&signed, None));
}

/// A mainnet policy for [`PROFILE`] at sequence 7 with the given signed
/// origin and pin, whose canonical bytes and owner are those of
/// [`policy_with`], so a receipt under that policy names it.
fn policy_with_site(origin: Option<ApprovalOrigin>, pin: Option<[u8; 32]>) -> VerifiedPolicy {
    VerifiedPolicy::from_verified(
        7,
        b"",
        [9; 32],
        engine(),
        Some(MainnetBody {
            profile: PROFILE.to_owned(),
            endpoint_host: "rpc.example.invalid".to_owned(),
            installation_nonce_sha256: [3; 32],
            classic_max_fee_per_op_stroops: 500,
            authorization_ttl_seconds: Some(60),
            cross_check_thresholds: None,
            approval_credentials: vec![credential_of(&fixture_authenticator())],
            approval_origin: origin,
            approval_cert_spki_sha256: pin,
        }),
    )
}

/// An origin without a pin, or a pin without an origin, is never served as
/// the localhost relying party: issue and listener capture refuse with
/// `approval.presence_policy_unavailable`, and a localhost receipt under
/// such a policy refuses with `approval.presence_invalid`.
#[test]
fn an_unpaired_origin_or_pin_refuses() {
    let entry = payment();
    let local = policy_with(&[&fixture_authenticator()]);
    let legacy = verified_receipt(&local, &entry);
    assert!(verify_receipt(&entry, &legacy, &binding(), &local, now_ms()).is_ok());
    for (label, policy) in [
        (
            "an origin without a pin",
            policy_with_site(Some(approval_origin(SIGNED_ORIGIN)), None),
        ),
        (
            "a pin without an origin",
            policy_with_site(None, Some(SIGNED_CERT_SPKI_SHA256)),
        ),
    ] {
        assert_eq!(policy.digest(), local.digest(), "{label}");
        assert_eq!(
            code(issue_on(
                &entry,
                &policy,
                PresenceListener::Loopback(ORIGIN),
                None
            )),
            "approval.presence_policy_unavailable",
            "{label}: issue"
        );
        assert_eq!(
            code(ListenerIdentity::capture(&policy)),
            "approval.presence_policy_unavailable",
            "{label}: capture"
        );
        assert_eq!(
            code(verify_receipt(
                &entry,
                &legacy,
                &binding(),
                &policy,
                now_ms()
            )),
            "approval.presence_invalid",
            "{label}: verify"
        );
    }
}

/// Intents that do not describe a payment entry on mainnet: one for another
/// chain and one for another record kind.
fn foreign_intents() -> [(&'static str, ClassicIntent); 2] {
    [
        ("another chain", intent_fixture("pay_native_memo_none")),
        (
            "another kind",
            intent_fixture("trustline_removal_memo_hash"),
        ),
    ]
}

/// Issue refuses an intent whose chain is not the binding's or whose
/// operation is not the entry's record kind, and an intent for an entry kind
/// without a classic intent form.
#[test]
fn issue_refuses_an_intent_for_another_chain_or_kind() {
    let local = policy_with(&[&fixture_authenticator()]);
    let signed = signed_policy();
    let identity = ListenerIdentity::capture(&signed).unwrap();
    let entry = payment();
    assert_eq!(intent_a().base().chain_id(), MAINNET_CHAIN_ID);
    assert!(
        issue_on(
            &entry,
            &local,
            PresenceListener::Loopback(ORIGIN),
            Some(&intent_a())
        )
        .is_ok()
    );
    for (label, intent) in foreign_intents() {
        for (policy, listener) in [
            (&local, PresenceListener::Loopback(ORIGIN)),
            (&signed, PresenceListener::SignedOrigin(&identity)),
        ] {
            assert_eq!(
                code(issue_on(&entry, policy, listener, Some(&intent))),
                "approval.presence_invalid",
                "{label}"
            );
        }
    }
    assert_eq!(
        code(issue_on(
            &opt_in(MAINNET_CHAIN_ID),
            &local,
            PresenceListener::Loopback(ORIGIN),
            Some(&intent_a())
        )),
        "approval.presence_invalid",
        "an opt-in"
    );
}

/// A ceremony whose challenge binds `intent` for `entry` under `policy` at
/// the loopback origin, then signed and verified: the issuer is asked for
/// intent A and the challenge is rebuilt over `intent`, so the receipt binds
/// an intent the issuer would refuse.
fn receipt_binding(
    entry: &PendingApproval,
    policy: &VerifiedPolicy,
    intent: &ClassicIntent,
) -> MainnetPresenceReceipt {
    let mut pending = issue_on(
        entry,
        policy,
        PresenceListener::Loopback(ORIGIN),
        Some(&intent_a()),
    )
    .unwrap();
    let digest = *intent.digest().as_bytes();
    pending.challenge = mainnet_presence_challenge(&ChallengeFacts {
        random: &pending.random,
        request_id: &pending.request_id,
        entry,
        binding: &binding(),
        subject: &mainnet_consent_subject(entry, &binding()).unwrap(),
        policy,
        rp_id: &pending.rp_id,
        expected_origin: &pending.expected_origin,
        layout: ChallengeLayout::Intent {
            intent: Some(&digest),
            pin: None,
        },
        issued_at_unix_ms: pending.issued_at_unix_ms,
        expires_at_unix_ms: pending.expires_at_unix_ms,
    })
    .unwrap();
    verify_issued(pending).unwrap().into_parts().receipt
}

/// Verification refuses a receipt whose challenge binds an intent for
/// another chain or record kind, although the challenge recomputes over
/// that intent; the same construction over intent A verifies.
#[test]
fn verification_refuses_an_intent_for_another_chain_or_kind() {
    let local = policy_with(&[&fixture_authenticator()]);
    let entry = payment();
    let verify = |receipt: &MainnetPresenceReceipt, intent: &ClassicIntent| {
        verify_receipt_for_intent(&entry, receipt, &binding(), &local, Some(intent), now_ms())
    };
    let own = receipt_binding(&entry, &local, &intent_a());
    assert!(verify(&own, &intent_a()).is_ok());
    for (label, intent) in foreign_intents() {
        let receipt = receipt_binding(&entry, &local, &intent);
        assert_eq!(
            code(verify(&receipt, &intent)),
            "approval.presence_invalid",
            "{label}"
        );
    }
}

/// A receipt for intent A verifies only through the intent-aware path with
/// intent A: intent B and the legacy path recompute another challenge. The
/// attester verifies through the legacy path, so it records nothing for a
/// presence that bound an intent.
#[test]
#[serial]
fn a_receipt_for_one_intent_refuses_another() {
    for policy in [policy_with(&[&fixture_authenticator()]), signed_policy()] {
        let entry = payment();
        let identity = ListenerIdentity::capture(&policy).ok();
        let listener = identity.as_ref().map_or(
            PresenceListener::Loopback(ORIGIN),
            PresenceListener::SignedOrigin,
        );
        let receipt = receipt_on(&entry, &policy, listener, Some(&intent_a()));
        assert_eq!(receipt.version(), MAINNET_PRESENCE_RECEIPT_VERSION_2);
        let verify = |intent: Option<&ClassicIntent>| {
            verify_receipt_for_intent(&entry, &receipt, &binding(), &policy, intent, now_ms())
        };
        assert!(verify(Some(&intent_a())).is_ok());
        assert_eq!(code(verify(Some(&intent_b()))), "approval.presence_invalid");
        assert_eq!(code(verify(None)), "approval.presence_invalid");
        assert_eq!(
            code(verify_receipt(
                &entry,
                &receipt,
                &binding(),
                &policy,
                now_ms()
            )),
            "approval.presence_invalid"
        );
    }

    let fixture = MainnetConsentFixture::new(PROFILE);
    let policy = fixture.current_policy();
    let entry = fixture.payment(DEFAULT_TTL_MS);
    let pending = issue_mainnet_intent_presence(
        &entry,
        &fixture.binding(),
        &policy,
        PresenceListener::Loopback(&MainnetConsentFixture::origin()),
        Some(&intent_a()),
        now_ms(),
        Instant::now(),
    )
    .unwrap();
    let presence = verify_issued(pending).unwrap();
    let mut store = PendingApprovalStore::open(fixture.store_path()).unwrap();
    store.insert(entry.clone(), now_ms()).unwrap();
    let mut writer = fixture.audit_writer();
    let error = attest_and_persist(
        &mut store,
        &entry,
        &ATTESTATION_KEY,
        &fixture.binding(),
        Surface::Cli,
        ConsentAudit::Writer(&mut writer),
        ConsentAuthorization::Mainnet {
            presence,
            policy: &policy,
        },
        |_, _| panic!("no grant"),
    )
    .unwrap_err();
    assert_eq!(error.code(), "approval.presence_invalid", "the attester");
    let stored = store.get(&entry.approval_nonce).unwrap();
    assert!(stored.attestation_blob_b64.is_none());
    assert!(stored.mainnet_presence.is_none());
    assert!(consent_rows(&fixture.audit_path()).is_empty());
}

/// An assertion carries the RP-ID hash its policy selects: a `localhost`
/// assertion refuses under a signed policy, and a signed-host assertion
/// refuses under a local policy.
#[test]
fn a_receipt_for_one_rp_refuses_another() {
    fn attempt(
        policy: &VerifiedPolicy,
        listener: PresenceListener<'_>,
        origin: &str,
        rp_id: &str,
    ) -> Result<VerifiedMainnetPresence, WalletError> {
        let pending = issue_on(&payment(), policy, listener, None).unwrap();
        let assertion =
            fixture_authenticator().assert(pending.challenge, origin, rp_id, FLAG_UP | FLAG_UV, 1);
        verify_mainnet_presence(pending, input(&assertion), now_ms(), Instant::now())
    }
    let signed = signed_policy();
    let identity = ListenerIdentity::capture(&signed).unwrap();
    let signed_listener = PresenceListener::SignedOrigin(&identity);
    assert!(attempt(&signed, signed_listener, SIGNED_ORIGIN, SIGNED_RP_ID).is_ok());
    assert_eq!(
        code(attempt(
            &signed,
            signed_listener,
            SIGNED_ORIGIN,
            "localhost"
        )),
        "approval.presence_invalid"
    );
    let local = policy_with(&[&fixture_authenticator()]);
    let loopback = PresenceListener::Loopback(ORIGIN);
    assert!(attempt(&local, loopback, ORIGIN, "localhost").is_ok());
    assert_eq!(
        code(attempt(&local, loopback, ORIGIN, SIGNED_RP_ID)),
        "approval.presence_invalid"
    );

    let entry = payment();
    let receipt = signed_receipt(&entry, &signed);
    assert!(verify_receipt(&entry, &receipt, &binding(), &signed, now_ms()).is_ok());
    let mut relying = receipt.clone();
    relying.assertion = input(
        &fixture_authenticator().assert(
            receipt
                .challenge_for(&entry, &binding(), &signed, None)
                .unwrap(),
            SIGNED_ORIGIN,
            "localhost",
            FLAG_UP | FLAG_UV,
            1,
        ),
    );
    assert_eq!(
        code(verify_receipt(
            &entry,
            &relying,
            &binding(),
            &signed,
            now_ms()
        )),
        "approval.presence_invalid",
        "a stored localhost assertion under a signed policy"
    );
}

/// A ceremony binds one origin: another caller origin refuses at issue,
/// another `clientDataJSON` origin at verify, and an edited receipt origin
/// at the stored verification.
#[test]
fn a_receipt_for_one_origin_refuses_another() {
    let authenticator = fixture_authenticator();
    let signed = signed_policy();
    let local = policy_with(&[&authenticator]);
    let entry = payment();
    for (policy, origin) in [
        (&signed, ORIGIN),
        (&signed, SIGNED_ORIGIN),
        (&local, SIGNED_ORIGIN),
    ] {
        assert_eq!(
            code(issue_mainnet_presence(
                &entry,
                &binding(),
                policy,
                origin,
                now_ms(),
                Instant::now()
            )),
            "approval.presence_invalid",
            "{origin}"
        );
        assert_eq!(
            code(issue_on(
                &entry,
                policy,
                PresenceListener::Loopback(origin),
                Some(&intent_a())
            )),
            "approval.presence_invalid",
            "{origin} with an intent"
        );
    }

    let identity = ListenerIdentity::capture(&signed).unwrap();
    for origin in [
        "https://approve.example.invalid:8444",
        "https://approve.example.invalid",
        "http://approve.example.invalid:8443",
        ORIGIN,
    ] {
        let pending = issue_on(
            &entry,
            &signed,
            PresenceListener::SignedOrigin(&identity),
            None,
        )
        .unwrap();
        let assertion = authenticator.assert(
            pending.challenge,
            origin,
            SIGNED_RP_ID,
            FLAG_UP | FLAG_UV,
            1,
        );
        assert_eq!(
            code(verify_mainnet_presence(
                pending,
                input(&assertion),
                now_ms(),
                Instant::now()
            )),
            "approval.presence_invalid",
            "client data origin {origin}"
        );
    }

    let receipt = signed_receipt(&entry, &signed);
    assert!(verify_receipt(&entry, &receipt, &binding(), &signed, now_ms()).is_ok());
    for origin in ["https://approve.example.invalid:8444", ORIGIN] {
        let mut edited = receipt.clone();
        origin.clone_into(&mut edited.expected_origin);
        assert_eq!(
            code(verify_receipt(
                &entry,
                &edited,
                &binding(),
                &signed,
                now_ms()
            )),
            "approval.presence_invalid",
            "receipt origin {origin}"
        );
    }
}

/// A signed-origin listener's challenge names the signed host and origin
/// and binds the pin; an identity of another policy refuses as stale.
#[test]
fn signed_origin_issue_takes_rp_and_origin_from_policy() {
    let policy = signed_policy();
    let identity = ListenerIdentity::capture(&policy).unwrap();
    assert_eq!(identity.policy_digest(), policy.digest());
    assert_eq!(identity.cert_spki_sha256(), SIGNED_CERT_SPKI_SHA256);
    let entry = frozen(opt_in(MAINNET_CHAIN_ID));
    let mut current = entry.clone();
    current.created_at_unix_ms = now_ms() - 1_000;
    current.expires_at_unix_ms = now_ms() + DEFAULT_TTL_MS;
    let pending = issue_on(
        &current,
        &policy,
        PresenceListener::SignedOrigin(&identity),
        None,
    )
    .unwrap();
    let options = pending.options();
    assert_eq!(options.rp_id, SIGNED_RP_ID);
    assert_eq!(pending.expected_origin(), SIGNED_ORIGIN);
    let expected = IntentFacts {
        facts: Facts {
            random: pending.random,
            request_id: pending.request_id.clone(),
            subject: mainnet_consent_subject(&current, &binding()).unwrap(),
            entry: current.clone(),
            profile: PROFILE.to_owned(),
            chain: MAINNET_CHAIN_ID.to_owned(),
            policy: policy.clone(),
            origin: SIGNED_ORIGIN.to_owned(),
            issued: pending.issued_at_unix_ms,
            expires: pending.expires_at_unix_ms,
        },
        rp_id: SIGNED_RP_ID.to_owned(),
        intent: None,
        pin: Some(SIGNED_CERT_SPKI_SHA256),
    };
    assert_eq!(pending.challenge, expected.challenge());
    let receipt = verify_issued(pending).unwrap().into_parts().receipt;
    assert_eq!(receipt.version(), MAINNET_PRESENCE_RECEIPT_VERSION_2);
    assert_eq!(receipt.expected_origin(), SIGNED_ORIGIN);
    assert_eq!(
        receipt.cert_spki_sha256_hex(),
        Some(crate::hex::encode(&SIGNED_CERT_SPKI_SHA256).as_str())
    );
    assert_eq!(
        receipt.listener_policy_digest_hex(),
        Some(crate::hex::encode(&policy.digest()).as_str())
    );

    for (label, current) in [
        (
            "a later sequence",
            signed_policy_at(
                8,
                SIGNED_ORIGIN,
                SIGNED_CERT_SPKI_SHA256,
                &[&fixture_authenticator()],
            ),
        ),
        (
            "another policy digest, from another signed pin",
            signed_policy_at(7, SIGNED_ORIGIN, [0xac; 32], &[&fixture_authenticator()]),
        ),
        ("a local policy", policy_with(&[&fixture_authenticator()])),
    ] {
        assert_eq!(
            code(issue_on(
                &payment(),
                &current,
                PresenceListener::SignedOrigin(&identity),
                None
            )),
            "approval.listener_policy_stale",
            "{label}"
        );
    }
    assert_eq!(
        code(ListenerIdentity::capture(&policy_with(&[
            &fixture_authenticator()
        ]))),
        "approval.presence_policy_unavailable"
    );
}

/// The consent row names the RP ID its policy selects and the receipt's
/// origin: `localhost` and the loopback origin, or the signed host and the
/// signed origin.
#[test]
#[serial]
fn presence_audit_names_the_policy_rp() {
    let mut fixture = MainnetConsentFixture::new(PROFILE);
    let local = fixture.payment(DEFAULT_TTL_MS);
    let (store, _) = fixture.consent(&local);
    drop(store);
    fixture.sign_signed_origin_policy(&[&fixture_authenticator()], &SIGNED_CERT_SPKI_SHA256);
    let policy = fixture.current_policy();
    let identity = ListenerIdentity::capture(&policy).unwrap();
    let entry = fixture.payment(DEFAULT_TTL_MS);
    let pending = issue_mainnet_intent_presence(
        &entry,
        &fixture.binding(),
        &policy,
        PresenceListener::SignedOrigin(&identity),
        None,
        now_ms(),
        Instant::now(),
    )
    .unwrap();
    let presence = verify_issued(pending).unwrap();
    let mut store = PendingApprovalStore::open(fixture.store_path()).unwrap();
    store.insert(entry.clone(), now_ms()).unwrap();
    let mut writer = fixture.audit_writer();
    attest_and_persist(
        &mut store,
        &entry,
        &ATTESTATION_KEY,
        &fixture.binding(),
        Surface::Cli,
        ConsentAudit::Writer(&mut writer),
        ConsentAuthorization::Mainnet {
            presence,
            policy: &policy,
        },
        |_, _| panic!("no grant"),
    )
    .unwrap();
    let receipt = store
        .get(&entry.approval_nonce)
        .unwrap()
        .mainnet_presence
        .clone()
        .unwrap();
    assert_eq!(receipt.version(), MAINNET_PRESENCE_RECEIPT_VERSION_2);
    let rows = consent_rows(&fixture.audit_path());
    assert_eq!(rows.len(), 2);
    for (row, rp_id, origin) in [
        (
            &rows[0],
            MAINNET_APPROVAL_RP_ID,
            MainnetConsentFixture::origin(),
        ),
        (&rows[1], SIGNED_RP_ID, SIGNED_ORIGIN.to_owned()),
    ] {
        assert_eq!(row["mainnet_presence"]["rp_id"], rp_id);
        assert_eq!(row["mainnet_presence"]["webauthn_origin"], origin);
    }
    assert_eq!(rows[1]["request_id"], receipt.request_id());
}

/// Each receipt version verifies under its own layout only: relabeled
/// receipts refuse, version 1 refuses under a signed policy, a version 2
/// receipt naming another pin or listener policy digest refuses, and version
/// 3 refuses to load.
#[test]
fn receipt_versions_verify_under_their_own_layout() {
    let local = policy_with(&[&fixture_authenticator()]);
    let signed = signed_policy();
    let entry = payment();
    let verify = |receipt: &MainnetPresenceReceipt,
                  policy: &VerifiedPolicy,
                  intent: Option<&ClassicIntent>| {
        verify_receipt_for_intent(&entry, receipt, &binding(), policy, intent, now_ms())
    };

    let legacy = verified_receipt(&local, &entry);
    assert_eq!(legacy.version(), MAINNET_PRESENCE_RECEIPT_VERSION);
    assert!(verify(&legacy, &local, None).is_ok());
    let intent_bound = receipt_on(
        &entry,
        &local,
        PresenceListener::Loopback(ORIGIN),
        Some(&intent_a()),
    );
    assert_eq!(intent_bound.version(), MAINNET_PRESENCE_RECEIPT_VERSION_2);
    assert!(verify(&intent_bound, &local, Some(&intent_a())).is_ok());
    let at_signed = signed_receipt(&entry, &signed);
    assert_eq!(at_signed.version(), MAINNET_PRESENCE_RECEIPT_VERSION_2);
    assert!(verify(&at_signed, &signed, None).is_ok());

    let mut relabeled = legacy.clone();
    relabeled.version = MAINNET_PRESENCE_RECEIPT_VERSION_2;
    assert!(relabeled.is_well_formed());
    assert_eq!(
        code(verify(&relabeled, &local, None)),
        "approval.presence_invalid",
        "version 1 relabeled as 2"
    );
    let mut relabeled = intent_bound.clone();
    relabeled.version = MAINNET_PRESENCE_RECEIPT_VERSION;
    assert!(relabeled.is_well_formed());
    assert_eq!(
        code(verify(&relabeled, &local, Some(&intent_a()))),
        "approval.presence_invalid",
        "an intent-bound version 2 relabeled as 1"
    );
    let mut relabeled = at_signed.clone();
    relabeled.version = MAINNET_PRESENCE_RECEIPT_VERSION;
    relabeled.cert_spki_sha256 = None;
    relabeled.listener_policy_digest = None;
    ORIGIN.clone_into(&mut relabeled.expected_origin);
    assert!(relabeled.is_well_formed());
    assert_eq!(
        code(verify(&relabeled, &signed, None)),
        "approval.presence_invalid",
        "version 1 under a signed policy"
    );
    for (label, pin, listener) in [
        (
            "another pin",
            Some("cd".repeat(32)),
            at_signed.listener_policy_digest.clone(),
        ),
        (
            "another listener policy digest",
            at_signed.cert_spki_sha256.clone(),
            Some("cd".repeat(32)),
        ),
    ] {
        let mut edited = at_signed.clone();
        edited.cert_spki_sha256 = pin;
        edited.listener_policy_digest = listener;
        assert!(edited.is_well_formed(), "{label}");
        assert_eq!(
            code(verify_receipt(
                &entry,
                &edited,
                &binding(),
                &signed,
                now_ms()
            )),
            "approval.presence_invalid",
            "{label}"
        );
    }

    let mut wire = serde_json::to_value(&legacy).unwrap();
    assert!(serde_json::from_value::<MainnetPresenceReceipt>(wire.clone()).is_ok());
    wire["version"] = serde_json::json!(3);
    assert!(serde_json::from_value::<MainnetPresenceReceipt>(wire).is_err());
}

/// The receipt origin bound admits `https://`, a 253-byte host and
/// `:65535`, and refuses one byte more at the wire.
#[test]
fn receipt_origin_bound_admits_267_bytes() {
    let receipt = signed_receipt(&payment(), &signed_policy());
    let host = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    assert_eq!(host.len(), 253);
    let longest = format!("https://{host}:65535");
    assert_eq!(longest.len(), 267);
    let mut wire = serde_json::to_value(&receipt).unwrap();
    wire["expected_origin"] = serde_json::json!(longest);
    let loaded: MainnetPresenceReceipt = serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(loaded.expected_origin(), longest);
    wire["expected_origin"] = serde_json::json!(format!("https://{host}e:65535"));
    let error = serde_json::from_value::<MainnetPresenceReceipt>(wire)
        .err()
        .unwrap();
    assert!(
        error.to_string().contains("string exceeds its byte bound"),
        "{error}"
    );
}

/// A version 2 receipt carries the certificate pin and the listener policy
/// digest both or neither, as lowercase hex, and both exactly with an HTTPS
/// origin; version 1 carries neither.
#[test]
fn receipt_version_2_requires_both_identity_fields() {
    let signed = serde_json::to_value(signed_receipt(&payment(), &signed_policy())).unwrap();
    assert!(serde_json::from_value::<MainnetPresenceReceipt>(signed.clone()).is_ok());
    let local = serde_json::to_value(verified_receipt(
        &policy_with(&[&fixture_authenticator()]),
        &payment(),
    ))
    .unwrap();
    let pin = signed["cert_spki_sha256"].clone();
    let listener = signed["listener_policy_digest"].clone();
    let edits: Vec<(&str, serde_json::Value)> = vec![
        ("pin alone", {
            let mut wire = signed.clone();
            wire.as_object_mut()
                .unwrap()
                .remove("listener_policy_digest");
            wire
        }),
        ("listener digest alone", {
            let mut wire = signed.clone();
            wire.as_object_mut().unwrap().remove("cert_spki_sha256");
            wire
        }),
        ("an HTTPS origin without either", {
            let mut wire = signed.clone();
            let object = wire.as_object_mut().unwrap();
            object.remove("cert_spki_sha256");
            object.remove("listener_policy_digest");
            wire
        }),
        ("uppercase pin", {
            let mut wire = signed.clone();
            wire["cert_spki_sha256"] =
                serde_json::json!(pin.as_str().unwrap().to_ascii_uppercase());
            wire
        }),
        ("a loopback origin with both", {
            let mut wire = signed.clone();
            wire["expected_origin"] = serde_json::json!(ORIGIN);
            wire
        }),
        ("version 1 with both", {
            let mut wire = local.clone();
            wire["cert_spki_sha256"] = pin.clone();
            wire["listener_policy_digest"] = listener.clone();
            wire
        }),
        ("version 1 with the pin alone", {
            let mut wire = local.clone();
            wire["cert_spki_sha256"] = pin.clone();
            wire
        }),
    ];
    for (label, wire) in edits {
        assert!(
            serde_json::from_value::<MainnetPresenceReceipt>(wire).is_err(),
            "{label}"
        );
    }
}

// ── The remote surface at a signed origin ───────────────────────────────────

/// The remote surface records a mainnet consent only for a receipt of a
/// signed-origin ceremony. Such consent is a version 5 attestation with
/// the mainnet passkey approver and a `serve-remote` row. A loopback
/// receipt refuses as unsupported with no row.
#[test]
#[serial]
fn serve_remote_admits_only_signed_origin_receipts() {
    let mut fixture = MainnetConsentFixture::new(PROFILE);
    let attempt = |fixture: &MainnetConsentFixture,
                   entry: &PendingApproval,
                   presence: VerifiedMainnetPresence,
                   policy: &VerifiedPolicy| {
        let mut store = PendingApprovalStore::open(fixture.store_path()).unwrap();
        store.insert(entry.clone(), now_ms()).unwrap();
        let mut writer = fixture.audit_writer();
        attest_and_persist(
            &mut store,
            entry,
            &ATTESTATION_KEY,
            &fixture.binding(),
            Surface::ServeRemote,
            ConsentAudit::Writer(&mut writer),
            ConsentAuthorization::Mainnet { presence, policy },
            |_, _| panic!("no grant"),
        )
    };
    let local = fixture.current_policy();
    let loopback_entry = fixture.payment(DEFAULT_TTL_MS);
    let presence = fixture.presence(&loopback_entry, &local);
    assert_eq!(
        code(attempt(&fixture, &loopback_entry, presence, &local)),
        "approval.mainnet_remote_unsupported"
    );
    assert!(consent_rows(&fixture.audit_path()).is_empty());

    fixture.sign_signed_origin_policy(&[&fixture_authenticator()], &SIGNED_CERT_SPKI_SHA256);
    let policy = fixture.current_policy();
    let identity = ListenerIdentity::capture(&policy).unwrap();
    let entry = fixture.payment(DEFAULT_TTL_MS);
    let pending = issue_mainnet_intent_presence(
        &entry,
        &fixture.binding(),
        &policy,
        PresenceListener::SignedOrigin(&identity),
        None,
        now_ms(),
        Instant::now(),
    )
    .unwrap();
    let presence = verify_issued(pending).unwrap();
    let surfaced = attempt(&fixture, &entry, presence, &policy)
        .unwrap()
        .unwrap();

    let store = PendingApprovalStore::open(fixture.store_path()).unwrap();
    let stored = store.get(&entry.approval_nonce).unwrap();
    let receipt = stored.mainnet_presence.clone().unwrap();
    assert_eq!(receipt.version(), MAINNET_PRESENCE_RECEIPT_VERSION_2);
    assert_eq!(receipt.expected_origin(), SIGNED_ORIGIN);
    let approver = AttestedApprover::MainnetPasskey {
        credential_id_b64url: receipt.credential_id_b64url(),
    };
    assert_eq!(stored.attested_approver.as_ref(), Some(&approver));
    let blob: [u8; 32] = URL_SAFE_NO_PAD
        .decode(stored.attestation_blob_b64.as_ref().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(URL_SAFE_NO_PAD.encode(blob), surfaced);
    let lifetime = entry.attested_lifetime();
    let scope = AttestationScope::pending(5, lifetime, Some(&approver), Some(&receipt)).unwrap();
    assert!(verify_attestation(
        &ATTESTATION_KEY,
        &fixture.binding(),
        &entry.approval_nonce,
        &mainnet_consent_subject(&entry, &fixture.binding()).unwrap(),
        &entry.process_uid,
        &scope,
        &blob
    ));
    let rows = consent_rows(&fixture.audit_path());
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["origin"], "serve-remote");
    assert_eq!(rows[0]["mainnet_presence"]["rp_id"], SIGNED_RP_ID);
    assert_eq!(
        rows[0]["mainnet_presence"]["webauthn_origin"],
        SIGNED_ORIGIN
    );
}

/// A policy re-sign with the same pin refuses persistence by its listener digest.
#[test]
#[serial]
fn signed_origin_persistence_refuses_a_same_pin_resign() {
    let mut fixture = MainnetConsentFixture::new(PROFILE);
    fixture.sign_signed_origin_policy(&[&fixture_authenticator()], &SIGNED_CERT_SPKI_SHA256);
    let policy = fixture.current_policy();
    let identity = ListenerIdentity::capture(&policy).unwrap();
    let verified = |entry: &PendingApproval| {
        let pending = issue_mainnet_intent_presence(
            entry,
            &fixture.binding(),
            &policy,
            PresenceListener::SignedOrigin(&identity),
            None,
            now_ms(),
            Instant::now(),
        )
        .unwrap();
        verify_issued(pending).unwrap()
    };
    let cases: Vec<(Surface, PendingApproval, VerifiedMainnetPresence)> =
        [Surface::ServeRemote, Surface::Cli]
            .into_iter()
            .map(|surface| {
                let entry = fixture.payment(DEFAULT_TTL_MS);
                let presence = verified(&entry);
                (surface, entry, presence)
            })
            .collect();
    fixture.sign_signed_origin_policy(&[&fixture_authenticator()], &SIGNED_CERT_SPKI_SHA256);
    let current = fixture.current_policy();
    assert_ne!(current.digest(), policy.digest());
    assert_eq!(
        current.mainnet().unwrap().approval_cert_spki_sha256,
        policy.mainnet().unwrap().approval_cert_spki_sha256
    );
    assert_eq!(
        fixture.current_policy().mainnet().unwrap().approval_origin,
        policy.mainnet().unwrap().approval_origin
    );
    for (surface, entry, presence) in cases {
        let mut store = PendingApprovalStore::open(fixture.store_path()).unwrap();
        store.insert(entry.clone(), now_ms()).unwrap();
        let mut writer = fixture.audit_writer();
        let result = attest_and_persist(
            &mut store,
            &entry,
            &ATTESTATION_KEY,
            &fixture.binding(),
            surface,
            ConsentAudit::Writer(&mut writer),
            ConsentAuthorization::Mainnet {
                presence,
                policy: &policy,
            },
            |_, _| panic!("no grant"),
        );
        assert_eq!(
            code(result),
            "approval.listener_policy_stale",
            "{surface:?}"
        );
        let stored = store.get(&entry.approval_nonce).unwrap();
        assert!(stored.attestation_blob_b64.is_none(), "{surface:?}");
        assert!(stored.mainnet_presence.is_none(), "{surface:?}");
    }
    assert!(consent_rows(&fixture.audit_path()).is_empty());
}

/// A pin change for the same origin between verification and persistence
/// refuses signed-origin consent as stale. Both the remote and local surfaces
/// write no row and leave the entry unattested.
#[test]
#[serial]
fn signed_origin_persistence_refuses_a_stale_listener() {
    let mut fixture = MainnetConsentFixture::new(PROFILE);
    fixture.sign_signed_origin_policy(&[&fixture_authenticator()], &SIGNED_CERT_SPKI_SHA256);
    let policy = fixture.current_policy();
    let identity = ListenerIdentity::capture(&policy).unwrap();
    let verified = |entry: &PendingApproval| {
        let pending = issue_mainnet_intent_presence(
            entry,
            &fixture.binding(),
            &policy,
            PresenceListener::SignedOrigin(&identity),
            None,
            now_ms(),
            Instant::now(),
        )
        .unwrap();
        verify_issued(pending).unwrap()
    };
    let cases: Vec<(Surface, PendingApproval, VerifiedMainnetPresence)> =
        [Surface::ServeRemote, Surface::Cli]
            .into_iter()
            .map(|surface| {
                let entry = fixture.payment(DEFAULT_TTL_MS);
                let presence = verified(&entry);
                (surface, entry, presence)
            })
            .collect();
    fixture.sign_signed_origin_policy(&[&fixture_authenticator()], &[0xcd; 32]);
    assert_eq!(
        fixture.current_policy().mainnet().unwrap().approval_origin,
        policy.mainnet().unwrap().approval_origin
    );
    for (surface, entry, presence) in cases {
        let mut store = PendingApprovalStore::open(fixture.store_path()).unwrap();
        store.insert(entry.clone(), now_ms()).unwrap();
        let mut writer = fixture.audit_writer();
        let result = attest_and_persist(
            &mut store,
            &entry,
            &ATTESTATION_KEY,
            &fixture.binding(),
            surface,
            ConsentAudit::Writer(&mut writer),
            ConsentAuthorization::Mainnet {
                presence,
                policy: &policy,
            },
            |_, _| panic!("no grant"),
        );
        assert_eq!(
            code(result),
            "approval.listener_policy_stale",
            "{surface:?}"
        );
        let stored = store.get(&entry.approval_nonce).unwrap();
        assert!(stored.attestation_blob_b64.is_none(), "{surface:?}");
        assert!(stored.mainnet_presence.is_none(), "{surface:?}");
    }
    assert!(consent_rows(&fixture.audit_path()).is_empty());
}
