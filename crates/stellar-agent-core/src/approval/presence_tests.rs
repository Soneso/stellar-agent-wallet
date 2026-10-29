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
            expected_origin: &self.origin,
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
    let lock_file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(outbox_lock_path(&fixture.audit_path()))
        .unwrap();
    let lock = crate::file_lock::HeldFileLock::try_lock(lock_file).unwrap();
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
        .challenge(&entry, &fixture.binding(), &policy)
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
            t["mainnet_presence"]["version"] = toml_edit::value(2);
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
/// layouts, computed here independently of the production builders.
#[test]
fn version_5_layout_matches_independent_hmac() {
    use hmac::{Hmac, KeyInit as _, Mac as _};
    use sha2::{Digest as _, Sha256};
    let lp = |out: &mut Vec<u8>, bytes: &[u8]| {
        out.extend(u32::try_from(bytes.len()).unwrap().to_be_bytes());
        out.extend(bytes);
    };
    let policy = policy_with(&[&fixture_authenticator()]);
    let entry = payment();
    let receipt = verified_receipt(&policy, &entry);

    let mut preimage = b"stellar-agent-mainnet-presence-receipt:v1".to_vec();
    preimage.extend(1_u32.to_be_bytes());
    lp(&mut preimage, receipt.request_id.as_bytes());
    preimage.extend(URL_SAFE_NO_PAD.decode(&receipt.random_b64url).unwrap());
    preimage.extend(7_i64.to_be_bytes());
    preimage.extend(policy.digest());
    preimage.extend([9; 32]);
    lp(&mut preimage, ORIGIN.as_bytes());
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
    let digest: [u8; 32] = Sha256::digest(&preimage).into();
    assert_eq!(receipt.digest(), Some(digest));

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
