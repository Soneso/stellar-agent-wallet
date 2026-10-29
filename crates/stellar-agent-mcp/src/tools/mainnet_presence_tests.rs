//! Mainnet consent at the MCP commit boundary.
//!
//! A mainnet commit admits only a version 5 approval whose receipt holds a
//! user-verified assertion of an approval credential in the current
//! owner-signed policy. The rows drive the commit tools of a routed mainnet
//! fixture with genuine consents from the production attester, and with the
//! records a same-user process holding the attestation key can write: the
//! genuine version 4 HMAC of a local or remote approver, and a version 5 HMAC
//! recomputed over an assertion the verifier refuses. Every refusal is the
//! uniform approval-required envelope, and no refused commit reads the
//! signing seed or sends a request that signs.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only fixture construction and assertions"
)]

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use stellar_agent_core::approval::attestation::AttestationScope;
use stellar_agent_core::approval::{
    AttestationBinding, AttestedApprover, MAINNET_APPROVAL_RP_ID, OperatorApprovalCredential,
    OperatorApprovalCredentialStore, PendingApproval, PendingApprovalStore, compute_attestation_v4,
    compute_attestation_v5, default_operator_approval_credentials_path, load_attestation_key,
    mainnet_consent_subject, verify_attestation,
};
use stellar_agent_core::profile::owner_key::OwnerKeyContext;
use stellar_agent_test_support::webauthn::{
    FLAG_UP, FLAG_UV, TestAssertion, TestAuthenticator, fixture_authenticator,
};

use super::common::tests::mainnet::{
    ClassicRun, Fixture, REMOTE_CREDENTIAL, Tool, X402Run, approval_for, assert_no_pre_send_entry,
    assert_x402_refused_before_intent, authorizations, is_consumed, remote_approval,
    stored_approval, wire, x402_args,
};
use super::common::{
    DispatchOutcome, GatedApprovalKind, approval_required_indistinguishable,
    verify_attestation_gate,
};
use super::x402_authenticated_mainnet_tests::{HOME, Run as AuthenticatedRun, signings};

/// The profile every fixture consents for.
const PROFILE: &str = "operator";

fn binding() -> AttestationBinding<'static> {
    AttestationBinding::new(PROFILE, "stellar:mainnet")
}

fn now_ms() -> u64 {
    stellar_agent_core::timefmt::now_unix_ms().unwrap()
}

/// The attestation key of the fixture profile, as any process of its user
/// reads it.
fn attestation_key(f: &Fixture) -> [u8; 32] {
    let profile = f.server.security_profile();
    let key = load_attestation_key(
        &profile.attestation_key_id,
        &OwnerKeyContext::for_profile(PROFILE, profile),
    )
    .unwrap();
    <[u8; 32]>::try_from(key.as_slice()).unwrap()
}

fn store_path(f: &Fixture) -> std::path::PathBuf {
    f.server
        .resolve_approval_dir()
        .unwrap()
        .join(format!("{PROFILE}.toml"))
}

/// Stores `entry` with the genuine version 4 attestation of `approver`, as a
/// process without the mainnet witness records it, and returns the blob.
fn record_v4(f: &Fixture, entry: &PendingApproval, approver: &AttestedApprover) -> String {
    let key = attestation_key(f);
    let subject = mainnet_consent_subject(entry, &binding()).unwrap();
    let blob = compute_attestation_v4(
        &key,
        &binding(),
        &entry.approval_nonce,
        &subject,
        &entry.process_uid,
        &entry.attested_lifetime(),
        approver,
    );
    let mut store = PendingApprovalStore::open(store_path(f)).unwrap();
    store.insert(entry.clone(), now_ms()).unwrap();
    store
        .record_attestation(&entry.approval_nonce, blob, approver.clone())
        .unwrap();
    let recorded = store.get(&entry.approval_nonce).unwrap();
    assert!(
        verify_attestation(
            &key,
            &binding(),
            &entry.approval_nonce,
            &subject,
            &recorded.process_uid,
            &recorded.attestation_scope().unwrap(),
            &blob,
        ),
        "{approver:?}: the blob verifies under the version 4 layout"
    );
    URL_SAFE_NO_PAD.encode(blob)
}

/// An assertion the verifier refuses, in place of the genuine one of a
/// consent.
#[derive(Clone, Copy, Debug)]
enum Forged {
    /// The pinned credential over another challenge.
    OtherChallenge,
    /// The pinned credential's assertion carrying the signature of another
    /// of its assertions.
    BadSignature,
    /// The pinned credential with user presence and no user verification.
    PresenceOnly,
    /// A credential the signed policy does not list.
    Unpinned,
}

const FORGED: [Forged; 4] = [
    Forged::OtherChallenge,
    Forged::BadSignature,
    Forged::PresenceOnly,
    Forged::Unpinned,
];

impl Forged {
    fn assertion(self, challenge: [u8; 32], origin: &str) -> TestAssertion {
        let pinned = fixture_authenticator();
        let mut other = challenge;
        other[0] ^= 1;
        match self {
            Self::OtherChallenge => {
                pinned.assert(other, origin, MAINNET_APPROVAL_RP_ID, FLAG_UP | FLAG_UV, 1)
            }
            Self::BadSignature => {
                let mut assertion = pinned.assert(
                    challenge,
                    origin,
                    MAINNET_APPROVAL_RP_ID,
                    FLAG_UP | FLAG_UV,
                    1,
                );
                assertion.signature_compact = pinned
                    .assert(other, origin, MAINNET_APPROVAL_RP_ID, FLAG_UP | FLAG_UV, 1)
                    .signature_compact;
                assertion
            }
            Self::PresenceOnly => {
                pinned.assert(challenge, origin, MAINNET_APPROVAL_RP_ID, FLAG_UP, 1)
            }
            Self::Unpinned => TestAuthenticator::from_seed([0x33; 32], vec![0x44; 16]).assert(
                challenge,
                origin,
                MAINNET_APPROVAL_RP_ID,
                FLAG_UP | FLAG_UV,
                1,
            ),
        }
    }
}

fn bytes(item: &toml_edit::Item) -> Vec<u8> {
    item.as_array()
        .unwrap()
        .iter()
        .map(|byte| u8::try_from(byte.as_integer().unwrap()).unwrap())
        .collect()
}

fn byte_array(bytes: &[u8]) -> toml_edit::Item {
    toml_edit::value(
        bytes
            .iter()
            .map(|byte| i64::from(*byte))
            .collect::<toml_edit::Array>(),
    )
}

/// Rewrites the stored pending entry `nonce` of `f` with `edit`.
fn edit_stored(f: &Fixture, nonce: &str, edit: impl FnOnce(&mut toml_edit::Table)) {
    let path = store_path(f);
    let mut document = std::fs::read_to_string(&path)
        .unwrap()
        .parse::<toml_edit::DocumentMut>()
        .unwrap();
    let entry = document["pending"]
        .as_array_of_tables_mut()
        .unwrap()
        .iter_mut()
        .find(|entry| {
            entry
                .get("approval_nonce")
                .and_then(toml_edit::Item::as_str)
                == Some(nonce)
        })
        .unwrap();
    edit(entry);
    std::fs::write(&path, document.to_string()).unwrap();
}

/// Replaces the assertion of the consented entry `nonce` with a `forged` one
/// over the same challenge and origin, and recomputes its version 5 HMAC with
/// the attestation key; returns that blob.
fn forge(f: &Fixture, nonce: &str, forged: Forged) -> String {
    edit_stored(f, nonce, |entry| {
        let assertion = &mut entry["mainnet_presence"]["assertion"];
        let client: serde_json::Value =
            serde_json::from_slice(&bytes(&assertion["client_data_json"])).unwrap();
        let challenge: [u8; 32] = URL_SAFE_NO_PAD
            .decode(client["challenge"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let replacement = forged.assertion(challenge, client["origin"].as_str().unwrap());
        assertion["credential_id"] = byte_array(&replacement.credential_id);
        assertion["authenticator_data"] = byte_array(&replacement.authenticator_data);
        assertion["client_data_json"] = byte_array(&replacement.client_data_json);
        assertion["signature_compact"] = byte_array(&replacement.signature_compact);
        entry["attested_approver"]["credential_id_b64url"] =
            toml_edit::value(URL_SAFE_NO_PAD.encode(&replacement.credential_id));
    });
    let store = PendingApprovalStore::open(store_path(f)).unwrap();
    let stored = store.get(nonce).unwrap();
    let Some(AttestationScope::V5(lifetime, approver, receipt)) = stored.attestation_scope() else {
        panic!("{forged:?}: the rewritten record keeps a version 5 scope")
    };
    let blob = URL_SAFE_NO_PAD.encode(compute_attestation_v5(
        &attestation_key(f),
        &binding(),
        nonce,
        &mainnet_consent_subject(stored, &binding()).unwrap(),
        &stored.process_uid,
        &lifetime,
        approver,
        receipt,
    ));
    drop(store);
    edit_stored(f, nonce, |entry| {
        entry["attestation_blob_b64"] = toml_edit::value(blob.clone());
    });
    blob
}

/// The debug log of this thread, which names the stable code behind each
/// uniform refusal.
struct Diagnostics {
    capture: stellar_agent_test_support::CaptureWriter,
    _guard: tracing::subscriber::DefaultGuard,
    _inert: tracing::Dispatch,
}

impl Diagnostics {
    fn install() -> Self {
        let inert = stellar_agent_test_support::inert_dispatcher();
        let capture = stellar_agent_test_support::CaptureWriter::new();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_ansi(false)
            .with_writer(capture.clone())
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();
        Self {
            capture,
            _guard: guard,
            _inert: inert,
        }
    }

    /// Asserts that the log since the last call names `code`, and clears it.
    fn assert_refused_with(&self, context: &str, code: &str) {
        let log = self.capture.captured_str();
        self.capture.clear();
        assert!(log.contains(code), "{context}: expected {code} in {log}");
    }
}

/// The stable code the witness refuses a forged assertion with.
const PRESENCE_INVALID: &str = "approval.presence_invalid";

/// `value` without its `request_id` fields.
fn normalized(mut value: serde_json::Value) -> serde_json::Value {
    fn strip(value: &mut serde_json::Value) {
        match value {
            serde_json::Value::Object(map) => {
                map.remove("request_id");
                map.values_mut().for_each(strip);
            }
            serde_json::Value::Array(items) => items.iter_mut().for_each(strip),
            _ => {}
        }
    }
    strip(&mut value);
    value
}

/// Asserts that `result` is the uniform approval-required refusal.
fn assert_uniform(context: &str, result: &serde_json::Value) {
    assert_eq!(result["ok"], false, "{context}: {result}");
    assert_eq!(
        normalized(result.clone()),
        normalized(wire(&approval_required_indistinguishable(PROFILE))),
        "{context}"
    );
}

/// Asserts that the classic commit of `entry` read no seed, minted no
/// authorization, sent nothing and left the approval unspent.
fn assert_classic_unsigned(context: &str, run: &ClassicRun, entry: &PendingApproval) {
    assert_eq!(run.seed_reads(), 0, "{context}");
    assert_eq!(run.control.count("sendTransaction"), 0, "{context}");
    assert!(authorizations(&run.f).is_empty(), "{context}");
    assert_no_pre_send_entry(run);
    if let Some(stored) = stored_approval(&run.f, &entry.approval_nonce) {
        assert!(
            !is_consumed(&stored),
            "{context}: the approval stays unspent"
        );
    }
}

/// Asserts the accepted classic commit of the run's own approval.
fn assert_classic_accepted(context: &str, run: &ClassicRun, result: &serde_json::Value) {
    assert_eq!(result["ok"], true, "{context}: {result}");
    assert_eq!(run.control.count("sendTransaction"), 1, "{context}");
    assert!(
        is_consumed(&stored_approval(&run.f, &run.entry.approval_nonce).unwrap()),
        "{context}"
    );
}

/// Enrolls [`REMOTE_CREDENTIAL`] as an operator approval credential of the
/// fixture profile.
fn enroll_remote_credential() {
    let mut key = vec![0x04u8; 65];
    key[1] = 7;
    OperatorApprovalCredentialStore::new(
        default_operator_approval_credentials_path(PROFILE).unwrap(),
    )
    .enroll(OperatorApprovalCredential {
        credential_id_b64url: REMOTE_CREDENTIAL.to_owned(),
        public_key_sec1_b64: URL_SAFE_NO_PAD.encode(&key),
        rp_id: "wallet.example.invalid".to_owned(),
        label: "device".to_owned(),
        registered_at_unix_ms: 1,
        sign_count: None,
    })
    .unwrap();
}

/// A genuine version 4 HMAC of the local operator, and of a remote approver
/// whose credential is allowed and enrolled, authorizes no mainnet commit;
/// the presence-backed consent of the same run commits.
#[tokio::test]
#[serial_test::serial(keyring)]
async fn mainnet_commit_rejects_a_genuine_local_v4_attestation() {
    let run = ClassicRun::with(
        Tool::Pay,
        |raw| raw,
        |profile| profile.remote_approval = Some(remote_approval(&[REMOTE_CREDENTIAL])),
        |_| {},
    )
    .await;
    enroll_remote_credential();
    let xdr = run.args["envelope_xdr"].as_str().unwrap().to_owned();
    let diagnostics = Diagnostics::install();
    for approver in [
        AttestedApprover::Local,
        AttestedApprover::Remote {
            credential_id_b64url: REMOTE_CREDENTIAL.to_owned(),
        },
    ] {
        let context = format!("{approver:?}");
        let entry = approval_for(Tool::Pay, &run.f, &xdr, 600_000);
        let blob = record_v4(&run.f, &entry, &approver);
        let result = run
            .commit_with(run.commit_args_for(&xdr, &entry.approval_nonce, &blob))
            .await;
        assert_uniform(&context, &result);
        diagnostics.assert_refused_with(&context, "approval.presence_required");
        assert_classic_unsigned(&context, &run, &entry);
    }
    let result = run.commit().await;
    assert_classic_accepted("the presence-backed consent", &run, &result);
}

/// Each commit kind refuses a version 5 record over an assertion the
/// verifier refuses, with the uniform envelope and before any signing, and
/// proceeds with the genuine assertion of the pinned credential: the four
/// classic commits, the plain x402 payment and the authenticated x402
/// payment.
#[tokio::test]
#[serial_test::serial(keyring)]
async fn mainnet_commit_requires_the_pinned_assertion_for_every_kind() {
    let diagnostics = Diagnostics::install();
    for tool in Tool::ALL {
        let run = ClassicRun::new(tool).await;
        for forged in FORGED {
            let context = format!("{tool:?} {forged:?}");
            let (mut args, entry) = run.prepare_again().await;
            args["approval_attestation"] =
                serde_json::json!(forge(&run.f, &entry.approval_nonce, forged));
            let result = run.commit_with(args).await;
            assert_uniform(&context, &result);
            diagnostics.assert_refused_with(&context, PRESENCE_INVALID);
            assert_classic_unsigned(&context, &run, &entry);
        }
        let result = run.commit().await;
        assert_classic_accepted(&format!("{tool:?}"), &run, &result);
    }

    let run = X402Run::new().await;
    for forged in FORGED {
        let context = format!("x402 {forged:?}");
        let (nonce, _) = X402Run::approve(&run.f, &run.control).await;
        let blob = forge(&run.f, &nonce, forged);
        let result = run.pay_with(x402_args(&run.f, Some((&nonce, &blob)))).await;
        assert_uniform(&context, &result);
        diagnostics.assert_refused_with(&context, PRESENCE_INVALID);
        assert_x402_refused_before_intent(&run, &result, "policy.approval_required", 0);
    }
    let result = run.pay().await;
    assert_eq!(result["ok"], true, "x402: {result}");
    assert_eq!(authorizations(&run.f).len(), 2, "x402: intent and child");

    let run = AuthenticatedRun::new().await;
    for forged in FORGED {
        let context = format!("authenticated x402 {forged:?}");
        let (nonce, _) = run.prepare().await;
        let blob = forge(&run.f, &nonce, forged);
        let result = run.pay(HOME, &(nonce, blob)).await;
        assert_uniform(&context, &result);
        diagnostics.assert_refused_with(&context, PRESENCE_INVALID);
        assert!(signings().is_empty(), "{context}");
        assert_eq!(run.double.posts().await, 0, "{context}");
        assert!(authorizations(&run.f).is_empty(), "{context}");
        assert_eq!(
            run.f.seed_reads.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "{context}"
        );
    }
    let approval = run.prepare().await;
    let result = run.pay(HOME, &approval).await;
    assert_eq!(result["ok"], true, "authenticated x402: {result}");
    assert_eq!(signings().len(), 1, "authenticated x402");
}

/// The other credential of the signed policy changes.
fn other_credential_line() -> String {
    let other = TestAuthenticator::from_seed([0x33; 32], vec![0x44; 16]);
    format!(
        "{{ credential_id_b64url = \"{}\", public_key_sec1_b64url = \"{}\" }}",
        other.credential_id_b64url(),
        other.public_key_sec1_b64url()
    )
}

/// The policy file of the fixture profile.
fn policy_file() -> std::path::PathBuf {
    stellar_agent_core::profile::schema::default_policy_dir()
        .unwrap()
        .join(format!("{PROFILE}.toml"))
}

/// The run's own approval presented to the attestation gate of its running
/// server.
async fn gate_of_running_server(run: &ClassicRun) -> serde_json::Value {
    let outcome = DispatchOutcome::RequireApproval(
        stellar_agent_core::policy::ApprovalRequest::new(run.entry.approval_nonce.clone(), 120)
            .into(),
    );
    let refusal = verify_attestation_gate(
        &run.f.server,
        &outcome,
        GatedApprovalKind::Payment,
        run.args["envelope_xdr"].as_str().unwrap(),
        Some(&run.entry.approval_nonce),
        run.args["approval_attestation"].as_str(),
        "stellar_pay_commit",
    )
    .await
    .unwrap_err();
    wire(&refusal)
}

/// A consent recorded before a policy change authorizes nothing after it:
/// the running server answers every change with its restart refusal and its
/// gate with the uniform refusal; a server started on a policy re-signed at
/// a higher sequence, with the credential revoked or kept, refuses the
/// consent uniformly; an unsigned edit and an absent pin stop the start
/// itself. A changed envelope and an altered stored expiry refuse uniformly
/// on the running server. No row signs.
#[tokio::test]
#[serial_test::serial(keyring)]
async fn mainnet_commit_rechecks_consent_after_policy_change() {
    let diagnostics = Diagnostics::install();
    for change in [
        "revoked credential",
        "re-signed body",
        "unsigned edit",
        "absent pin",
    ] {
        let mut run = ClassicRun::new(Tool::Pay).await;
        let raw = run.f.raw.replace("sequence = 7", "sequence = 8");
        match change {
            "revoked credential" => {
                let line = raw
                    .lines()
                    .find(|line| line.contains("credential_id_b64url"))
                    .unwrap()
                    .trim()
                    .trim_end_matches(',')
                    .to_owned();
                Fixture::write_policy(&raw.replace(&line, &other_credential_line()));
            }
            "re-signed body" => Fixture::write_policy(&raw),
            "unsigned edit" => {
                let signed = std::fs::read_to_string(policy_file()).unwrap();
                std::fs::write(
                    policy_file(),
                    signed.replace(
                        "authorization_ttl_seconds = 60",
                        "authorization_ttl_seconds = 59",
                    ),
                )
                .unwrap();
            }
            "absent pin" => {
                let pin = stellar_agent_core::policy::pin::PinScope::new(
                    &run.f.server.window_path,
                    &run.f.server.profile.policy_window_state_key_id,
                )
                .pin_entry_ref();
                keyring_core::Entry::new(&pin.service, &pin.account)
                    .unwrap()
                    .delete_credential()
                    .unwrap();
            }
            _ => unreachable!(),
        }
        let result = run.commit().await;
        assert_eq!(result["ok"], false, "{change}: {result}");
        assert_eq!(
            result["error"]["code"], "network.mainnet_write_forbidden",
            "{change}: {result}"
        );
        assert_classic_unsigned(change, &run, &run.entry.clone());
        let gate = gate_of_running_server(&run).await;
        assert_eq!(
            normalized(gate),
            normalized(wire(&approval_required_indistinguishable(PROFILE))),
            "{change}: the running gate"
        );
        diagnostics.assert_refused_with(change, "policy.changed_before_proof");
        let restarted = run.restart();
        if matches!(change, "unsigned edit" | "absent pin") {
            assert!(restarted.is_err(), "{change}: the start refuses");
            continue;
        }
        restarted.unwrap();
        let result = run.commit().await;
        assert_uniform(&format!("{change} after restart"), &result);
        diagnostics.assert_refused_with(change, "approval.presence_policy_unavailable");
        assert_classic_unsigned(change, &run, &run.entry.clone());
    }

    let run = ClassicRun::new(Tool::Pay).await;
    let changed = {
        use stellar_xdr::{Limits, ReadXdr as _, TransactionEnvelope, WriteXdr as _};
        let TransactionEnvelope::Tx(mut envelope) = TransactionEnvelope::from_xdr_base64(
            run.args["envelope_xdr"].as_str().unwrap(),
            Limits::none(),
        )
        .unwrap() else {
            panic!("classic envelope expected")
        };
        envelope.tx.fee += 1;
        TransactionEnvelope::Tx(envelope)
            .to_xdr_base64(Limits::none())
            .unwrap()
    };
    let result = run
        .commit_with(run.commit_args_for(
            &changed,
            &run.entry.approval_nonce,
            run.args["approval_attestation"].as_str().unwrap(),
        ))
        .await;
    assert_uniform("changed envelope", &result);
    diagnostics.assert_refused_with("changed envelope", "approval.attestation_invalid");
    assert_classic_unsigned("changed envelope", &run, &run.entry);

    edit_stored(&run.f, &run.entry.approval_nonce, |entry| {
        let expires = entry["expires_at_unix_ms"].as_integer().unwrap();
        entry["expires_at_unix_ms"] = toml_edit::value(expires - 1_000);
    });
    let result = run.commit().await;
    assert_uniform("altered expiry", &result);
    diagnostics.assert_refused_with("altered expiry", "approval.attestation_invalid");
    assert_classic_unsigned("altered expiry", &run, &run.entry);
}

/// Commits `args` on `run` and asserts that the commit read no seed and sent
/// nothing; returns the result.
async fn refused_commit(run: &ClassicRun, args: serde_json::Value) -> serde_json::Value {
    let seeds = run.seed_reads();
    let result = run.commit_with(args).await;
    assert_eq!(run.seed_reads(), seeds, "{result}");
    assert_eq!(run.control.count("sendTransaction"), 0, "{result}");
    result
}

/// Every failed proof answers with the same envelope: a missing record, a
/// genuine version 4 record, an assertion over another challenge, a bad
/// signature, an assertion without user verification, an unpinned
/// credential and a malformed receipt. A rejected and a consumed approval
/// keep their own codes.
#[tokio::test]
#[serial_test::serial(keyring)]
async fn mainnet_presence_failures_are_indistinguishable() {
    let run = ClassicRun::new(Tool::Pay).await;
    let xdr = run.args["envelope_xdr"].as_str().unwrap().to_owned();
    let genuine = run.args["approval_attestation"]
        .as_str()
        .unwrap()
        .to_owned();
    let diagnostics = Diagnostics::install();

    let (_, rejected) = run.prepare_again().await;
    PendingApprovalStore::open(store_path(&run.f))
        .unwrap()
        .reject(&rejected.approval_nonce, now_ms(), 600_000)
        .unwrap();
    let result = refused_commit(
        &run,
        run.commit_args_for(&xdr, &rejected.approval_nonce, &genuine),
    )
    .await;
    assert_eq!(
        result["error"]["code"], "policy.approval_rejected",
        "{result}"
    );

    let mut refusals = Vec::new();
    let missing = approval_for(Tool::Pay, &run.f, &xdr, 600_000);
    refusals.push((
        "missing record".to_owned(),
        refused_commit(
            &run,
            run.commit_args_for(&xdr, &missing.approval_nonce, &genuine),
        )
        .await,
    ));
    diagnostics.assert_refused_with("missing record", "approval entry not found");
    let legacy = approval_for(Tool::Pay, &run.f, &xdr, 600_000);
    let blob = record_v4(&run.f, &legacy, &AttestedApprover::Local);
    refusals.push((
        "version 4".to_owned(),
        refused_commit(
            &run,
            run.commit_args_for(&xdr, &legacy.approval_nonce, &blob),
        )
        .await,
    ));
    diagnostics.assert_refused_with("version 4", "approval.presence_required");
    for forged in FORGED {
        let (mut args, entry) = run.prepare_again().await;
        args["approval_attestation"] =
            serde_json::json!(forge(&run.f, &entry.approval_nonce, forged));
        refusals.push((format!("{forged:?}"), refused_commit(&run, args).await));
        diagnostics.assert_refused_with(&format!("{forged:?}"), PRESENCE_INVALID);
    }

    // A malformed receipt leaves the whole store unreadable; the store is
    // restored afterwards for the remaining rows.
    let (args, malformed) = run.prepare_again().await;
    let intact = std::fs::read(store_path(&run.f)).unwrap();
    edit_stored(&run.f, &malformed.approval_nonce, |entry| {
        entry["mainnet_presence"]["random_b64url"] = toml_edit::value("AAAA");
    });
    refusals.push((
        "malformed receipt".to_owned(),
        refused_commit(&run, args).await,
    ));
    diagnostics.assert_refused_with("malformed receipt", "approval store open failed");
    std::fs::write(store_path(&run.f), intact).unwrap();

    let result = run.commit().await;
    assert_classic_accepted("the genuine consent", &run, &result);
    let result = refused_commit(
        &run,
        run.commit_args_for(&xdr, &run.entry.approval_nonce, &genuine),
    )
    .await;
    assert_eq!(
        result["error"]["code"], "policy.approval_consumed",
        "{result}"
    );

    let uniform = normalized(wire(&approval_required_indistinguishable(PROFILE)));
    for (context, result) in &refusals {
        assert_eq!(normalized(result.clone()), uniform, "{context}: {result}");
    }
}
