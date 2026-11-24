#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test fixtures and assertions"
)]

use super::*;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::Parser;
use serde_json::{Value, json};
use serial_test::serial;
use std::sync::Arc;
use stellar_agent_core::approval::{
    ApprovalKind, AttestationBinding, AttestedApprover, ConsumedOutcome, PendingApproval,
    PendingApprovalStore, compute_attestation_v4, fixtures,
    mainnet_fixtures::{ALLOWED_DESTINATION, ATTESTATION_KEY, MainnetConsentFixture},
    presence::approval_view_subject,
};
use stellar_agent_mcp::server::WalletServer;

const NAME: &str = "approval-status-test";

fn write_entries(path: &std::path::Path, entries: &[PendingApproval]) {
    #[derive(serde::Serialize)]
    struct File<'a> {
        pending: &'a [PendingApproval],
    }
    std::fs::write(path, toml::to_string(&File { pending: entries }).unwrap()).unwrap();
}

fn testnet_profile() -> Profile {
    let profile = Profile::builder_testnet_named(NAME, "status-sign", "key", "status-nonce", "key")
        .with_noop_engine()
        .build();
    stellar_agent_core::profile::loader::save_to_dir(
        NAME,
        &profile,
        &stellar_agent_core::profile::schema::default_profile_dir().unwrap(),
    )
    .unwrap();
    let key = &profile.attestation_key_id;
    keyring_core::Entry::new(&key.service, &key.account)
        .unwrap()
        .set_password(&URL_SAFE_NO_PAD.encode(ATTESTATION_KEY))
        .unwrap();
    profile
}

fn payment() -> PendingApproval {
    fixtures::payment_pending(
        ALLOWED_DESTINATION,
        ALLOWED_DESTINATION,
        "XLM",
        10,
        None,
        100,
        7,
        "123".into(),
        600_000,
    )
}

fn attest(entry: &mut PendingApproval, profile: &Profile) {
    entry.attested_approver = Some(AttestedApprover::Local);
    entry.attestation_version = 4;
    let binding = AttestationBinding::new(NAME, profile.chain_id.caip2_str());
    let subject = approval_view_subject(entry, &binding).unwrap();
    entry.attestation_blob_b64 = Some(URL_SAFE_NO_PAD.encode(compute_attestation_v4(
        &ATTESTATION_KEY,
        &binding,
        &entry.approval_nonce,
        &subject,
        &entry.process_uid,
        &entry.attested_lifetime(),
        &AttestedApprover::Local,
    )));
}

async fn surfaces(name: &str, server: &WalletServer, nonce: &str) -> (i32, Value) {
    let parsed = crate::Cli::try_parse_from([
        "stellar-agent",
        "approve",
        "status",
        nonce,
        "--profile",
        name,
    ])
    .unwrap();
    let crate::Commands::Approve(args) = parsed.command else {
        panic!("approve command")
    };
    assert_eq!(
        args.profile_flag(),
        Some(name),
        "status selects its own profile"
    );
    crate::common::render::take_rendered_for_test();
    let rc = super::super::dispatch(args).await;
    let cli = crate::common::render::take_rendered_for_test()
        .pop()
        .unwrap();
    let mcp = server
        .approval_status_for_test(nonce.to_owned())
        .await
        .unwrap();
    let wire: Value = serde_json::from_str(&mcp.content[0].as_text().unwrap().text).unwrap();
    assert_eq!(
        mcp.is_error == Some(true),
        rc != 0,
        "both adapters flag refusal"
    );
    assert_eq!(
        cli["data"], wire["data"],
        "CLI and MCP have the same status JSON"
    );
    assert_eq!(
        cli["error"]["code"], wire["error"]["code"],
        "both adapters preserve wire codes"
    );
    (rc, cli)
}

fn unsupported() -> Vec<PendingApproval> {
    let uid = "123".to_owned();
    let rp = stellar_agent_core::approval::MAINNET_APPROVAL_RP_ID.to_owned();
    vec![
        PendingApproval::new_passkey_pending(
            [0; 32],
            vec![1; 32],
            "CAAAA...AAAAA".into(),
            vec![1],
            [0; 32],
            rp.clone(),
            uid.clone(),
            600_000,
        )
        .unwrap(),
        PendingApproval::new_register_passkey_pending(
            "CAAAA...AAAAA".into(),
            vec![1],
            [0; 32],
            rp,
            [0; 32],
            uid.clone(),
            600_000,
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
            600_000,
        )
        .unwrap(),
        PendingApproval::new_trustline_clawback_opt_in_pending(
            stellar_agent_core::profile::caip2::Caip2::Testnet
                .network_passphrase()
                .into(),
            "USD".into(),
            ALLOWED_DESTINATION.into(),
            uid,
            600_000,
        )
        .unwrap(),
        fixtures::rule_proposal_pending(),
        fixtures::mpp_pending(),
    ]
}

#[tokio::test(flavor = "current_thread")]
#[serial(keyring)]
#[serial]
async fn approval_status_cli_mcp_parity() {
    stellar_agent_test_support::keyring_mock::install().unwrap();
    let root = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(root.path());
    let profile = testnet_profile();
    let server = WalletServer::new(profile.clone()).unwrap();
    let path = super::super::approval_store_dir()
        .unwrap()
        .join(format!("{NAME}.toml"));
    drop(PendingApprovalStore::open(path.clone()).unwrap());
    let entry = payment();
    let mut attested = entry.clone();
    attest(&mut attested, &profile);
    let mut expired = entry.clone();
    expired.created_at_unix_ms = 1;
    expired.expires_at_unix_ms = 2;
    attest(&mut expired, &profile);
    let mut rejected = entry.clone();
    rejected.created_at_unix_ms = 1;
    rejected.expires_at_unix_ms = 2;
    rejected.kind = ApprovalKind::Rejected {
        original_kind_name: "PaymentSimulated".into(),
    };
    let mut consumed = expired.clone();
    consumed.kind = ApprovalKind::Consumed {
        original_kind_name: "PaymentSimulated".into(),
        tx_hash: "a".repeat(64),
        outcome: ConsumedOutcome::Confirmed,
    };
    for (stored, state, reason) in [
        (&entry, "pending", "attestation_invalid"),
        (&attested, "attested", "ok"),
        (&expired, "expired", "expired"),
        (&rejected, "rejected", "rejected"),
        (&consumed, "consumed", "consumed"),
    ] {
        write_entries(&path, std::slice::from_ref(stored));
        let before = crate::common::test_support::tree(root.path());
        for _ in 0..2 {
            let (rc, result) = surfaces(NAME, &server, &stored.approval_nonce).await;
            assert_eq!(rc, 0, "{state}: {result}");
            let view = &result["data"];
            assert_eq!(view["state"], state, "stored tombstones precede expiry");
            assert_eq!(
                view["kind"], "PaymentSimulated",
                "original kind survives tombstones"
            );
            assert_eq!(
                view["verification"],
                json!({"supported":true,"valid":reason == "ok","reason":reason})
            );
            assert_eq!(view["reusable"], false);
            assert_eq!(view["reuse_kind"], "none");
            assert_eq!(
                view.get("binding"),
                (state != "rejected").then_some(&json!("legacy-envelope")),
                "consumed approvals retain their binding; rejection discards it"
            );
            assert!(
                view.get("business_id").is_none(),
                "inbox has no operation link"
            );
            assert!(view.get("waiting_expires_at_ms").is_none());
            assert!(view.get("execution_expires_at_ms").is_none());
            assert!(
                view.get("attested_at_ms").is_none(),
                "testnet has no stored consent time"
            );
            assert_eq!(
                view.get("subject_digest").is_none(),
                matches!(state, "consumed" | "rejected"),
                "tombstones omit their subject"
            );
            assert_eq!(
                view.get("created_at_ms").is_none(),
                state == "rejected",
                "rejection time replaces creation"
            );
            if state == "rejected" {
                assert_eq!(view["rejected_at_ms"], 1);
            }
            if state == "consumed" {
                assert_eq!(view["tx_hash"], "a".repeat(64));
                assert_eq!(view["outcome"], "confirmed");
            }
            for forbidden in [
                "attestation_blob_b64",
                "mainnet_presence",
                "passkey_assertion",
                "credential_id",
                "link_token",
            ] {
                assert!(
                    view.get(forbidden).is_none(),
                    "status excludes proof material"
                );
            }
            if let Some(blob) = &stored.attestation_blob_b64 {
                assert!(
                    !view.to_string().contains(blob),
                    "status never serializes the proof blob"
                );
            }
        }
        assert_eq!(
            crate::common::test_support::tree(root.path()),
            before,
            "repeated status preserves domain bytes"
        );
    }
    for stored in unsupported() {
        write_entries(&path, std::slice::from_ref(&stored));
        let (rc, result) = surfaces(NAME, &server, &stored.approval_nonce).await;
        assert_eq!(rc, 0);
        assert_eq!(result["data"]["kind"], stored.kind.kind_name());
        assert_eq!(result["data"]["verification"], json!({"supported":false}));
        assert_eq!(
            result["data"].get("valid"),
            Some(&Value::Null),
            "unsupported validity is explicitly null"
        );
    }
    write_entries(&path, &[attested.clone(), rejected]);
    assert_eq!(
        surfaces(NAME, &server, &attested.approval_nonce).await.1["data"]["state"],
        "attested",
        "first duplicate wins"
    );
    write_entries(&path, &[expired]);
    PendingApprovalStore::open(path.clone())
        .unwrap()
        .gc_expired(u64::MAX)
        .unwrap();
    for nonce in [
        &entry.approval_nonce,
        "garbage",
        "é\n\u{1b}[31m",
        "-AAAAAAAAAAAAAAAAAAAAA",
    ] {
        let (rc, result) = surfaces(NAME, &server, nonce).await;
        assert_eq!(rc, 1);
        assert_eq!(
            result["error"]["code"], "approval.unknown",
            "unknown and collected nonces share the typed refusal"
        );
        assert!(!result["error"]["message"].as_str().unwrap().contains(nonce));
    }
}

#[tokio::test(flavor = "current_thread")]
#[serial(keyring)]
#[serial]
async fn approval_status_errors_end_to_end() {
    stellar_agent_test_support::keyring_mock::install().unwrap();
    let root = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(root.path());
    let profile = testnet_profile();
    let server = WalletServer::new(profile.clone()).unwrap();
    let path = super::super::approval_store_dir()
        .unwrap()
        .join(format!("{NAME}.toml"));
    let store = PendingApprovalStore::open(path.clone()).unwrap();
    let nonce = payment().approval_nonce;
    let (rc, result) = surfaces(NAME, &server, &nonce).await;
    assert_eq!(rc, 1);
    assert_eq!(
        result["error"]["code"], "approval.store_open_failed",
        "lock errors keep the status wire code"
    );
    assert!(
        result["error"]["message"]
            .as_str()
            .unwrap()
            .contains("lock")
    );
    drop(store);
    for content in ["malformed = [", "[[pending]]\napproval_nonce = 'short'"] {
        std::fs::write(&path, content).unwrap();
        let (rc, result) = surfaces(NAME, &server, &nonce).await;
        assert_eq!(rc, 1);
        assert_eq!(
            result["error"]["code"], "approval.store_open_failed",
            "strict decode failures cross both surfaces"
        );
    }
    let entry = payment();
    write_entries(&path, std::slice::from_ref(&entry));
    let window = PersistedWindowStore::for_profile(NAME);
    stellar_agent_network::signed_intent::test_helpers::seed_two_intents(&profile, &window)
        .unwrap();
    let bytes = std::fs::read(window.path()).unwrap();
    let mut corrupt = bytes.clone();
    corrupt[0] ^= 1;
    std::fs::write(window.path(), &corrupt).unwrap();
    let (rc, result) = surfaces(NAME, &server, &entry.approval_nonce).await;
    assert_eq!(rc, 1, "durable corruption refuses even with a valid inbox");
    assert_eq!(
        result["error"]["code"], "submission.record_unavailable",
        "durable corruption never falls back to a valid inbox"
    );
    std::fs::write(window.path(), bytes).unwrap();
    assert_eq!(
        surfaces(NAME, &server, &entry.approval_nonce).await.0,
        0,
        "a later read needs no manual reset"
    );
}

/// Under one fixed clock on both surfaces, an attested entry whose
/// `expires_at_unix_ms` equals the clock is expired, and one a millisecond
/// later is attested and valid.
#[tokio::test(flavor = "current_thread")]
#[serial(keyring)]
#[serial]
async fn approval_status_expiry_boundary_cli_mcp() {
    use stellar_agent_core::timefmt::{MockClock, test_clock};
    stellar_agent_test_support::keyring_mock::install().unwrap();
    let root = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(root.path());
    let profile = testnet_profile();
    const NOW: u64 = 1_900_000_000_000;
    let fixed: Arc<MockClock> = Arc::new(MockClock::new(|| Ok(NOW)));
    let _clock = test_clock::install(fixed.clone());
    let mut server = WalletServer::new(profile.clone()).unwrap();
    server.set_clock_for_test(fixed);
    let path = super::super::approval_store_dir()
        .unwrap()
        .join(format!("{NAME}.toml"));
    drop(PendingApprovalStore::open(path.clone()).unwrap());
    for (expires, state, reason) in [(NOW, "expired", "expired"), (NOW + 1, "attested", "ok")] {
        let mut entry = payment();
        entry.created_at_unix_ms = NOW - 60_000;
        entry.expires_at_unix_ms = expires;
        attest(&mut entry, &profile);
        write_entries(&path, std::slice::from_ref(&entry));
        let (rc, result) = surfaces(NAME, &server, &entry.approval_nonce).await;
        assert_eq!(rc, 0, "{result}");
        assert_eq!(
            (
                &result["data"]["state"],
                &result["data"]["verification"]["reason"]
            ),
            (&json!(state), &json!(reason)),
            "the expiry boundary is exclusive: expires_at {expires}, now {NOW}"
        );
    }
}

/// An unreadable clock refuses `approve status` with `wallet.clock_error`
/// before any store is read.
#[tokio::test(flavor = "current_thread")]
#[serial(keyring)]
#[serial]
async fn approval_status_cli_clock_failure() {
    use stellar_agent_core::timefmt::{MockClock, test_clock};
    use stellar_agent_core::wallet::WalletLifecycleError;
    stellar_agent_test_support::keyring_mock::install().unwrap();
    let root = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(root.path());
    testnet_profile();
    let nonce = payment().approval_nonce;
    let _clock = test_clock::install(Arc::new(MockClock::new(|| {
        Err(WalletLifecycleError::ClockError {
            detail: "system clock is before UNIX_EPOCH".to_owned(),
            source: None,
        })
    })));
    let before = crate::common::test_support::tree(root.path());
    let parsed = crate::Cli::try_parse_from([
        "stellar-agent",
        "approve",
        "status",
        &nonce,
        "--profile",
        NAME,
    ])
    .unwrap();
    let crate::Commands::Approve(args) = parsed.command else {
        panic!("approve command")
    };
    crate::common::render::take_rendered_for_test();
    let rc = super::super::dispatch(args).await;
    let cli = crate::common::render::take_rendered_for_test()
        .pop()
        .unwrap();
    assert_eq!(
        (rc, &cli["error"]["code"]),
        (1, &json!("wallet.clock_error")),
        "{cli}"
    );
    assert_eq!(
        crate::common::test_support::tree(root.path()),
        before,
        "a clock refusal reads and writes no store"
    );
}

#[tokio::test(flavor = "current_thread")]
#[serial(keyring)]
#[serial]
async fn approval_status_durable_cli_mcp_parity() {
    use stellar_agent_core::approval::{
        subject::SubjectKind,
        witness::{ApprovalExpectation, ApprovedKind, verify_approval, verify_intent_approval},
    };
    use stellar_agent_network::policy_state::{
        ApprovalRecorder, BusinessId, ConsentPayload, IntentSlot, OpenOutcome, OpenRequest,
        OperationAudit, OperationKind, OperationRecorder, OperationTool, PendingApprovalFacts,
    };
    struct Rows;
    impl OperationAudit for Rows {
        fn append(&mut self, _: stellar_agent_core::audit_log::AuditEntry) -> Result<(), String> {
            Ok(())
        }
    }
    for canonical in [false, true] {
        let fixture = MainnetConsentFixture::new(NAME);
        let (entry, intent) = if canonical {
            let (entry, intent) = fixture.intent_payment(600_000);
            (entry, Some(intent))
        } else {
            (fixture.payment(600_000), None)
        };
        let (mut inbox, blob) = match &intent {
            Some(intent) => fixture.intent_consent(&entry, intent),
            None => fixture.consent(&entry),
        };
        let blob: [u8; 32] = URL_SAFE_NO_PAD
            .decode(blob.unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let receipt = inbox
            .get(&entry.approval_nonce)
            .unwrap()
            .mainnet_presence
            .clone()
            .unwrap();
        let now = receipt.verified_at_unix_ms();
        let policy = fixture.current_policy();
        let witness = match &intent {
            Some(intent) => verify_intent_approval(
                &inbox,
                fixture.profile(),
                NAME,
                &entry.approval_nonce,
                &blob,
                intent,
                &fixture.decision(600_000),
                &policy,
                now,
            )
            .unwrap(),
            None => verify_approval(
                &inbox,
                fixture.profile(),
                NAME,
                &entry.approval_nonce,
                &blob,
                &ApprovalExpectation {
                    kind: ApprovedKind::Payment,
                    subject: approval_view_subject(&entry, &fixture.binding()).unwrap(),
                },
                &policy,
                now,
            )
            .unwrap(),
        };
        inbox
            .consume(
                &entry.approval_nonce,
                &"a".repeat(64),
                ConsumedOutcome::Confirmed,
            )
            .unwrap();
        drop(inbox);
        let mut server = WalletServer::new(fixture.profile().clone()).unwrap();
        server.set_policy_engine_for_test(Arc::new(stellar_agent_core::policy::NoopPolicyEngine));
        let (rc, consumed) = surfaces(NAME, &server, &entry.approval_nonce).await;
        assert_eq!(rc, 0);
        assert_eq!(consumed["data"]["state"], "consumed");
        assert_eq!(
            consumed["data"]["attested_at_ms"], now,
            "consumed inbox consent retains its verification time"
        );
        let mut inbox = PendingApprovalStore::open(fixture.store_path()).unwrap();
        let store = PersistedWindowStore::for_profile(NAME);
        let mut rows = Rows;
        let digest = intent
            .as_ref()
            .map_or([1; 32], |intent| *intent.digest().as_bytes());
        let OpenOutcome::New(operation) =
            OperationRecorder::new(&store, fixture.profile(), &mut rows, "status-fixture")
                .open(&OpenRequest {
                    business_id: BusinessId::parse("status-order").unwrap(),
                    tool: OperationTool::CliPay,
                    kind: OperationKind::Pay,
                    intent: IntentSlot::Canonical {
                        intent_digest: digest,
                        intent: json!({"op":"pay"}),
                    },
                    envelope_xdr: None,
                    prepared_decision: None,
                    rule_ttl_ms: Some(600_000),
                })
                .unwrap()
        else {
            panic!("new operation")
        };
        let mut recorder =
            ApprovalRecorder::new(&store, fixture.profile(), &mut rows, "status-fixture");
        let record = recorder
            .open_pending(
                operation.id(),
                &PendingApprovalFacts {
                    nonce: entry.approval_nonce.clone(),
                    kind: ApprovedKind::Payment,
                    subject_kind: if canonical {
                        SubjectKind::IntentDigest
                    } else {
                        SubjectKind::EnvelopeText
                    },
                    subject: witness.subject(),
                    intent_digest: digest,
                    created_at_ms: entry.created_at_unix_ms,
                    waiting_expires_at_ms: entry.expires_at_unix_ms,
                    rule_ttl_ms: 600_000,
                },
                stellar_agent_core::audit_log::PolicyDecision::RequireApproval,
            )
            .unwrap()
            .record;
        recorder
            .record_consent(
                record.id,
                &witness,
                &ConsentPayload {
                    attestation: blob,
                    receipt,
                    process_uid: entry.process_uid.clone(),
                    outbox_row: None,
                    challenge_subject: None,
                    row_provenance: Some(
                        stellar_agent_network::policy_state::RowProvenance::Written,
                    ),
                },
            )
            .unwrap();
        inbox.remove(&entry.approval_nonce).unwrap();
        drop(inbox);
        let mut server = WalletServer::new(fixture.profile().clone()).unwrap();
        server.set_policy_engine_for_test(Arc::new(stellar_agent_core::policy::NoopPolicyEngine));
        let before = crate::common::test_support::tree(fixture.home());
        let (rc, result) = surfaces(NAME, &server, &entry.approval_nonce).await;
        assert_eq!(rc, 0);
        assert_eq!(result["data"]["state"], "attested");
        assert_eq!(
            result["data"]["business_id"], "status-order",
            "business ID comes from the authenticated operation"
        );
        assert_eq!(
            result["data"]["binding"],
            if canonical {
                "canonical-intent"
            } else {
                "legacy-envelope"
            }
        );
        assert_eq!(
            result["data"]["verification"],
            json!({"supported":true,"valid":true,"reason":"ok"}),
            "retained durable proof verifies after inbox cleanup"
        );
        assert_eq!(result["data"]["attested_at_ms"], now);
        assert_eq!(crate::common::test_support::tree(fixture.home()), before);
        assert_eq!(
            surfaces(NAME, &server, &stellar_agent_core::hex::encode(&record.id))
                .await
                .1["error"]["code"],
            "approval.unknown",
            "durable ID is not a second public namespace"
        );
        recorder.revoke(record.id).unwrap();
        let (rc, result) = surfaces(NAME, &server, &entry.approval_nonce).await;
        assert_eq!(rc, 0);
        assert_eq!(result["data"]["state"], "revoked");
        assert_eq!(result["data"]["verification"]["reason"], "revoked");
    }
}
