use super::*;

async fn changed_consent_at_signing(subject_change: bool) {
    use stellar_xdr::WriteXdr as _;
    for auth in [false, true] {
        let mut fixture = crate::tools::message_signing_tests::Fixture::new();
        let reads = Arc::new(AtomicUsize::new(0));
        type Change = Box<dyn Fn() + Send + Sync>;
        let change = Arc::new(std::sync::Mutex::new(None::<Change>));
        let (count, action) = (reads.clone(), change.clone());
        let coord = &fixture.profile.mcp_signer_default;
        stellar_agent_test_support::keyring_mock::install_with_read_hooks(vec![
            stellar_agent_test_support::keyring_mock::ReadHook::new(
                &coord.service,
                &coord.account,
                Arc::new(move || {
                    if count.fetch_add(1, Ordering::SeqCst) == 1
                        && let Some(change) = action.lock().unwrap().as_ref()
                    {
                        change();
                    }
                }),
            ),
        ])
        .unwrap();
        fixture.seed_signer();
        fixture.seed_audit();
        let mock = MockServer::start().await;
        fixture.profile.rpc_url = mock.uri();
        let mut server = fixture.server();
        server.policy_engine = super::super::tests::make_require_approval_server().policy_engine;
        server.set_approval_dir_for_test(fixture.dir.path().join("approvals"));
        server.set_x402_identity_session_for_test("jwt".into(), fixture.account.clone(), vec![]);
        let queued = call(&server, auth, None).await;
        let nonce = value(&queued)["data"]["approval"]["approval_nonce"]
            .as_str()
            .unwrap()
            .to_owned();
        let proof = attest(&server, &nonce);
        let entry = server
            .x402_approval_store()
            .unwrap()
            .get(&nonce)
            .unwrap()
            .clone();
        let now = Arc::new(AtomicU64::new(entry.created_at_unix_ms));
        server.clock = Arc::new(Clock(now.clone()));
        let path = server
            .resolve_approval_dir()
            .unwrap()
            .join(format!("{}.toml", server.profile_name_for_approval()));
        if subject_change {
            let ApprovalKind::X402Payment {
                intent_digest,
                root_invocation_xdr,
                ..
            } = entry.kind
            else {
                panic!("x402 approval");
            };
            let mut terms: stellar_agent_x402::wire::PaymentRequirements =
                serde_json::from_str(&requirements()).unwrap();
            terms.amount = "20000000".into();
            let root = stellar_agent_x402::exact::payment_root(&terms, &fixture.account).unwrap();
            let replacement_root = root.to_xdr_base64(stellar_xdr::Limits::none()).unwrap();
            let replacement_digest =
                stellar_agent_x402::exact::intent_digest(&terms, &fixture.account).unwrap();
            *change.lock().unwrap() = Some(Box::new(move || {
                let text = std::fs::read_to_string(&path).unwrap();
                let changed = text
                    .replace(&root_invocation_xdr, &replacement_root)
                    .replace(
                        &stellar_agent_core::hex::encode(&intent_digest),
                        &stellar_agent_core::hex::encode(&replacement_digest),
                    );
                assert_ne!(
                    text, changed,
                    "the stored subject changes after preparation"
                );
                std::fs::write(&path, changed).unwrap();
            }));
        } else {
            let coord = server.profile.attestation_key_id.clone();
            *change.lock().unwrap() = Some(Box::new(move || {
                keyring_core::Entry::new(&coord.service, &coord.account)
                    .unwrap()
                    .set_password(&URL_SAFE_NO_PAD.encode([0x6b; 32]))
                    .unwrap();
            }));
        }
        let simulations = Arc::new(AtomicUsize::new(0));
        let public = stellar_strkey::ed25519::PublicKey::from_string(&fixture.account).unwrap();
        Mock::given(wiremock::matchers::method("POST"))
            .respond_with(Rpc {
                payer: stellar_xdr::ScAddress::Account(stellar_xdr::AccountId(
                    stellar_xdr::PublicKey::PublicKeyTypeEd25519(stellar_xdr::Uint256(public.0)),
                )),
                clock: now,
                health_expiry: Arc::new(AtomicU64::new(0)),
                simulations: simulations.clone(),
            })
            .mount(&mock)
            .await;
        reads.store(0, Ordering::SeqCst);
        let callbacks = pre_sign_checks_on_this_thread();
        let transmissions = transmit_gate_entries_on_this_thread();
        let result = call(&server, auth, Some(&proof)).await;
        assert_eq!(
            reads.load(Ordering::SeqCst),
            2,
            "the final payer read triggers the change"
        );
        assert_eq!(pre_sign_checks_on_this_thread() - callbacks, 1);
        assert_eq!(
            value(&result)["error"]["code"],
            "policy.approval_required",
            "the final guard refuses changed consent"
        );
        assert_eq!(transmit_gate_entries_on_this_thread() - transmissions, 0);
        assert_eq!(simulations.load(Ordering::SeqCst), 1);
        let store = server.x402_approval_store().unwrap();
        let entry = store.get(&nonce).unwrap();
        assert!(matches!(entry.kind, ApprovalKind::X402Payment { .. }));
        assert!(entry.attestation_blob_b64.is_some());
    }
}

#[tokio::test]
#[serial_test::serial(keyring)]
async fn final_guard_refuses_rotated_attestation_key() {
    changed_consent_at_signing(false).await;
}

#[tokio::test]
#[serial_test::serial(keyring)]
async fn final_guard_refuses_changed_stored_subject() {
    changed_consent_at_signing(true).await;
}

#[tokio::test]
#[serial_test::serial(keyring)]
async fn approval_clock_bounds_refuse_without_consumption() {
    use crate::tools::common::{
        ApprovalOutcome, DispatchOutcome, GatedApprovalKind, verify_attestation_subject_gate,
    };
    for auth in [false, true] {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let fixture = crate::tools::message_signing_tests::Fixture::new();
        fixture.seed_signer();
        fixture.seed_audit();
        let mut server = fixture.server();
        server.policy_engine = super::super::tests::make_require_approval_server().policy_engine;
        server.set_approval_dir_for_test(fixture.dir.path().join("approvals"));
        let queued = call(&server, auth, None).await;
        let nonce = value(&queued)["data"]["approval"]["approval_nonce"]
            .as_str()
            .unwrap()
            .to_owned();
        let proof = attest(&server, &nonce);
        let entry = server
            .x402_approval_store()
            .unwrap()
            .get(&nonce)
            .unwrap()
            .clone();
        let clock = Arc::new(AtomicU64::new(0));
        server.clock = Arc::new(Clock(clock.clone()));
        let outcome = DispatchOutcome::RequireApproval(ApprovalOutcome::from(
            stellar_agent_core::policy::ApprovalRequest::new("reason".into(), 120),
        ));
        for (now, passes) in [
            (entry.expires_at_unix_ms, false),
            (entry.created_at_unix_ms - 1, false),
            (entry.created_at_unix_ms, true),
            (entry.expires_at_unix_ms - 1, true),
        ] {
            clock.store(now, Ordering::SeqCst);
            let gate = verify_attestation_subject_gate(
                &server,
                &outcome,
                GatedApprovalKind::X402.expectation(proof.expected_subject),
                Some(&nonce),
                Some(&proof.attestation),
                "stellar_x402_create_payment",
            )
            .await;
            assert_eq!(
                gate.is_ok(),
                passes,
                "subject gate enforces the creation and expiry bounds"
            );
            if let Err(refusal) = gate {
                assert_eq!(value(&refusal)["error"]["code"], "policy.approval_required");
            }
            let guard = x402_pre_sign_guard(&server, &proof);
            assert_eq!(
                guard.is_ok(),
                passes,
                "final guard enforces the creation and expiry bounds"
            );
            match guard {
                Ok(store) => drop(store),
                Err(refusal) => {
                    assert_eq!(value(&refusal)["error"]["code"], "policy.approval_required");
                }
            }
            if !passes {
                let refusal = spend_x402_approval(&server, &nonce, 120_000, &[1; 32]).unwrap_err();
                assert_eq!(value(&refusal)["error"]["code"], "policy.approval_required");
            }
            let stored = server
                .x402_approval_store()
                .unwrap()
                .get(&nonce)
                .unwrap()
                .clone();
            assert_eq!(
                serde_json::to_value(stored).unwrap(),
                serde_json::to_value(&entry).unwrap()
            );
        }
        clock.store(entry.created_at_unix_ms, Ordering::SeqCst);
        spend_x402_approval(&server, &nonce, 120_000, &[1; 32]).unwrap();
    }
}

#[test]
fn child_helpers_are_explicitly_ignored() {
    let source = include_str!("x402_create_payment.rs");
    for signature in [
        "fn x402_spend_child()",
        "async fn x402_crash_child()",
        "async fn x402_private_directory_child()",
    ] {
        let before = source.split(signature).next().unwrap().trim_end();
        assert!(
            before.ends_with("#[ignore = \"child helper requires an isolated approval fixture\"]"),
            "{signature}: child helpers are ignored without their parent fixture"
        );
    }
}

#[test]
fn approval_public_text_names_the_contract() {
    for (source, sentence) in [
        (
            include_str!("../../../stellar-agent-network/src/keyring.rs"),
            "Called from `sign_bytes` with an accepting check and from `sign_soroban_address_auth_payload_checked`.",
        ),
        (
            include_str!("../../../stellar-agent-cli/src/commands/approve/list.rs"),
            "A consumed x402 payment approval names its value as the payment digest.",
        ),
        (
            include_str!("common.rs"),
            "and the DeFi tools refuse approval requirements.",
        ),
        (
            include_str!("x402_create_payment.rs"),
            "Wallet-issued approval nonce from the queueing call's `data.approval` block.",
        ),
        (
            include_str!("../../../stellar-agent-x402/src/exact.rs"),
            "An error returns at once, unchanged, and nothing is signed.",
        ),
        (
            include_str!("../../../../changelog.d/x402-owner-approval.added.md"),
            "`KeyringSignHandle::sign_soroban_address_auth_payload_checked` runs a caller check after the payer-key read, immediately before signing.",
        ),
    ] {
        assert!(source.contains(sentence), "public text states: {sentence}");
    }
    for (fragment, items) in [
        (
            include_str!("../../../../changelog.d/x402-owner-approval.added.md"),
            3,
        ),
        (
            include_str!("../../../../changelog.d/x402-owner-approval.changed.md"),
            4,
        ),
    ] {
        assert_eq!(
            fragment
                .lines()
                .filter(|line| line.starts_with("- "))
                .count(),
            items,
            "each release category retains its top-level items"
        );
        assert!(
            fragment
                .lines()
                .all(|line| line.starts_with("- ") || line.starts_with("  "))
        );
    }
}
