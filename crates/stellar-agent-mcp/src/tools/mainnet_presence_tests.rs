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
    assert_x402_refused_before_intent, authorizations, is_consumed, remote_approval, rule_index_of,
    stored_approval, wire, x402_args,
};
use super::common::{
    DispatchOutcome, GatedApprovalKind, approval_required_indistinguishable,
    verify_attestation_gate,
};
use super::x402_authenticated_mainnet_tests::{
    HOME, Run as AuthenticatedRun, authenticated_policy_with, signings,
};

/// The profile every fixture consents for.
const PROFILE: &str = "operator";

mod producers {
    use super::*;
    use stellar_agent_core::approval::witness::ApprovedKind;
    use stellar_agent_core::audit_log::PolicyDecision;
    use stellar_agent_network::operation_entry::{self, ClassicEntry};
    use stellar_agent_network::policy_state::approvals::UnreadableSiblingProfile;
    use stellar_agent_network::policy_state::store::commit_faults::{
        COMMIT_FAULT_AFTER_COUNTER, COMMIT_FAULT_AFTER_PREPARED, arm_accounting_fault,
        observe_commit,
    };
    use stellar_agent_network::policy_state::{
        ApprovalStatus, BusinessId, OperationHandle, OperationState, OperationStatus,
    };

    const TOOLS: [Tool; 3] = [Tool::CreateAccount, Tool::Trustline, Tool::Claim];

    /// A producer write of an unpublished kind that stores its entry in one
    /// step through `F`; the published route, which builds first, never runs it.
    pub(super) struct Persist<F>(pub(super) F);

    impl<F, E> super::super::business_entry::InboxWrite for Persist<F>
    where
        F: FnOnce() -> Result<PendingApproval, E>,
    {
        type Error = E;

        fn build(
            &self,
            _: Option<&stellar_agent_core::approval::ClassicIntent>,
        ) -> Result<PendingApproval, E> {
            panic!("an unpublished fixture write is never built alone")
        }

        fn insert(self, _: PendingApproval) -> Result<PendingApproval, E> {
            panic!("an unpublished fixture write is never inserted alone")
        }

        fn persist(
            self,
            _: Option<&stellar_agent_core::approval::ClassicIntent>,
        ) -> Result<PendingApproval, E> {
            (self.0)()
        }
    }

    #[tokio::test]
    #[serial_test::serial(keyring)]
    #[serial_test::serial]
    async fn x402_producers_open_facts_and_reuse_the_linked_entry() {
        use super::super::common::tests::mainnet::{ledger, require_approval_rules};
        use super::super::x402_authenticated_mainnet_tests::{authenticated_policy, call_muxed};
        for authenticated in [false, true] {
            for ttl in [300, 3600] {
                let run = AuthenticatedRun::build(|raw| {
                    require_approval_rules(
                        &authenticated_policy(&raw),
                        &[
                            "stellar_x402_create_payment",
                            "stellar_x402_authenticated_payment",
                        ],
                        ttl,
                    )
                })
                .await;
                let args = run.args(HOME, None);
                let business = BusinessId::parse(args.business_id.as_ref().unwrap()).unwrap();
                let mut first = run.args(HOME, None);
                first.business_id = args.business_id.clone();
                let result = call_muxed(&run, authenticated, first).await;
                assert_eq!(result["ok"], true, "{result}");
                let nonce = result["data"]["approval"]["approval_nonce"]
                    .as_str()
                    .unwrap();
                let entry = stored_approval(&run.f, nonce).unwrap();
                let status = ApprovalStatus::new(
                    &run.f.server.window_store,
                    run.f.server.security_profile(),
                );
                let record = status
                    .find_by_nonce(nonce)
                    .unwrap()
                    .expect("each x402 producer opens its record")
                    .record;
                let operation = OperationStatus::new(
                    &run.f.server.window_store,
                    run.f.server.security_profile(),
                )
                .view(&business)
                .unwrap()
                .unwrap();
                assert_eq!(record.kind, ApprovedKind::X402Payment);
                assert_eq!(
                    record.subject,
                    mainnet_consent_subject(&entry, &binding()).unwrap(),
                    "authenticated producer facts bind the home domain"
                );
                assert_eq!(record.subject_kind, entry.subject_kind);
                assert_eq!(record.intent_digest, operation.intent_digest);
                assert_eq!(record.operation_id, operation.operation_id);
                assert_eq!(
                    (record.created_at_ms, record.waiting_expires_at_ms),
                    (entry.created_at_unix_ms, entry.expires_at_unix_ms)
                );
                assert_eq!(record.rule_ttl_ms, u64::try_from(ttl).unwrap() * 1000);
                assert_eq!(
                    operation.waiting_expires_at_ms,
                    Some(entry.expires_at_unix_ms)
                );
                assert_eq!(operation.state, OperationState::AwaitingApproval);
                let state = ledger(&run.f).unwrap();
                assert_eq!(
                    state["operations"]["records"][0]["prepared_decision"],
                    "require_approval"
                );
                let before = std::fs::read(store_path(&run.f)).unwrap();
                let repeated = call_muxed(&run, authenticated, args).await;
                assert_eq!(repeated["ok"], true);
                assert_eq!(
                    repeated["data"], result["data"],
                    "x402 preparation returns the linked approval"
                );
                assert_eq!(std::fs::read(store_path(&run.f)).unwrap(), before);
                assert_eq!(ledger(&run.f).unwrap(), state);
            }
        }
    }

    #[tokio::test]
    #[serial_test::serial(keyring)]
    #[serial_test::serial]
    async fn x402_rerun_removes_orphans_and_recovers_open_failures() {
        use super::super::common::tests::mainnet::require_approval_rules;
        use super::super::x402_authenticated_mainnet_tests::{authenticated_policy, call_muxed};
        for authenticated in [false, true] {
            for fault in [COMMIT_FAULT_AFTER_PREPARED, COMMIT_FAULT_AFTER_COUNTER] {
                let run = AuthenticatedRun::build(|raw| {
                    require_approval_rules(
                        &authenticated_policy(&raw),
                        &[
                            "stellar_x402_create_payment",
                            "stellar_x402_authenticated_payment",
                        ],
                        300,
                    )
                })
                .await;
                let args = run.args(HOME, None);
                // Establish the operation, then leave only an unattested inbox orphan.
                let root = stellar_agent_x402::exact::payment_root(
                    &run.f.requirements(),
                    run.f.envelope.source(),
                )
                .unwrap();
                let digest = stellar_agent_x402::exact::intent_digest(
                    &run.f.requirements(),
                    run.f.envelope.source(),
                )
                .unwrap();
                let handle = run.f.server.x402_entry("stellar:mainnet", args.business_id.as_deref(), if authenticated { stellar_agent_network::policy_state::OperationTool::X402AuthenticatedPayment } else { stellar_agent_network::policy_state::OperationTool::X402CreatePayment }, if authenticated { stellar_agent_network::policy_state::OperationKind::X402AuthenticatedPayment } else { stellar_agent_network::policy_state::OperationKind::X402Payment }, digest, stellar_agent_network::policy_state::X402Intent {
                    network: run.f.requirements().network, asset: run.f.requirements().asset,
                    payer: run.f.envelope.source().to_owned(), pay_to: run.f.requirements().pay_to, amount: run.f.requirements().amount,
                }).unwrap().unwrap();
                use sha2::Digest as _;
                let orphan = PendingApproval::new_x402_pending(
                    &sha2::Sha256::digest(run.f.server.context.network_passphrase().as_bytes())
                        .into(),
                    &root,
                    authenticated.then(|| HOME.to_owned()),
                    stellar_agent_core::approval::process_uid_for_attestation().unwrap(),
                    300_000,
                )
                .unwrap();
                PendingApprovalStore::open(store_path(&run.f))
                    .unwrap()
                    .insert(orphan.clone(), now_ms())
                    .unwrap();
                let crash = arm_accounting_fault(fault);
                let mut first = run.args(HOME, None);
                first.business_id = args.business_id.clone();
                let failed = call_muxed(&run, authenticated, first).await;
                drop(crash);
                assert_eq!(
                    failed["error"]["code"], "submission.record_unavailable",
                    "durable x402 errors retain their code: {failed}"
                );
                assert!(
                    stored_approval(&run.f, &orphan.approval_nonce).is_none(),
                    "x402 orphans are removed by intent digest"
                );
                let status = ApprovalStatus::new(
                    &run.f.server.window_store,
                    run.f.server.security_profile(),
                );
                let committed = status.find_by_operation(handle.id()).unwrap();
                assert_eq!(committed.is_some(), fault == COMMIT_FAULT_AFTER_COUNTER);
                if let Some(view) = &committed {
                    assert!(
                        stored_approval(&run.f, &view.record.nonce).is_some(),
                        "a committed open retains its inbox entry"
                    );
                }
                let retry = call_muxed(&run, authenticated, args).await;
                assert_eq!(retry["ok"], true, "{retry}");
                let view = status.find_by_operation(handle.id()).unwrap().unwrap();
                assert_eq!(
                    retry["data"]["approval"]["approval_nonce"],
                    view.record.nonce
                );
                assert_eq!(
                    status
                        .find_by_nonce(&view.record.nonce)
                        .unwrap()
                        .unwrap()
                        .record
                        .id,
                    view.record.id,
                    "authenticated lookup converges on the same unique record"
                );
                assert_eq!(
                    PendingApprovalStore::open(store_path(&run.f))
                        .unwrap()
                        .snapshot(now_ms())
                        .len(),
                    1
                );
            }
        }
    }

    #[tokio::test]
    #[serial_test::serial(keyring)]
    #[serial_test::serial]
    async fn preinsert_inbox_failures_use_the_protocol_channel() {
        for tool in Tool::ALL {
            for directory_failure in [false, true] {
                let mut run = ClassicRun::new(tool).await;
                let (args, _) = fresh(&run);
                let scratch = tempfile::tempdir().unwrap();
                let invalid = scratch.path().join("invalid-approval-home");
                let _home = if directory_failure {
                    run.f.server.approval_dir_override = None;
                    Some(stellar_agent_test_support::env_guard::ScopedEnvVar::new(
                        "STELLAR_AGENT_HOME",
                        Some(invalid.as_os_str()),
                    ))
                } else {
                    std::fs::write(&invalid, b"not a directory").unwrap();
                    run.f.server.approval_dir_override = Some(invalid);
                    None
                };
                let result = tool.prepare_result(&run.f.server, &args).await;
                assert!(
                    result.is_err(),
                    "pre-insert failures use the protocol channel: {tool:?}, directory={directory_failure}"
                );
                let error = result.unwrap_err();
                assert!(
                    error.message.starts_with("approval.store_error:"),
                    "pre-insert failures keep approval.store_error: {error:?}"
                );
            }
        }
    }

    fn status(run: &ClassicRun) -> ApprovalStatus<'_> {
        ApprovalStatus::new(&run.f.server.window_store, run.f.server.security_profile())
    }

    pub(super) fn fresh(run: &ClassicRun) -> (serde_json::Value, OperationHandle) {
        let mut args = run.args.clone();
        args["business_id"] = serde_json::json!(run.bind_new_business_id());
        let id = BusinessId::parse(args["business_id"].as_str().unwrap()).unwrap();
        let digest =
            OperationStatus::new(&run.f.server.window_store, run.f.server.security_profile())
                .view(&id)
                .unwrap()
                .unwrap()
                .intent_digest;
        let ClassicEntry::Resume(handle) = run
            .f
            .server
            .operation_step(|recorder| operation_entry::lookup_classic(recorder, &id, &digest))
            .unwrap()
        else {
            panic!("a fresh operation is resumable")
        };
        (args, handle)
    }

    fn kind(tool: Tool) -> ApprovedKind {
        match tool {
            Tool::Pay | Tool::CreateAccount => ApprovedKind::Payment,
            Tool::Trustline => ApprovedKind::Trustline,
            Tool::Claim => ApprovedKind::Claim,
        }
    }

    #[tokio::test]
    #[serial_test::serial(keyring)]
    #[serial_test::serial]
    async fn mcp_simulate_opens_one_durable_record_per_tool() {
        use super::super::common::tests::mainnet::{ledger, require_approval_rules};
        for tool in TOOLS {
            for ttl in [300, 3600] {
                let run = ClassicRun::with(
                    tool,
                    |raw| {
                        require_approval_rules(
                            &raw,
                            &[tool.prepare_name(), tool.commit_name()],
                            ttl,
                        )
                    },
                    |_| {},
                    |_| {},
                )
                .await;
                let record = status(&run)
                    .find_by_nonce(&run.entry.approval_nonce)
                    .unwrap();
                assert!(
                    record.is_some(),
                    "each producer opens a durable record: {tool:?}"
                );
                let record = record.unwrap().record;
                assert_eq!(
                    record.kind,
                    kind(tool),
                    "the record keeps the approval kind"
                );
                assert_eq!(
                    record.subject,
                    mainnet_consent_subject(&run.entry, &binding()).unwrap()
                );
                assert_eq!(record.created_at_ms, run.entry.created_at_unix_ms);
                assert_eq!(record.waiting_expires_at_ms, run.entry.expires_at_unix_ms);
                assert_eq!(
                    record.rule_ttl_ms,
                    u64::try_from(ttl).unwrap() * 1000,
                    "the signed interval governs"
                );
                assert!(
                    record.consent.is_some(),
                    "fixture consent reaches the durable record"
                );
                let operation = OperationStatus::new(
                    &run.f.server.window_store,
                    run.f.server.security_profile(),
                )
                .view(&BusinessId::parse(run.args["business_id"].as_str().unwrap()).unwrap())
                .unwrap()
                .unwrap();
                assert_eq!(record.operation_id, operation.operation_id);
                assert_eq!(record.intent_digest, operation.intent_digest);
                assert_eq!(operation.state, OperationState::AwaitingApproval);
                let end =
                    operation_entry::envelope_max_time(run.args["envelope_xdr"].as_str().unwrap())
                        .unwrap()
                        * 1000;
                assert_eq!(
                    operation.waiting_expires_at_ms,
                    Some(end.min(record.waiting_expires_at_ms))
                );
                let window = ledger(&run.f).unwrap();
                let operations = window["operations"]["records"].as_array().unwrap();
                assert_eq!(operations.len(), 1);
                assert_eq!(
                    operations[0]["prepared_decision"], "require_approval",
                    "the prepare decision is retained"
                );
                assert_eq!(window["approvals"]["records"].as_array().unwrap().len(), 1);
            }
        }
    }

    #[tokio::test]
    #[serial_test::serial(keyring)]
    #[serial_test::serial]
    async fn retried_preparation_reuses_the_linked_entry() {
        for tool in TOOLS {
            let mut run = ClassicRun::new(tool).await;
            let original = run.prepared["approval"].clone();
            let before = std::fs::read(store_path(&run.f)).unwrap();
            for restart in [false, true] {
                if restart {
                    run.restart().unwrap();
                }
                let clock = stellar_agent_network::mainnet::clock::set_now_ms_for_test(
                    run.entry.created_at_unix_ms - 1,
                );
                let response = wire(&tool.prepare(&run.f.server, &run.args).await);
                drop(clock);
                assert_eq!(
                    response["ok"], true,
                    "a retry reuses its handle: {response}"
                );
                assert_eq!(
                    response["data"]["approval"], original,
                    "the linked approval block is reused"
                );
                assert_eq!(
                    std::fs::read(store_path(&run.f)).unwrap(),
                    before,
                    "reuse writes no inbox entry"
                );
            }
            PendingApprovalStore::open(store_path(&run.f))
                .unwrap()
                .remove(&run.entry.approval_nonce)
                .unwrap();
            let response = wire(&tool.prepare(&run.f.server, &run.args).await);
            assert_eq!(
                response["error"]["code"], "approval.not_found",
                "a missing linked entry is not replaced"
            );
            let clock = stellar_agent_network::mainnet::clock::set_now_ms_for_test(
                run.entry.expires_at_unix_ms + 86_400_000,
            );
            let expired = wire(&tool.prepare(&run.f.server, &run.args).await);
            assert_eq!(
                expired["data"]["operation"]["state"], "expired",
                "a far-later restart expires the operation"
            );
            clock.set(run.entry.created_at_unix_ms - 1);
            let rolled_back = wire(&tool.prepare(&run.f.server, &run.args).await);
            assert_eq!(
                rolled_back["data"]["operation"]["state"], "expired",
                "clock rollback cannot revive an expired operation"
            );
            drop(clock);
        }
    }

    #[tokio::test]
    #[serial_test::serial(keyring)]
    #[serial_test::serial]
    async fn rerun_removes_the_orphan_and_keeps_one_nonce() {
        for tool in TOOLS {
            let run = ClassicRun::new(tool).await;
            let (args, handle) = fresh(&run);
            let orphan = approval_for(tool, &run.f, handle.envelope_xdr().unwrap(), 300_000);
            let attested = approval_for(tool, &run.f, handle.envelope_xdr().unwrap(), 300_000);
            run.f.attest(&attested);
            let attested = stored_approval(&run.f, &attested.approval_nonce).unwrap();
            let other_envelope = {
                use stellar_xdr::{Limits, ReadXdr as _, TransactionEnvelope, WriteXdr as _};
                let TransactionEnvelope::Tx(mut envelope) = TransactionEnvelope::from_xdr_base64(
                    handle.envelope_xdr().unwrap(),
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
            let unrelated = approval_for(tool, &run.f, &other_envelope, 300_000);
            let mut inbox = PendingApprovalStore::open(store_path(&run.f)).unwrap();
            inbox.insert(orphan.clone(), now_ms()).unwrap();
            inbox.insert(unrelated.clone(), now_ms()).unwrap();
            assert!(
                status(&run)
                    .find_by_nonce(&attested.approval_nonce)
                    .unwrap()
                    .is_none()
            );
            assert!(
                status(&run)
                    .find_by_nonce(&unrelated.approval_nonce)
                    .unwrap()
                    .is_none()
            );
            assert!(attested.attestation_blob_b64.is_some());
            assert!(unrelated.attestation_blob_b64.is_none());
            drop(inbox);
            let response = wire(&tool.prepare(&run.f.server, &args).await);
            assert_eq!(response["ok"], true, "{response}");
            let nonce = response["data"]["approval"]["approval_nonce"]
                .as_str()
                .unwrap();
            let inbox = PendingApprovalStore::open(store_path(&run.f)).unwrap();
            assert!(
                inbox.get(&orphan.approval_nonce).is_none(),
                "a crashed insert is removed before replacement"
            );
            assert!(inbox.get(nonce).is_some());
            assert!(
                inbox.get(&run.entry.approval_nonce).is_some(),
                "the attested linked entry is retained"
            );
            assert!(
                inbox.get(&attested.approval_nonce).is_some(),
                "the attested orphan of the same envelope is retained"
            );
            assert!(
                inbox.get(&unrelated.approval_nonce).is_some(),
                "the unattested entry of another envelope is retained"
            );
            assert_eq!(
                inbox.snapshot(now_ms()).len(),
                4,
                "the linked entry, new winner and both protected entries remain"
            );
            assert_eq!(
                status(&run)
                    .find_by_operation(handle.id())
                    .unwrap()
                    .unwrap()
                    .record
                    .nonce,
                nonce
            );
        }
    }

    #[tokio::test]
    #[serial_test::serial(keyring)]
    #[serial_test::serial]
    async fn open_error_cleanup_follows_the_read_by_operation() {
        for tool in TOOLS {
            let mut run = ClassicRun::new(tool).await;
            for seam in [COMMIT_FAULT_AFTER_PREPARED, COMMIT_FAULT_AFTER_COUNTER] {
                let (args, handle) = fresh(&run);
                let path = store_path(&run.f);
                let observed = std::rc::Rc::new(std::cell::RefCell::new(None));
                let capture = observed.clone();
                let original = run.entry.approval_nonce.clone();
                let observer = observe_commit(move |_| {
                    let inbox = PendingApprovalStore::open(path.clone());
                    assert!(
                        inbox.is_ok(),
                        "producers hold no inbox lock across a window commit"
                    );
                    *capture.borrow_mut() = inbox
                        .unwrap()
                        .snapshot(now_ms())
                        .into_iter()
                        .find(|entry| entry.approval_nonce != original)
                        .map(|entry| entry.approval_nonce);
                });
                let armed = arm_accounting_fault(seam);
                let response = wire(&tool.prepare(&run.f.server, &args).await);
                drop(armed);
                drop(observer);
                assert_eq!(
                    response["error"]["code"], "submission.record_unavailable",
                    "open errors retain the store code"
                );
                let nonce = observed.borrow().clone().unwrap();
                let committed = seam == COMMIT_FAULT_AFTER_COUNTER;
                assert_eq!(
                    stored_approval(&run.f, &nonce).is_some(),
                    committed,
                    "cleanup follows the authenticated outcome"
                );
                assert_eq!(
                    status(&run)
                        .find_by_operation(handle.id())
                        .unwrap()
                        .is_some(),
                    committed
                );
                run.restart().unwrap();
                let retried = wire(&tool.prepare(&run.f.server, &args).await);
                assert_eq!(
                    retried["ok"], true,
                    "a restart resumes the preparation: {retried}"
                );
                if committed {
                    assert_eq!(
                        retried["data"]["approval"]["approval_nonce"], nonce,
                        "committed errors retain their nonce"
                    );
                }
                // Each fault case has a distinct operation; its completed entry
                // is removed so the next observer identifies its own insert.
                let retried_nonce = retried["data"]["approval"]["approval_nonce"]
                    .as_str()
                    .unwrap();
                PendingApprovalStore::open(store_path(&run.f))
                    .unwrap()
                    .remove(retried_nonce)
                    .unwrap();
            }
        }
    }

    #[tokio::test]
    #[serial_test::serial(keyring)]
    #[serial_test::serial]
    async fn concurrent_preparations_converge_on_the_winner() {
        const CHILD: &str = "MCP_PRODUCER_LOCK_PROBE";
        if let Some(path) = std::env::var_os(CHILD) {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)
                .unwrap();
            assert!(
                matches!(file.try_lock(), Err(std::fs::TryLockError::WouldBlock)),
                "the other process cannot cross the producer lock"
            );
            return;
        }
        let run = ClassicRun::new(Tool::Claim).await;
        let (args, handle) = fresh(&run);
        let path = store_path(&run.f).with_file_name("operator.producer.lock");
        let observer = observe_commit(move |_| {
            let child = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "tools::mainnet_presence_tests::producers::concurrent_preparations_converge_on_the_winner", "--nocapture"])
                .env(CHILD, &path).output().unwrap();
            assert!(
                child.status.success(),
                "an independent producer is excluded until open completes"
            );
        });
        let first = wire(&run.tool.prepare(&run.f.server, &args).await);
        drop(observer);
        let second = wire(&run.tool.prepare(&run.f.server, &args).await);
        assert_eq!(
            second["data"]["approval"], first["data"]["approval"],
            "the stale reader returns the winner"
        );
        assert_eq!(
            status(&run)
                .find_by_operation(handle.id())
                .unwrap()
                .unwrap()
                .record
                .nonce,
            first["data"]["approval"]["approval_nonce"]
                .as_str()
                .unwrap()
        );
    }

    #[tokio::test]
    #[serial_test::serial(keyring)]
    #[serial_test::serial]
    async fn producer_lock_exhaustion_keeps_its_code() {
        use stellar_agent_core::file_lock::HeldFileLock;
        for tool in TOOLS {
            let run = ClassicRun::new(tool).await;
            let (args, _) = fresh(&run);
            let path = store_path(&run.f).with_file_name("operator.producer.lock");
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)
                .unwrap();
            let held = HeldFileLock::try_lock(file).unwrap();
            let response = wire(&tool.prepare(&run.f.server, &args).await);
            assert_eq!(
                response["error"]["code"], "approval.writer_locked",
                "{tool:?}: exhausted producer retries retain the refusal code"
            );
            drop(held);
            let response = wire(&tool.prepare(&run.f.server, &args).await);
            assert_eq!(
                response["ok"], true,
                "{tool:?}: preparation resumes after lock release"
            );
        }
    }

    #[tokio::test]
    #[serial_test::serial(keyring)]
    #[serial_test::serial]
    async fn producer_preconditions_and_competing_open_keep_their_codes() {
        let run = ClassicRun::new(Tool::Claim).await;
        let server = &run.f.server;
        let result = server.classic_pending_approval(
            None,
            ApprovedKind::Claim,
            PolicyDecision::RequireApproval,
            Persist(|| panic!("missing handle must refuse before insertion")),
        );
        assert_eq!(
            result.unwrap_err().code(),
            "internal.unexpected_state",
            "mainnet requires an operation handle"
        );
        let (_, handle) = fresh(&run);
        let result = server.classic_pending_approval(
            Some(&handle),
            ApprovedKind::Claim,
            PolicyDecision::RequireApproval,
            Persist(|| Err("fixture insertion failure".to_owned())),
        );
        let super::super::common::ToolError::Protocol(error) = result.unwrap_err() else {
            panic!("insertion keeps its protocol channel")
        };
        assert_eq!(
            error.message,
            "approval.store_error: fixture insertion failure"
        );
        let winner = approval_for(Tool::Claim, &run.f, handle.envelope_xdr().unwrap(), 300_000);
        let loser = approval_for(Tool::Claim, &run.f, handle.envelope_xdr().unwrap(), 300_000);
        let result = server
            .classic_pending_approval(
                Some(&handle),
                ApprovedKind::Claim,
                PolicyDecision::RequireApproval,
                Persist(|| {
                    let mut inbox = PendingApprovalStore::open(store_path(&run.f)).unwrap();
                    inbox.insert(winner.clone(), now_ms()).unwrap();
                    inbox.insert(loser.clone(), now_ms()).unwrap();
                    drop(inbox);
                    let facts = operation_entry::pending_approval_facts(
                        &winner,
                        &handle,
                        ApprovedKind::Claim,
                        mainnet_consent_subject(&winner, &binding()).unwrap(),
                        300_000,
                    );
                    server
                        .approval_step(|recorder| {
                            recorder
                                .open_pending(handle.id(), &facts, PolicyDecision::RequireApproval)
                                .map_err(operation_entry::operation_refusal)
                        })
                        .unwrap();
                    Ok(loser.clone())
                }),
            )
            .unwrap();
        assert_eq!(
            result.approval_nonce, winner.approval_nonce,
            "an open conflict returns the concurrent winner"
        );
        assert!(
            stored_approval(&run.f, &loser.approval_nonce).is_none(),
            "the loser is removed only after the winner is read"
        );
        let (_, invalid_handle) = fresh(&run);
        let mut invalid = loser.clone();
        invalid.expires_at_unix_ms = invalid.created_at_unix_ms - 1;
        let error = server
            .classic_pending_approval(
                Some(&invalid_handle),
                ApprovedKind::Claim,
                PolicyDecision::RequireApproval,
                Persist(|| Ok(invalid)),
            )
            .unwrap_err();
        let result = wire(&error.into_result().unwrap());
        assert!(
            result["error"]["message"]
                .as_str()
                .unwrap()
                .contains("the signed approval interval ends before it starts"),
            "a backwards signed interval refuses before subtraction wraps"
        );

        let testnet = crate::server::WalletServer::new(
            stellar_agent_core::profile::Profile::builder_testnet_named(
                "producer-testnet",
                "producer-signer",
                "default",
                "producer-nonce",
                "default",
            )
            .with_noop_engine()
            .build(),
        )
        .unwrap();
        let before = stellar_agent_network::policy_state::approvals::facade_calls::count(
            testnet.window_store.path(),
        );
        let returned = testnet
            .classic_pending_approval(
                None,
                ApprovedKind::Claim,
                PolicyDecision::RequireApproval,
                Persist(|| Ok(loser.clone())),
            )
            .unwrap();
        assert_eq!(
            serde_json::to_value(returned).unwrap(),
            serde_json::to_value(loser).unwrap(),
            "testnet keeps the insertion's bytes"
        );
        assert_eq!(
            stellar_agent_network::policy_state::approvals::facade_calls::count(
                testnet.window_store.path()
            ),
            before,
            "testnet calls no approval facade"
        );
    }

    /// The evidence slots one scope holds.
    const MAX_SLOTS: usize = stellar_agent_core::audit_log::MAX_EVIDENCE_ENTRIES;

    /// Publishes `server`'s consents of `kind`: the scoped capability, an
    /// unreadable sibling profile unless the scope is `ready`, initialized
    /// evidence, and `foreign` reserved slots of other identities.
    fn publish_scope(
        server: &crate::server::WalletServer,
        kind: ApprovedKind,
        ready: bool,
        foreign: usize,
    ) -> (
        stellar_agent_network::policy_state::approvals::ConsentEvidenceEnforcementGuard,
        Option<UnreadableSiblingProfile>,
    ) {
        use stellar_agent_network::policy_state::approvals::ConsentEvidenceEnforcementGuard;
        let name = server.profile_name_for_approval();
        let profile = server.security_profile();
        crate::tools::value_audit::require_value_audit_writer(profile, &name, server.audit_binding)
            .unwrap()
            .lock()
            .unwrap()
            .initialize_consent_evidence()
            .unwrap();
        let (key, anchor) = stellar_agent_network::keyring::keyed_audit_access(
            profile,
            &name,
            server.audit_binding,
        )
        .unwrap()
        .into_parts();
        let ids: Vec<_> = (0..foreign)
            .map(|i| {
                let mut id = [0xee; 32];
                id[..8].copy_from_slice(&(i as u64).to_be_bytes());
                id
            })
            .collect();
        stellar_agent_core::audit_log::test_helpers::seed_reserved_evidence(
            &profile.audit_log_path,
            anchor.as_ref(),
            &key,
            &ids,
            u64::MAX,
        )
        .unwrap();
        (
            ConsentEvidenceEnforcementGuard::new(&name, kind),
            (!ready).then(UnreadableSiblingProfile::plant),
        )
    }

    /// Reacquires the slot of `view`'s record with its authenticated facts,
    /// as a retry does; at full capacity only the record's own exact slot
    /// succeeds.
    fn reacquire(
        server: &crate::server::WalletServer,
        view: &stellar_agent_network::policy_state::ApprovalView,
    ) -> Result<(), String> {
        let name = server.profile_name_for_approval();
        let profile = server.security_profile();
        let (key, anchor) = stellar_agent_network::keyring::keyed_audit_access(
            profile,
            &name,
            server.audit_binding,
        )
        .unwrap()
        .into_parts();
        operation_entry::ConsentAdmission::reacquire(
            &server.window_store,
            profile,
            view.record.operation_id,
            &view.record.facts(),
            &stellar_agent_core::audit_log::AuditOutbox::for_log_keyed(
                &profile.audit_log_path,
                anchor,
                key,
            ),
        )
        .map(drop)
        .map_err(|error| error.code().to_owned())
    }

    /// Every classic tool reserves its published request before the inbox
    /// entry and the approval block exist. An unproven scope refuses before
    /// the open, also when the scope is ready but the run's consented setup
    /// grant has no delivery facts; a full scope keeps the committed record.
    /// Each refusal stores nothing
    /// and keep their wire codes. A successful request holds its exact slot,
    /// so the next operation finds the scope full.
    #[tokio::test]
    #[serial_test::serial(keyring)]
    #[serial_test::serial]
    async fn mcp_classic_requests_reserve_before_exposure() {
        for tool in [Tool::CreateAccount, Tool::Pay, Tool::Trustline, Tool::Claim] {
            for mode in ["inventory", "legacy", "capacity", "reserved"] {
                let run = if mode == "legacy" {
                    ClassicRun::new(tool).await
                } else {
                    ClassicRun::unconsented(tool).await
                };
                let _published = publish_scope(
                    &run.f.server,
                    kind(tool),
                    mode != "inventory",
                    if mode == "capacity" {
                        MAX_SLOTS
                    } else {
                        MAX_SLOTS - 1
                    },
                );
                let (args, handle) = fresh(&run);
                let inbox = std::fs::read(store_path(&run.f)).unwrap();
                let response = wire(&tool.prepare(&run.f.server, &args).await);
                let record = status(&run).find_by_operation(handle.id()).unwrap();
                if mode == "reserved" {
                    assert_eq!(response["ok"], true, "{tool:?}: {response}");
                    let nonce = response["data"]["approval"]["approval_nonce"]
                        .as_str()
                        .unwrap();
                    let record = record.unwrap();
                    assert_eq!(record.record.nonce, nonce, "{tool:?}");
                    let entry = stored_approval(&run.f, nonce).unwrap();
                    if tool == Tool::Pay {
                        assert!(
                            matches!(
                                PendingApprovalStore::open(store_path(&run.f))
                                    .unwrap()
                                    .check_payment_recovery_at(nonce, entry.expires_at_unix_ms),
                                Err(stellar_agent_core::approval::ApprovalError::Expired)
                            ),
                            "the published payment keeps its recovery binding"
                        );
                    }
                    let (other, _) = fresh(&run);
                    let other_inbox = std::fs::read(store_path(&run.f)).unwrap();
                    let full = wire(&tool.prepare(&run.f.server, &other).await);
                    assert_eq!(
                        full["error"]["code"], "approval.evidence_capacity",
                        "{tool:?}: the published request holds its reservation"
                    );
                    assert_eq!(std::fs::read(store_path(&run.f)).unwrap(), other_inbox);
                    assert_eq!(
                        reacquire(&run.f.server, &record),
                        Ok(()),
                        "{tool:?}: the slot is the record's exact reservation"
                    );
                } else {
                    assert_eq!(
                        response["error"]["code"],
                        if mode == "capacity" {
                            "approval.evidence_capacity"
                        } else {
                            "audit.outbox_evidence_unusable"
                        },
                        "{tool:?} {mode}: the producer keeps the admission refusal: {response}"
                    );
                    if mode == "legacy" {
                        assert!(
                            response["error"]["message"]
                                .as_str()
                                .unwrap()
                                .contains("live grant without delivery facts"),
                            "{tool:?}: the setup grant alone leaves a ready scope unready: {response}"
                        );
                    }
                    assert!(
                        response["data"]["approval"].is_null(),
                        "{tool:?} {mode}: a refused admission exposes no approval block"
                    );
                    assert_eq!(
                        std::fs::read(store_path(&run.f)).unwrap(),
                        inbox,
                        "{tool:?} {mode}: a refused admission stores no inbox entry"
                    );
                    assert_eq!(
                        record.is_some(),
                        mode == "capacity",
                        "{tool:?} {mode}: only the open precedes the reservation"
                    );
                }
            }
        }
    }

    /// A published open keeps the prepared decision. A published retry
    /// reacquires the committed record's slot at capacity and answers with
    /// the same approval block. It refuses before exposure when the scope is
    /// unproven, answers `approval.not_found` for a missing linked entry, and
    /// answers `approval.revoked` for a revoked record. A conflicting open reserves and answers with the winner,
    /// never storing the loser. A 300-second payment request whose signed
    /// interval the operation deadline shortens reserves that interval.
    #[tokio::test]
    #[serial_test::serial(keyring)]
    #[serial_test::serial]
    async fn classic_retry_admission_uses_winner_facts() {
        use super::super::common::tests::mainnet::require_approval_rules;
        for tool in Tool::ALL {
            let run = ClassicRun::unconsented(tool).await;
            let _published = publish_scope(&run.f.server, kind(tool), true, MAX_SLOTS - 1);
            let (args, _) = fresh(&run);
            let first = wire(&tool.prepare(&run.f.server, &args).await);
            assert_eq!(first["ok"], true, "{tool:?}: {first}");
            let window = super::super::common::tests::mainnet::ledger(&run.f).unwrap();
            let opened = window["operations"]["records"]
                .as_array()
                .unwrap()
                .iter()
                .find(|record| record["business_id"] == args["business_id"])
                .unwrap();
            assert_eq!(
                opened["prepared_decision"], "require_approval",
                "{tool:?}: the published open keeps the prepared decision"
            );
            let retry = wire(&tool.prepare(&run.f.server, &args).await);
            assert_eq!(
                retry["data"]["approval"], first["data"]["approval"],
                "{tool:?}: a retry reacquires its own slot at capacity"
            );
            let nonce = first["data"]["approval"]["approval_nonce"]
                .as_str()
                .unwrap();
            let unready = UnreadableSiblingProfile::plant();
            let refused = wire(&tool.prepare(&run.f.server, &args).await);
            assert_eq!(
                refused["error"]["code"], "audit.outbox_evidence_unusable",
                "{tool:?}: a linked retry reacquires before it exposes the approval"
            );
            drop(unready);
            PendingApprovalStore::open(store_path(&run.f))
                .unwrap()
                .remove(nonce)
                .unwrap();
            let missing = wire(&tool.prepare(&run.f.server, &args).await);
            assert_eq!(
                missing["error"]["code"], "approval.not_found",
                "{tool:?}: a missing linked entry is not replaced"
            );
            if matches!(tool, Tool::Pay | Tool::Claim) {
                let id = status(&run)
                    .find_by_nonce(nonce)
                    .unwrap()
                    .unwrap()
                    .record
                    .id;
                run.f
                    .server
                    .approval_step(|recorder| {
                        recorder
                            .revoke(id)
                            .map_err(operation_entry::operation_refusal)
                    })
                    .unwrap();
                let revoked = wire(&tool.prepare(&run.f.server, &args).await);
                assert_eq!(
                    revoked["error"]["code"], "approval.revoked",
                    "{tool:?}: a published retry names the revoked record: {revoked}"
                );
            }
        }

        let run = ClassicRun::unconsented(Tool::Claim).await;
        let _published = publish_scope(&run.f.server, ApprovedKind::Claim, true, MAX_SLOTS - 1);
        let server = &run.f.server;
        let (_, handle) = fresh(&run);
        let winner = approval_for(Tool::Claim, &run.f, handle.envelope_xdr().unwrap(), 300_000);
        let loser = approval_for(Tool::Claim, &run.f, handle.envelope_xdr().unwrap(), 300_000);
        let name = server.profile_name_for_approval();
        let result = server
            .classic_pending_approval(
                Some(&handle),
                ApprovedKind::Claim,
                PolicyDecision::RequireApproval,
                super::super::business_entry::Staged {
                    build: |_: Option<&stellar_agent_core::approval::ClassicIntent>| {
                        PendingApprovalStore::open(store_path(&run.f))
                            .unwrap()
                            .insert(winner.clone(), now_ms())
                            .unwrap();
                        let facts = operation_entry::pending_approval_facts(
                            &winner,
                            &handle,
                            ApprovedKind::Claim,
                            mainnet_consent_subject(&winner, &binding()).unwrap(),
                            300_000,
                        );
                        server
                            .approval_step(|recorder| {
                                recorder
                                    .open_pending(
                                        handle.id(),
                                        &facts,
                                        PolicyDecision::RequireApproval,
                                    )
                                    .map_err(operation_entry::operation_refusal)
                            })
                            .unwrap();
                        Ok(loser.clone())
                    },
                    insert: |entry| server.insert_classic_pending(&name, entry),
                },
            )
            .map_err(|error| wire(&error.into_result().unwrap_or_else(|e| panic!("{e:?}"))));
        let Ok(result) = result else {
            panic!("a published conflict reserves the winner's facts: {result:?}")
        };
        assert_eq!(
            result.approval_nonce, winner.approval_nonce,
            "a published conflict answers with the winner"
        );
        assert!(
            stored_approval(&run.f, &loser.approval_nonce).is_none(),
            "the loser is never stored"
        );
        let view = status(&run)
            .find_by_operation(handle.id())
            .unwrap()
            .unwrap();
        assert_eq!(
            reacquire(server, &view),
            Ok(()),
            "the winner's exact slot holds the last free reservation"
        );

        let run = ClassicRun::build(
            Tool::Pay,
            Some(false),
            |raw| {
                require_approval_rules(
                    &raw,
                    &[Tool::Pay.prepare_name(), Tool::Pay.commit_name()],
                    300,
                )
            },
            |_| {},
            |_| {},
        )
        .await;
        let _published = publish_scope(&run.f.server, ApprovedKind::Payment, true, MAX_SLOTS - 1);
        let (args, handle) = fresh(&run);
        let response = wire(&Tool::Pay.prepare(&run.f.server, &args).await);
        assert_eq!(response["ok"], true, "{response}");
        let view = status(&run)
            .find_by_operation(handle.id())
            .unwrap()
            .unwrap();
        let entry = stored_approval(&run.f, &view.record.nonce).unwrap();
        let signed = entry.expires_at_unix_ms - entry.created_at_unix_ms;
        assert!(
            signed <= 120_000,
            "the deadline shortens the request: {signed}"
        );
        assert_eq!(
            view.record.rule_ttl_ms, signed,
            "the reserved record keeps the signed interval"
        );
        assert_eq!(
            reacquire(&run.f.server, &view),
            Ok(()),
            "the reservation's deadline is the signed record's"
        );
    }

    /// A record opened before its kind is published holds no reservation.
    /// Once the kind is enabled, a retry admits the record into a free slot
    /// and answers with the same approval block; at full capacity it refuses
    /// before exposure. Neither retry writes the inbox.
    #[tokio::test]
    #[serial_test::serial(keyring)]
    #[serial_test::serial]
    async fn a_record_opened_before_publication_admits_on_retry() {
        for tool in Tool::ALL {
            for full in [false, true] {
                let run = ClassicRun::unconsented(tool).await;
                let view = status(&run)
                    .find_by_nonce(&run.entry.approval_nonce)
                    .unwrap()
                    .expect("the unpublished preparation opens its record");
                let _published = publish_scope(
                    &run.f.server,
                    kind(tool),
                    true,
                    if full { MAX_SLOTS } else { MAX_SLOTS - 1 },
                );
                let inbox = std::fs::read(store_path(&run.f)).unwrap();
                let retry = wire(&tool.prepare(&run.f.server, &run.args).await);
                if full {
                    assert_eq!(
                        retry["error"]["code"], "approval.evidence_capacity",
                        "{tool:?}: an unreserved record refuses at full capacity: {retry}"
                    );
                    assert!(retry["data"]["approval"].is_null(), "{tool:?}");
                } else {
                    assert_eq!(
                        retry["data"]["approval"], run.prepared["approval"],
                        "{tool:?}: an unreserved record admits into a free slot: {retry}"
                    );
                    assert_eq!(
                        reacquire(&run.f.server, &view),
                        Ok(()),
                        "{tool:?}: the retry holds the record's exact slot"
                    );
                }
                assert_eq!(
                    std::fs::read(store_path(&run.f)).unwrap(),
                    inbox,
                    "{tool:?} full={full}: a retry writes no inbox entry"
                );
            }
        }
    }

    /// Both x402 tools reserve their published request before exposure. A
    /// full scope or an unproven scope refuses with its wire code and stores
    /// nothing. A reserved request keeps the home-domain subject, a dispatch
    /// under another home domain reserves another subject, and a retry at
    /// capacity answers with the same approval. The production capability
    /// stays closed. The D5 message
    /// path consumes the reserved record for its own operation.
    #[tokio::test]
    #[serial_test::serial(keyring)]
    #[serial_test::serial]
    async fn x402_requests_keep_scope_and_admission() {
        use super::super::common::tests::mainnet::require_approval_rules;
        use super::super::x402_authenticated_mainnet_tests::{authenticated_policy, call_muxed};
        use stellar_agent_network::policy_state::ApprovalState;
        for kind in [
            ApprovedKind::Payment,
            ApprovedKind::Claim,
            ApprovedKind::Trustline,
            ApprovedKind::X402Payment,
        ] {
            assert!(
                !stellar_agent_network::policy_state::approvals::consent_evidence_enforced(kind),
                "{kind:?}: the production capability stays closed"
            );
        }
        for authenticated in [true, false] {
            for mode in ["inventory", "capacity", "reserved"] {
                let run = AuthenticatedRun::build(|raw| {
                    require_approval_rules(
                        &authenticated_policy(&raw),
                        &[
                            "stellar_x402_create_payment",
                            "stellar_x402_authenticated_payment",
                        ],
                        300,
                    )
                })
                .await;
                let published = publish_scope(
                    &run.f.server,
                    ApprovedKind::X402Payment,
                    mode != "inventory",
                    match mode {
                        "capacity" => MAX_SLOTS,
                        // The other home domain's dispatch takes one more slot.
                        "reserved" if authenticated => MAX_SLOTS - 2,
                        _ => MAX_SLOTS - 1,
                    },
                );
                let args = run.args(HOME, None);
                let mut first = run.args(HOME, None);
                first.business_id = args.business_id.clone();
                let inbox = std::fs::read(store_path(&run.f)).unwrap_or_default();
                let result = call_muxed(&run, authenticated, first).await;
                if mode != "reserved" {
                    assert_eq!(
                        result["error"]["code"],
                        if mode == "capacity" {
                            "approval.evidence_capacity"
                        } else {
                            "audit.outbox_evidence_unusable"
                        },
                        "{authenticated} {mode}: the x402 producer keeps the admission refusal: {result}"
                    );
                    assert_eq!(
                        std::fs::read(store_path(&run.f)).unwrap_or_default(),
                        inbox,
                        "{authenticated} {mode}: a refused admission stores no inbox entry"
                    );
                    continue;
                }
                assert_eq!(result["ok"], true, "{authenticated}: {result}");
                let nonce = result["data"]["approval"]["approval_nonce"]
                    .as_str()
                    .unwrap()
                    .to_owned();
                let entry = stored_approval(&run.f, &nonce).unwrap();
                let status = ApprovalStatus::new(
                    &run.f.server.window_store,
                    run.f.server.security_profile(),
                );
                let view = status.find_by_nonce(&nonce).unwrap().unwrap();
                assert_eq!(
                    view.record.subject,
                    mainnet_consent_subject(&entry, &binding()).unwrap(),
                    "{authenticated}: the published record keeps the authenticated subject"
                );
                if authenticated {
                    // A second dispatch under another home domain takes the
                    // last free slot with its own subject.
                    let other = call_muxed(&run, true, run.args("other.example.com", None)).await;
                    assert_eq!(other["ok"], true, "{other}");
                    let other_nonce = other["data"]["approval"]["approval_nonce"]
                        .as_str()
                        .unwrap();
                    let other_entry = stored_approval(&run.f, other_nonce).unwrap();
                    let other_view = status.find_by_nonce(other_nonce).unwrap().unwrap();
                    assert_eq!(
                        other_view.record.subject,
                        mainnet_consent_subject(&other_entry, &binding()).unwrap(),
                        "the other home domain's record keeps its own subject"
                    );
                    assert_ne!(
                        other_view.record.subject, view.record.subject,
                        "another home domain names another subject"
                    );
                }
                assert_eq!(reacquire(&run.f.server, &view), Ok(()));
                let repeated = call_muxed(&run, authenticated, args).await;
                assert_eq!(
                    repeated["data"], result["data"],
                    "{authenticated}: a resumed request reacquires at capacity"
                );
                if !authenticated {
                    continue;
                }
                // The message mint names the reserved record's operation.
                drop(published);
                let attestation = run.f.attest(&entry);
                run.oracle_control
                    .latest_ledger_behind
                    .store(3, std::sync::atomic::Ordering::SeqCst);
                let paid = run.pay(HOME, &(nonce.clone(), attestation)).await;
                assert_eq!(paid["error"]["code"], "simulation.divergence", "{paid}");
                let after = status.find_by_nonce(&nonce).unwrap().unwrap().record;
                assert_eq!(
                    (after.state, after.operation_id),
                    (ApprovalState::Consumed, view.record.operation_id),
                    "the message mint consumes the reserved record of its operation"
                );
            }
        }
    }

    /// Tears both evidence slots of `server`'s audit log and returns their
    /// paths and original bytes; `None` names a slot that did not exist.
    fn tear_evidence(
        server: &crate::server::WalletServer,
    ) -> Vec<(std::path::PathBuf, Option<Vec<u8>>)> {
        [".evidence.0", ".evidence.1"]
            .into_iter()
            .map(|suffix| {
                let mut path = stellar_agent_core::audit_log::outbox_path(
                    &server.security_profile().audit_log_path,
                )
                .into_os_string();
                path.push(suffix);
                let path = std::path::PathBuf::from(path);
                let original = std::fs::read(&path).ok();
                std::fs::write(&path, b"torn evidence").unwrap();
                (path, original)
            })
            .collect()
    }

    /// The six MCP producers keep the precise wire code of an admission
    /// refusal: torn evidence gives `audit.outbox_evidence_unusable`, and a
    /// window commit that fails during the admitted open gives
    /// `submission.record_unavailable`. Neither exposes an approval block or
    /// stores an inbox entry. Torn evidence refuses after the open, so a
    /// classic repeat with the evidence restored answers `approval.not_found`.
    #[tokio::test]
    #[serial_test::serial(keyring)]
    #[serial_test::serial]
    async fn producer_adapters_preserve_refusal_codes() {
        use super::super::common::tests::mainnet::require_approval_rules;
        use super::super::x402_authenticated_mainnet_tests::{authenticated_policy, call_muxed};
        let expected = |mode: &str| match mode {
            "corrupt" => "audit.outbox_evidence_unusable",
            _ => "submission.record_unavailable",
        };
        for tool in Tool::ALL {
            for mode in ["corrupt", "store"] {
                let run = ClassicRun::unconsented(tool).await;
                let _published = publish_scope(&run.f.server, kind(tool), true, 0);
                let (args, handle) = fresh(&run);
                let torn = (mode == "corrupt").then(|| tear_evidence(&run.f.server));
                let inbox = std::fs::read(store_path(&run.f)).unwrap();
                let fault =
                    (mode == "store").then(|| arm_accounting_fault(COMMIT_FAULT_AFTER_PREPARED));
                let response = match tool.prepare_result(&run.f.server, &args).await {
                    Ok(result) => wire(&result),
                    Err(error) => serde_json::json!({ "protocol": error.message }),
                };
                drop(fault);
                assert_eq!(
                    response["error"]["code"],
                    expected(mode),
                    "{tool:?} {mode}: the adapter keeps the precise code: {response}"
                );
                assert!(response["data"]["approval"].is_null(), "{tool:?} {mode}");
                assert_eq!(
                    std::fs::read(store_path(&run.f)).unwrap(),
                    inbox,
                    "{tool:?} {mode}: a refused admission stores no inbox entry"
                );
                if mode == "store" {
                    assert!(
                        status(&run)
                            .find_by_operation(handle.id())
                            .unwrap()
                            .is_none(),
                        "{tool:?}: the failed open commits no record"
                    );
                }
                if let Some(torn) = torn {
                    // The refusal follows the open: the committed record has
                    // no inbox entry, which a repeat never replaces.
                    assert!(
                        status(&run)
                            .find_by_operation(handle.id())
                            .unwrap()
                            .is_some(),
                        "{tool:?}: torn evidence refuses after the open"
                    );
                    for (path, original) in torn {
                        match original {
                            Some(bytes) => std::fs::write(path, bytes).unwrap(),
                            None => std::fs::remove_file(path).unwrap(),
                        }
                    }
                    let repeated = wire(&tool.prepare(&run.f.server, &args).await);
                    assert_eq!(
                        repeated["error"]["code"], "approval.not_found",
                        "{tool:?}: a repeat after the restored evidence ends the business id: {repeated}"
                    );
                    assert_eq!(std::fs::read(store_path(&run.f)).unwrap(), inbox);
                }
            }
        }
        for authenticated in [true, false] {
            for mode in ["corrupt", "store"] {
                let run = AuthenticatedRun::build(|raw| {
                    require_approval_rules(
                        &authenticated_policy(&raw),
                        &[
                            "stellar_x402_create_payment",
                            "stellar_x402_authenticated_payment",
                        ],
                        300,
                    )
                })
                .await;
                let (_enabled, unready) =
                    publish_scope(&run.f.server, ApprovedKind::X402Payment, false, 0);
                let args = run.args(HOME, None);
                let mut first = run.args(HOME, None);
                first.business_id = args.business_id.clone();
                // The refused first call leaves the operation without a record.
                let refused = call_muxed(&run, authenticated, first).await;
                assert_eq!(refused["error"]["code"], "audit.outbox_evidence_unusable");
                drop(unready);
                if mode == "corrupt" {
                    tear_evidence(&run.f.server);
                }
                let inbox = std::fs::read(store_path(&run.f)).unwrap_or_default();
                let fault =
                    (mode == "store").then(|| arm_accounting_fault(COMMIT_FAULT_AFTER_PREPARED));
                let result = call_muxed(&run, authenticated, args).await;
                drop(fault);
                assert_eq!(
                    result["error"]["code"],
                    expected(mode),
                    "{authenticated} {mode}: the x402 adapter keeps the precise code: {result}"
                );
                assert!(result["data"]["approval"].is_null());
                assert_eq!(
                    std::fs::read(store_path(&run.f)).unwrap_or_default(),
                    inbox,
                    "{authenticated} {mode}: a refused admission stores no inbox entry"
                );
            }
        }
    }

    /// Off mainnet both x402 tools, dispatched with the x402 kind enabled,
    /// queue their approvals through the direct write and call no approval
    /// facade.
    #[tokio::test]
    #[serial_test::serial(keyring)]
    #[serial_test::serial]
    async fn x402_tools_off_mainnet_call_no_facade() {
        crate::tools::x402_create_payment::approval_tests::off_mainnet_published_case().await;
    }

    mod payment {
        use super::*;
        use stellar_agent_core::approval::ApprovalError;
        use stellar_agent_core::error::WalletError;

        type Produced = Result<Result<PendingApproval, ApprovalError>, WalletError>;

        /// Runs the payment producer for `handle` with `entry`'s interval as
        /// the call's captured interval.
        fn produce(
            run: &ClassicRun,
            handle: &OperationHandle,
            entry: &PendingApproval,
            persist: impl FnOnce() -> Result<PendingApproval, ApprovalError>,
        ) -> Produced {
            run.f.server.payment_pending_approval(
                Some(handle),
                PolicyDecision::RequireApproval,
                (entry.created_at_unix_ms, entry.expires_at_unix_ms),
                Persist(persist),
            )
        }

        /// Opens the durable record of `entry` for `handle`'s operation, with
        /// its signed facts changed by `edit`.
        fn open_record(
            run: &ClassicRun,
            handle: &OperationHandle,
            entry: &PendingApproval,
            edit: impl FnOnce(&mut stellar_agent_network::policy_state::approvals::PendingApprovalFacts),
        ) {
            let mut facts = operation_entry::pending_approval_facts(
                entry,
                handle,
                ApprovedKind::Payment,
                mainnet_consent_subject(entry, &binding()).unwrap(),
                entry.expires_at_unix_ms - entry.created_at_unix_ms,
            );
            edit(&mut facts);
            run.f
                .server
                .approval_step(|recorder| {
                    recorder
                        .open_pending(handle.id(), &facts, PolicyDecision::RequireApproval)
                        .map_err(operation_entry::operation_refusal)
                })
                .unwrap();
        }

        fn set_clocks(run: &mut ClassicRun, now: u64) {
            run.f.server.clock =
                std::sync::Arc::new(stellar_agent_core::timefmt::MockClock::new(move || Ok(now)));
        }

        #[tokio::test]
        #[serial_test::serial(keyring)]
        #[serial_test::serial]
        async fn payment_opens_one_record_with_its_signed_interval() {
            use super::super::super::common::tests::mainnet::{ledger, require_approval_rules};
            let run = ClassicRun::with(
                Tool::Pay,
                |raw| {
                    require_approval_rules(
                        &raw,
                        &[Tool::Pay.prepare_name(), Tool::Pay.commit_name()],
                        300,
                    )
                },
                |_| {},
                |_| {},
            )
            .await;
            let record = status(&run)
                .find_by_nonce(&run.entry.approval_nonce)
                .unwrap();
            assert!(
                record.is_some(),
                "the payment producer opens a durable record"
            );
            let record = record.unwrap().record;
            let signed = run.entry.expires_at_unix_ms - run.entry.created_at_unix_ms;
            assert!(
                signed <= 120_000,
                "the operation deadline shortens the 300-second request: {signed}"
            );
            assert_eq!(
                record.rule_ttl_ms, signed,
                "the signed interval is the record lifetime"
            );
            assert_eq!(record.kind, ApprovedKind::Payment);
            assert_eq!(
                record.subject,
                mainnet_consent_subject(&run.entry, &binding()).unwrap()
            );
            assert_eq!(
                (record.created_at_ms, record.waiting_expires_at_ms),
                (run.entry.created_at_unix_ms, run.entry.expires_at_unix_ms),
                "the record keeps the entry's original timestamps"
            );
            assert!(
                record.consent.is_some(),
                "fixture consent completes the record"
            );
            let window = ledger(&run.f).unwrap();
            let operations = window["operations"]["records"].as_array().unwrap();
            assert_eq!(operations.len(), 1);
            assert_eq!(operations[0]["state"], "awaiting_approval");
            assert_eq!(
                operations[0]["prepared_decision"], "require_approval",
                "the prepare decision is retained"
            );
            assert_eq!(window["approvals"]["records"].as_array().unwrap().len(), 1);
        }

        #[tokio::test]
        #[serial_test::serial(keyring)]
        #[serial_test::serial]
        async fn payment_retry_checks_the_linked_entry() {
            let mut run = ClassicRun::new(Tool::Pay).await;
            let original = run.prepared["approval"].clone();
            let inbox = std::fs::read(store_path(&run.f)).unwrap();
            let window = std::fs::read(run.f.server.window_store.path()).unwrap();
            for restart in [false, true] {
                if restart {
                    run.restart().unwrap();
                }
                let response = wire(&Tool::Pay.prepare(&run.f.server, &run.args).await);
                assert_eq!(
                    response["data"]["approval"], original,
                    "a retry returns the linked approval block: {response}"
                );
                assert_eq!(std::fs::read(store_path(&run.f)).unwrap(), inbox);
                assert_eq!(
                    std::fs::read(run.f.server.window_store.path()).unwrap(),
                    window,
                    "a linked retry writes no window state"
                );
            }
            let created = run.entry.created_at_unix_ms;
            let end = run.entry.expires_at_unix_ms;
            let policy_time =
                stellar_agent_core::policy::v1::criteria::state_store::set_query_time_for_test(
                    created - 1,
                );
            set_clocks(&mut run, created - 1);
            let early = wire(&Tool::Pay.prepare(&run.f.server, &run.args).await);
            assert_eq!(
                early["error"]["code"], "policy.approval_required",
                "a clock before the stored creation refuses: {early}"
            );
            for now in [end, created + 1] {
                policy_time.set(now);
                set_clocks(&mut run, now);
                let expired = wire(&Tool::Pay.prepare(&run.f.server, &run.args).await);
                assert_eq!(
                    expired["error"]["code"], "policy.approval_required",
                    "an observed expiry refuses at {now}: {expired}"
                );
            }
            drop(policy_time);
            assert!(
                matches!(
                    PendingApprovalStore::open(store_path(&run.f))
                        .unwrap()
                        .check_payment_recovery(&run.entry.approval_nonce),
                    Err(ApprovalError::Expired)
                ),
                "the linked check persists the observed expiry"
            );
            assert!(
                stored_approval(&run.f, &run.entry.approval_nonce).is_some(),
                "an expired entry is never replaced"
            );
            drop(run);

            // A handle retained while the record was live observes its expiry.
            let mut run = ClassicRun::with(
                Tool::Pay,
                |raw| {
                    super::super::super::common::tests::mainnet::require_approval_rules(
                        &raw,
                        &[Tool::Pay.prepare_name(), Tool::Pay.commit_name()],
                        60,
                    )
                },
                |_| {},
                |_| {},
            )
            .await;
            let id = BusinessId::parse(run.args["business_id"].as_str().unwrap()).unwrap();
            let digest =
                OperationStatus::new(&run.f.server.window_store, run.f.server.security_profile())
                    .view(&id)
                    .unwrap()
                    .unwrap()
                    .intent_digest;
            let ClassicEntry::Resume(handle) = run
                .f
                .server
                .operation_step(|recorder| operation_entry::lookup_classic(recorder, &id, &digest))
                .unwrap()
            else {
                panic!("a live operation resumes")
            };
            let record = status(&run)
                .find_by_nonce(&run.entry.approval_nonce)
                .unwrap()
                .unwrap()
                .record;
            // Just past the signed expiry the consent's execution window is
            // still open, so the signed lifetime alone decides.
            let consent = record.consent.as_ref().unwrap();
            let end = run.entry.expires_at_unix_ms + 1;
            assert!(end < consent.execution_expires_at_ms);
            let stored = std::fs::read_to_string(store_path(&run.f))
                .unwrap()
                .parse::<toml_edit::DocumentMut>()
                .unwrap();
            let retained = stored["payment_recovery"]
                .as_array_of_tables()
                .unwrap()
                .iter()
                .find(|b| b["nonce"].as_str() == Some(run.entry.approval_nonce.as_str()))
                .unwrap()["retain_until"]
                .as_integer()
                .unwrap();
            assert!(
                end < u64::try_from(retained).unwrap(),
                "the observation stays inside retained history"
            );
            let window_time = stellar_agent_network::mainnet::clock::set_now_ms_for_test(end);
            set_clocks(&mut run, end);
            // The commit runs before any other call settles the operation at
            // this time. It decides on the mainnet authorization clock: the
            // durable proof refuses with the uniform envelope and nothing is
            // sent.
            let committed = run.commit().await;
            assert_eq!(
                normalized(committed.clone()),
                normalized(wire(&approval_required_indistinguishable(PROFILE))),
                "an expired retry refuses at the approval gate: {committed}"
            );
            assert_eq!(
                run.control.count("sendTransaction"),
                0,
                "an expired record admits no send: {committed}"
            );
            assert!(
                matches!(
                    produce(&run, &handle, &run.entry, || panic!(
                        "a linked retry persists nothing"
                    )),
                    Ok(Err(ApprovalError::Expired))
                ),
                "an expired record refuses its retained handle"
            );
            let policy_time =
                stellar_agent_core::policy::v1::criteria::state_store::set_query_time_for_test(end);
            run.restart().unwrap();
            set_clocks(&mut run, end);
            assert!(
                matches!(
                    PendingApprovalStore::open(store_path(&run.f))
                        .unwrap()
                        .check_payment_recovery(&run.entry.approval_nonce),
                    Err(ApprovalError::Expired)
                ),
                "an observed record expiry survives restart"
            );
            // The operation's waiting time ended with the signed expiry, so a
            // later preparation answers the expired operation and returns no
            // approval.
            let prepared = wire(&Tool::Pay.prepare(&run.f.server, &run.args).await);
            assert!(
                prepared["data"]["approval"].is_null(),
                "an expired retry returns no approval: {prepared}"
            );
            assert_eq!(
                prepared["data"]["operation"]["state"], "expired",
                "{prepared}"
            );
            assert_eq!(run.control.count("sendTransaction"), 0);
            drop((policy_time, window_time));
        }

        #[tokio::test]
        #[serial_test::serial(keyring)]
        #[serial_test::serial]
        async fn payment_linked_entry_matches_its_operation() {
            use stellar_xdr::{Limits, ReadXdr as _, TransactionEnvelope, WriteXdr as _};
            let run = ClassicRun::new(Tool::Pay).await;
            let (args, handle) = fresh(&run);
            let TransactionEnvelope::Tx(mut envelope) = TransactionEnvelope::from_xdr_base64(
                handle.envelope_xdr().unwrap(),
                Limits::none(),
            )
            .unwrap() else {
                panic!("a classic envelope")
            };
            envelope.tx.seq_num.0 += 1;
            let other = TransactionEnvelope::Tx(envelope)
                .to_xdr_base64(Limits::none())
                .unwrap();
            let entry = approval_for(Tool::Pay, &run.f, &other, 60_000);
            PendingApprovalStore::open(store_path(&run.f))
                .unwrap()
                .insert(entry.clone(), now_ms())
                .unwrap();
            open_record(&run, &handle, &entry, |_| {});
            let result = wire(&Tool::Pay.prepare(&run.f.server, &args).await);
            assert_eq!(
                result["error"]["code"], "approval.entry_inconsistent",
                "an entry and record for another envelope refuse: {result}"
            );
        }

        /// An open that fails and whose following status read meets an
        /// unreadable image returns the open's error, keeps the pair byte for
        /// byte, reads no seed and sends nothing; once the image reads again,
        /// a retry recovers the same nonce.
        #[tokio::test]
        #[serial_test::serial(keyring)]
        #[serial_test::serial]
        async fn payment_open_error_with_an_unreadable_status_keeps_the_pair() {
            let mut run = ClassicRun::new(Tool::Pay).await;
            let known = run.entry.approval_nonce.clone();
            let (args, handle) = fresh(&run);
            let window = run.f.server.window_store.path().to_owned();
            let inbox = store_path(&run.f);
            let saved = std::rc::Rc::new(std::cell::RefCell::new(None));
            let capture = saved.clone();
            let (window_seam, inbox_seam) = (window.clone(), inbox.clone());
            let observer = observe_commit(move |point| {
                if point != COMMIT_FAULT_AFTER_PREPARED {
                    return;
                }
                let bytes = std::fs::read(&window_seam).unwrap();
                let mut unreadable = bytes.clone();
                unreadable[0] ^= 1;
                std::fs::write(&window_seam, unreadable).unwrap();
                *capture.borrow_mut() = Some((bytes, std::fs::read(&inbox_seam).unwrap()));
            });
            let seeds = run.seed_reads();
            let armed = arm_accounting_fault(COMMIT_FAULT_AFTER_PREPARED);
            let response = wire(&Tool::Pay.prepare(&run.f.server, &args).await);
            drop(armed);
            drop(observer);
            assert_eq!(
                response["error"]["code"], "submission.record_unavailable",
                "the open's own error returns: {response}"
            );
            let (image, pair) = saved.borrow_mut().take().unwrap();
            assert_eq!(
                std::fs::read(&inbox).unwrap(),
                pair,
                "the recovered pair keeps its bytes"
            );
            assert_eq!(run.seed_reads(), seeds, "no seed is read");
            assert_eq!(run.control.count("sendTransaction"), 0, "nothing is sent");
            let nonce = PendingApprovalStore::open(inbox.clone())
                .unwrap()
                .snapshot(now_ms())
                .into_iter()
                .find(|entry| entry.approval_nonce != known)
                .map(|entry| entry.approval_nonce)
                .unwrap();
            // The condition clears: the image reads again.
            std::fs::write(&window, image).unwrap();
            run.restart().unwrap();
            let retried = wire(&Tool::Pay.prepare(&run.f.server, &args).await);
            assert_eq!(
                retried["data"]["approval"]["approval_nonce"], nonce,
                "a retry recovers the same nonce: {retried}"
            );
            assert_eq!(
                status(&run)
                    .find_by_operation(handle.id())
                    .unwrap()
                    .unwrap()
                    .record
                    .nonce,
                nonce
            );
        }

        #[tokio::test]
        #[serial_test::serial(keyring)]
        #[serial_test::serial]
        async fn payment_retry_keeps_terminal_decisions() {
            for decision in ["rejected", "revoked"] {
                let mut run = ClassicRun::new(Tool::Pay).await;
                let nonce = run.entry.approval_nonce.clone();
                let now = now_ms();
                let expected = if decision == "rejected" {
                    PendingApprovalStore::open(store_path(&run.f))
                        .unwrap()
                        .reject(&nonce, now, 1)
                        .unwrap();
                    "policy.approval_rejected"
                } else {
                    let id = status(&run)
                        .find_by_nonce(&nonce)
                        .unwrap()
                        .unwrap()
                        .record
                        .id;
                    run.f
                        .server
                        .approval_step(|recorder| {
                            recorder
                                .revoke(id)
                                .map_err(operation_entry::operation_refusal)
                        })
                        .unwrap();
                    "approval.revoked"
                };
                for clock in [now, run.entry.created_at_unix_ms + 1] {
                    set_clocks(&mut run, clock);
                    let refused = wire(&Tool::Pay.prepare(&run.f.server, &run.args).await);
                    assert_eq!(
                        refused["error"]["code"], expected,
                        "{decision} survives an earlier clock: {refused}"
                    );
                }
                if decision == "rejected" {
                    PendingApprovalStore::open(store_path(&run.f))
                        .unwrap()
                        .gc_expired(now + 2)
                        .unwrap();
                    set_clocks(&mut run, now + 2);
                    let collected = wire(&Tool::Pay.prepare(&run.f.server, &run.args).await);
                    assert_eq!(
                        collected["error"]["code"], "approval.not_found",
                        "a collected linked payload is never recreated: {collected}"
                    );
                    assert!(
                        PendingApprovalStore::open(store_path(&run.f))
                            .unwrap()
                            .is_empty()
                    );
                }
            }
        }

        #[tokio::test]
        #[serial_test::serial(keyring)]
        #[serial_test::serial]
        async fn payment_open_errors_keep_the_recovered_pair() {
            let mut run = ClassicRun::new(Tool::Pay).await;
            let mut known = vec![run.entry.approval_nonce.clone()];
            for seam in [COMMIT_FAULT_AFTER_PREPARED, COMMIT_FAULT_AFTER_COUNTER] {
                let (args, handle) = fresh(&run);
                let path = store_path(&run.f);
                let observed = std::rc::Rc::new(std::cell::RefCell::new(None));
                let capture = observed.clone();
                let skip = known.clone();
                let observer = observe_commit(move |_| {
                    *capture.borrow_mut() = PendingApprovalStore::open(path.clone())
                        .unwrap()
                        .snapshot(now_ms())
                        .into_iter()
                        .find(|entry| !skip.contains(&entry.approval_nonce))
                        .map(|entry| entry.approval_nonce);
                });
                let armed = arm_accounting_fault(seam);
                let response = wire(&Tool::Pay.prepare(&run.f.server, &args).await);
                drop(armed);
                drop(observer);
                assert_eq!(
                    response["error"]["code"], "submission.record_unavailable",
                    "{response}"
                );
                let nonce = observed.borrow().clone().unwrap();
                known.push(nonce.clone());
                assert!(
                    stored_approval(&run.f, &nonce).is_some(),
                    "a recovered pair outlives an unresolved open"
                );
                assert_eq!(
                    status(&run)
                        .find_by_operation(handle.id())
                        .unwrap()
                        .is_some(),
                    seam == COMMIT_FAULT_AFTER_COUNTER
                );
                run.restart().unwrap();
                let retried = wire(&Tool::Pay.prepare(&run.f.server, &args).await);
                assert_eq!(
                    retried["data"]["approval"]["approval_nonce"], nonce,
                    "a retry recovers the same nonce: {retried}"
                );
                assert_eq!(
                    status(&run)
                        .find_by_operation(handle.id())
                        .unwrap()
                        .unwrap()
                        .record
                        .nonce,
                    nonce
                );
            }
            assert_eq!(
                PendingApprovalStore::open(store_path(&run.f))
                    .unwrap()
                    .len(),
                known.len(),
                "each operation keeps one entry"
            );
        }

        #[tokio::test]
        #[serial_test::serial(keyring)]
        #[serial_test::serial]
        async fn payment_adopts_no_unindexed_entry() {
            let run = ClassicRun::new(Tool::Pay).await;
            let (args, handle) = fresh(&run);
            let unindexed =
                approval_for(Tool::Pay, &run.f, handle.envelope_xdr().unwrap(), 300_000);
            PendingApprovalStore::open(store_path(&run.f))
                .unwrap()
                .insert(unindexed.clone(), now_ms())
                .unwrap();
            let response = wire(&Tool::Pay.prepare(&run.f.server, &args).await);
            assert_eq!(response["ok"], true, "{response}");
            assert_ne!(
                response["data"]["approval"]["approval_nonce"],
                unindexed.approval_nonce.as_str(),
                "an unindexed entry is never adopted"
            );
            let mut inbox = PendingApprovalStore::open(store_path(&run.f)).unwrap();
            assert!(
                inbox.get(&unindexed.approval_nonce).is_some(),
                "an unindexed entry keeps its lifecycle"
            );
            assert!(
                inbox
                    .reject(&unindexed.approval_nonce, now_ms(), 300)
                    .unwrap()
            );
        }

        #[tokio::test]
        #[serial_test::serial(keyring)]
        #[serial_test::serial]
        async fn payment_winners_pass_the_linked_check() {
            let run = ClassicRun::new(Tool::Pay).await;
            let pending = || {
                approval_for(
                    Tool::Pay,
                    &run.f,
                    run.args["envelope_xdr"].as_str().unwrap(),
                    300_000,
                )
            };
            let insert = |entry: &PendingApproval| {
                PendingApprovalStore::open(store_path(&run.f))
                    .unwrap()
                    .insert(entry.clone(), now_ms())
                    .unwrap();
            };

            let (_, handle) = fresh(&run);
            let (winner, loser) = (pending(), pending());
            let result = produce(&run, &handle, &winner, || {
                insert(&winner);
                insert(&loser);
                open_record(&run, &handle, &winner, |_| {});
                Ok(loser.clone())
            });
            assert_eq!(
                result.unwrap().unwrap().approval_nonce,
                winner.approval_nonce,
                "an open conflict returns the checked winner"
            );
            assert!(stored_approval(&run.f, &loser.approval_nonce).is_none());
            let raw = std::fs::read_to_string(store_path(&run.f)).unwrap();
            let mut file = raw.parse::<toml_edit::DocumentMut>().unwrap();
            let pending_entries = file["pending"].as_array_of_tables_mut().unwrap();
            let copy = pending_entries
                .iter()
                .find(|e| e["approval_nonce"].as_str() == Some(winner.approval_nonce.as_str()))
                .unwrap()
                .clone();
            pending_entries.push(copy);
            std::fs::write(store_path(&run.f), file.to_string()).unwrap();
            assert!(
                matches!(
                    produce(&run, &handle, &winner, || panic!(
                        "a linked retry persists nothing"
                    )),
                    Ok(Err(ApprovalError::RecoveryInconsistent))
                ),
                "a duplicated linked payload refuses"
            );
            std::fs::write(store_path(&run.f), raw).unwrap();

            for differs in ["clocks", "kind", "subject"] {
                let (_, handle) = fresh(&run);
                let (winner, loser) = (pending(), pending());
                let result = produce(&run, &handle, &winner, || {
                    insert(&winner);
                    insert(&loser);
                    open_record(&run, &handle, &winner, |facts| match differs {
                        "clocks" => {
                            facts.waiting_expires_at_ms -= 1;
                            facts.rule_ttl_ms -= 1;
                        }
                        "kind" => facts.kind = ApprovedKind::Claim,
                        _ => facts.subject[0] ^= 1,
                    });
                    Ok(loser.clone())
                });
                let Ok(Err(error)) = result else {
                    panic!("a winner whose {differs} differ from its record refuses: {result:?}")
                };
                assert!(matches!(error, ApprovalError::RecoveryInconsistent));
                let refusal =
                    super::super::super::common::payment_recovery_wire_error(&error, PROFILE)
                        .unwrap();
                assert_eq!(
                    wire(&refusal)["error"]["code"],
                    "approval.entry_inconsistent"
                );
            }

            let (_, handle) = fresh(&run);
            let (winner, loser) = (pending(), pending());
            let result = produce(&run, &handle, &winner, || {
                insert(&loser);
                open_record(&run, &handle, &winner, |_| {});
                Ok(loser.clone())
            });
            let Err(error) = result else {
                panic!("a removed winner refuses: {result:?}")
            };
            assert_eq!(error.code(), "approval.not_found");
            assert!(
                stored_approval(&run.f, &winner.approval_nonce).is_none(),
                "a missing winner is never recreated"
            );

            let (_, handle) = fresh(&run);
            let entry = pending();
            let path = store_path(&run.f);
            let nonce = entry.approval_nonce.clone();
            let observer = observe_commit(move |_| {
                PendingApprovalStore::open(path.clone())
                    .unwrap()
                    .reject(&nonce, now_ms(), 300_000)
                    .unwrap();
            });
            let result = produce(&run, &handle, &entry, || {
                insert(&entry);
                Ok(entry.clone())
            });
            drop(observer);
            assert!(
                matches!(result, Ok(Err(ApprovalError::Rejected))),
                "a rejection during the open refuses the opened entry: {result:?}"
            );
            let record = status(&run)
                .find_by_operation(handle.id())
                .unwrap()
                .unwrap();
            assert!(
                record.record.consent.is_none(),
                "rejection writes no consent"
            );
        }
    }
}

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

/// Stores `entry`, unless a producer already stored it, with the genuine
/// version 4 attestation of `approver`, as a process without the mainnet
/// witness records it, and returns the blob.
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
    if store.get(&entry.approval_nonce).is_none() {
        store.insert(entry.clone(), now_ms()).unwrap();
    }
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

/// The stable code the durable verifier refuses a proof over a forged
/// assertion with: the forged receipt is only in the inbox, so the presented
/// bytes do not authenticate the record's genuine consent.
const FORGED_PROOF_REFUSAL: &str = "approval.attestation_invalid";

/// A fresh operation of `run`'s prepared envelope and the durable record of
/// a new, unattested pay entry for it, opened through the classic producer,
/// which stores the entry. Returns the operation's business id and the entry.
fn recorded_fresh_entry(run: &ClassicRun) -> (serde_json::Value, PendingApproval) {
    let (args, handle) = producers::fresh(run);
    let xdr = run.args["envelope_xdr"].as_str().unwrap();
    let entry = approval_for(Tool::Pay, &run.f, xdr, 600_000);
    run.f
        .server
        .classic_pending_approval(
            Some(&handle),
            stellar_agent_core::approval::witness::ApprovedKind::Payment,
            stellar_agent_core::audit_log::PolicyDecision::RequireApproval,
            producers::Persist(|| {
                PendingApprovalStore::open(store_path(&run.f))
                    .unwrap()
                    .insert(entry.clone(), now_ms())
                    .unwrap();
                Ok(entry.clone())
            }),
        )
        .unwrap();
    (args["business_id"].clone(), entry)
}

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
    assert_classic_accepted_for(context, run, result, &run.entry.approval_nonce);
}

/// Asserts the accepted classic commit of the approval `approval_nonce`:
/// one submission, and that approval spent.
fn assert_classic_accepted_for(
    context: &str,
    run: &ClassicRun,
    result: &serde_json::Value,
    approval_nonce: &str,
) {
    assert_eq!(result["ok"], true, "{context}: {result}");
    assert_eq!(run.control.count("sendTransaction"), 1, "{context}");
    assert!(
        is_consumed(&stored_approval(&run.f, approval_nonce).unwrap()),
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
        source: stellar_agent_core::approval::OperatorCredentialSource::Enrolled,
    })
    .unwrap();
}

/// A genuine version 4 HMAC of the local operator, and of a remote approver
/// whose credential is allowed and enrolled, authorizes no mainnet commit;
/// the presence-backed consent of the same run commits.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
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
        // The producer records the approval for its own operation; the
        // version 4 HMAC leaves that record without consent.
        let business_id = run.bind_new_business_id();
        let entry = approval_for(Tool::Pay, &run.f, &xdr, 600_000);
        run.record_pending(&business_id, &entry);
        let blob = record_v4(&run.f, &entry, &approver);
        let mut args = run.commit_args_for(&xdr, &entry.approval_nonce, &blob);
        args["business_id"] = serde_json::json!(business_id);
        let result = run.commit_with(args).await;
        assert_uniform(&context, &result);
        diagnostics.assert_refused_with(&context, "approval.presence_required");
        assert_classic_unsigned(&context, &run, &entry);
    }
    let result = run.commit().await;
    assert_classic_accepted("the presence-backed consent", &run, &result);
}

/// A mainnet preparation asks the primary which network it serves, then
/// for its health and the close time of its latest ledger, and reads the
/// account the envelope is built against only after both checks; the
/// preparation reports what the readiness check observed.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn mainnet_prepare_checks_readiness_before_the_account_read() {
    for tool in Tool::ALL {
        let run = ClassicRun::new(tool).await;
        let methods = run.control.methods();
        assert!(methods.len() > 3, "{tool:?}: {methods:?}");
        assert_eq!(
            methods[..4],
            ["getNetwork", "getHealth", "getLedgers", "getLedgerEntries"],
            "{tool:?}: identity, then readiness, then the account read: {methods:?}"
        );
    }
}

/// Each commit kind refuses a proof computed over a forged assertion, which
/// does not authenticate the record's consent, with the uniform envelope and
/// before any signing, and
/// proceeds with the genuine assertion of the pinned credential: the four
/// classic commits, the plain x402 payment and the authenticated x402
/// payment.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
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
            diagnostics.assert_refused_with(&context, FORGED_PROOF_REFUSAL);
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
        diagnostics.assert_refused_with(&context, FORGED_PROOF_REFUSAL);
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
        diagnostics.assert_refused_with(&context, FORGED_PROOF_REFUSAL);
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

/// A signed listener can persist only under the policy it issued under.
/// A re-sign keeps the record unauthorized at the MCP commit boundary.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn signed_origin_resign_between_issuance_and_persistence_refuses() {
    use stellar_agent_core::approval::{
        ConsentAudit, ConsentAuthorization, ListenerIdentity, MainnetApprovalAuthority,
        PresenceListener, Surface, attest_and_persist, issue_mainnet_intent_presence,
        mainnet_fixtures::{MainnetConsentFixture, SIGNED_CERT_SPKI_SHA256, SIGNED_ORIGIN},
        verify_mainnet_presence,
    };
    for change in ["control", "same pin", "changed pin"] {
        let mut run = ClassicRun::new(Tool::Pay).await;
        let signed = run.f.raw.replace("sequence = 7", "sequence = 8").replace(
            "[mainnet]",
            &format!("[mainnet]\napproval_origin = \"{SIGNED_ORIGIN}\"\napproval_cert_spki_sha256 = \"{}\"", stellar_agent_core::hex::encode(&SIGNED_CERT_SPKI_SHA256)),
        );
        Fixture::write_policy(&signed);
        run.restart().unwrap();
        let policy = MainnetApprovalAuthority::for_profile(PROFILE)
            .unwrap()
            .load_current()
            .unwrap()
            .into_policy();
        let identity = ListenerIdentity::capture(&policy).unwrap();
        let xdr = run.args["envelope_xdr"].as_str().unwrap().to_owned();
        // The ceremony's entry has its own operation and durable record.
        let (business_id, entry) = recorded_fresh_entry(&run);
        let pending = issue_mainnet_intent_presence(
            &entry,
            &binding(),
            &policy,
            PresenceListener::SignedOrigin(&identity),
            None,
            now_ms(),
            std::time::Instant::now(),
        )
        .unwrap();
        let assertion = MainnetConsentFixture::sign_issued(&fixture_authenticator(), &pending);
        let presence = verify_mainnet_presence(
            pending,
            MainnetConsentFixture::input(&assertion),
            now_ms(),
            std::time::Instant::now(),
        )
        .unwrap();
        if change != "control" {
            let newer = signed.replace("sequence = 8", "sequence = 9");
            Fixture::write_policy(&if change == "changed pin" {
                newer.replace(
                    &stellar_agent_core::hex::encode(&SIGNED_CERT_SPKI_SHA256),
                    &"cd".repeat(32),
                )
            } else {
                newer
            });
        }
        let mut store = PendingApprovalStore::open(store_path(&run.f)).unwrap();
        let before = std::fs::read(store_path(&run.f)).unwrap();
        let audit = stellar_agent_network::mainnet::audit_readiness::audit_readiness(
            run.f.server.security_profile(),
            PROFILE,
        )
        .unwrap();
        let result = attest_and_persist(
            &mut store,
            &entry,
            &attestation_key(&run.f),
            &binding(),
            Surface::ServeRemote,
            ConsentAudit::Writer(&mut audit.writer().lock().unwrap()),
            ConsentAuthorization::Mainnet {
                presence,
                policy: &policy,
            },
            |_, _| panic!("no grant"),
        );
        if change != "control" {
            let recorded = store.get(&entry.approval_nonce).unwrap();
            assert!(
                recorded.attestation_blob_b64.is_none(),
                "{change}: no persisted authority"
            );
            assert!(recorded.mainnet_presence.is_none(), "{change}: no receipt");
            assert_eq!(
                std::fs::read(store_path(&run.f)).unwrap(),
                before,
                "{change}"
            );
            assert_eq!(
                result.unwrap_err().code(),
                "approval.listener_policy_stale",
                "{change}"
            );
        } else {
            result.unwrap();
            assert_eq!(
                store
                    .get(&entry.approval_nonce)
                    .unwrap()
                    .attestation_version,
                5
            );
        }
        let blob = store
            .get(&entry.approval_nonce)
            .unwrap()
            .attestation_blob_b64
            .clone()
            .unwrap_or_else(|| URL_SAFE_NO_PAD.encode([0; 32]));
        drop(store);
        if change == "control" {
            run.f.complete_consent(&entry.approval_nonce);
        }
        let rows =
            std::fs::read_to_string(&run.f.server.security_profile().audit_log_path).unwrap();
        let consents = rows
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .filter(|row| row["kind"] == "approval_attested" && row["origin"] == "serve-remote")
            .count();
        assert_eq!(
            consents,
            usize::from(change == "control"),
            "{change}: consent audit"
        );
        if change != "control" {
            run.restart().unwrap();
        }
        let diagnostics = Diagnostics::install();
        let mut args = run.commit_args_for(&xdr, &entry.approval_nonce, &blob);
        args["business_id"] = business_id;
        let result = run.commit_with(args).await;
        if change == "control" {
            assert_classic_accepted_for(change, &run, &result, &entry.approval_nonce);
        } else {
            assert_uniform(change, &result);
            diagnostics.assert_refused_with(change, "approval.presence_required");
            assert_classic_unsigned(change, &run, &entry);
        }
    }
}

/// A consent recorded before a policy change authorizes nothing after it:
/// the running server answers every change with its restart refusal and its
/// gate with the uniform refusal; a server started on a policy re-signed at
/// a higher sequence, with the credential revoked or kept, refuses the
/// consent uniformly; an unsigned edit and an absent pin stop the start
/// itself. A changed envelope refuses uniformly. No refused row signs. An
/// inbox entry with an altered stored expiry, bound to its recovery link or
/// not, leaves the durable record's proof admitted, and the commit sends once.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
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
                    run.f.server.window_store.path(),
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
    // The changed envelope commits under an id whose record binds it, so the
    // commit passes the envelope binding and meets the attestation check.
    let mut args = run.commit_args_for(
        &changed,
        &run.entry.approval_nonce,
        run.args["approval_attestation"].as_str().unwrap(),
    );
    args["business_id"] = serde_json::json!(run.bind_business_id_for(&changed));
    let result = run.commit_with(args).await;
    assert_uniform("changed envelope", &result);
    diagnostics.assert_refused_with("changed envelope", "approval.attestation_invalid");
    assert_classic_unsigned("changed envelope", &run, &run.entry);

    // The approval inbox grants no mainnet authority: an inbox entry whose
    // expiry contradicts its recovery link, or that lost its recovery
    // binding, leaves the durable record's proof admitted.
    for case in ["altered expiry", "unbound altered expiry"] {
        let run = ClassicRun::new(Tool::Pay).await;
        edit_stored(&run.f, &run.entry.approval_nonce, |entry| {
            let expires = entry["expires_at_unix_ms"].as_integer().unwrap();
            entry["expires_at_unix_ms"] = toml_edit::value(expires - 1_000);
        });
        if case == "unbound altered expiry" {
            let path = store_path(&run.f);
            let mut document: toml_edit::DocumentMut =
                std::fs::read_to_string(&path).unwrap().parse().unwrap();
            assert!(document.remove("payment_recovery").is_some());
            std::fs::write(&path, document.to_string()).unwrap();
        }
        let result = run.commit().await;
        assert_eq!(result["ok"], true, "{case}: {result}");
        assert_eq!(run.control.count("sendTransaction"), 1, "{case}");
        assert_eq!(authorizations(&run.f).len(), 1, "{case}");
    }
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
/// credential, and a forged proof beside a malformed inbox receipt. A
/// rejected and a consumed approval keep their own codes.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
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
    diagnostics.assert_refused_with("missing record", "approval.not_found");
    let legacy_business_id = run.bind_new_business_id();
    let legacy = approval_for(Tool::Pay, &run.f, &xdr, 600_000);
    run.record_pending(&legacy_business_id, &legacy);
    let blob = record_v4(&run.f, &legacy, &AttestedApprover::Local);
    let mut legacy_args = run.commit_args_for(&xdr, &legacy.approval_nonce, &blob);
    legacy_args["business_id"] = serde_json::json!(legacy_business_id);
    refusals.push((
        "version 4".to_owned(),
        refused_commit(&run, legacy_args).await,
    ));
    diagnostics.assert_refused_with("version 4", "approval.presence_required");
    for forged in FORGED {
        let (mut args, entry) = run.prepare_again().await;
        args["approval_attestation"] =
            serde_json::json!(forge(&run.f, &entry.approval_nonce, forged));
        refusals.push((format!("{forged:?}"), refused_commit(&run, args).await));
        diagnostics.assert_refused_with(&format!("{forged:?}"), FORGED_PROOF_REFUSAL);
    }

    // A malformed receipt leaves the whole inbox unreadable. A proof that
    // does not authenticate the record's consent still refuses uniformly:
    // the unreadable inbox replaces no refusal. The inbox is restored
    // afterwards for the remaining rows.
    let (mut args, malformed) = run.prepare_again().await;
    args["approval_attestation"] = serde_json::json!("A".repeat(43));
    let intact = std::fs::read(store_path(&run.f)).unwrap();
    edit_stored(&run.f, &malformed.approval_nonce, |entry| {
        entry["mainnet_presence"]["random_b64url"] = toml_edit::value("AAAA");
    });
    refusals.push((
        "malformed receipt".to_owned(),
        refused_commit(&run, args).await,
    ));
    diagnostics.assert_refused_with("malformed receipt", "approval.attestation_invalid");
    std::fs::write(store_path(&run.f), intact).unwrap();

    let result = run.commit().await;
    assert_classic_accepted("the genuine consent", &run, &result);
    // A commit under another business id that binds the same envelope
    // reaches the approval gate, which refuses the consumed approval.
    let mut consumed = run.commit_args_for(&xdr, &run.entry.approval_nonce, &genuine);
    consumed["business_id"] = serde_json::json!(run.bind_new_business_id());
    let result = refused_commit(&run, consumed).await;
    assert_eq!(
        result["error"]["code"], "policy.approval_consumed",
        "{result}"
    );

    let uniform = normalized(wire(&approval_required_indistinguishable(PROFILE)));
    for (context, result) in &refusals {
        assert_eq!(normalized(result.clone()), uniform, "{context}: {result}");
    }
}

/// The policy `raw` with every rule of `tools` requiring approval for 600
/// seconds under the reason `operator review`.
fn require_approval_for(raw: &str, tools: &[&str]) -> String {
    let mut doc = raw.parse::<toml_edit::DocumentMut>().unwrap();
    for rule in doc["rules"].as_array_of_tables_mut().unwrap().iter_mut() {
        if rule["match"]["tool"]
            .as_str()
            .is_some_and(|tool| tools.contains(&tool))
        {
            require_approval_rule(rule);
        }
    }
    doc.to_string()
}

/// Makes `rule` require approval for 600 seconds under the reason
/// `operator review`.
fn require_approval_rule(rule: &mut toml_edit::Table) {
    rule["decision"] = toml_edit::value("require_approval");
    rule["ttl_secs"] = toml_edit::value(600);
    rule["reason"] = toml_edit::value("operator review");
}

/// The preparation and commit names of `tool`.
fn classic_names(tool: Tool) -> [&'static str; 2] {
    match tool {
        Tool::Pay => ["stellar_pay", "stellar_pay_commit"],
        Tool::Claim => ["stellar_claim", "stellar_claim_commit"],
        Tool::CreateAccount => ["stellar_create_account", "stellar_create_account_commit"],
        Tool::Trustline => ["stellar_trustline", "stellar_trustline_commit"],
    }
}

/// The keys whose values change from call to call: nonces, envelopes,
/// instants, business ids and request ids.
const VOLATILE_KEYS: [&str; 7] = [
    "approval_nonce",
    "business_id",
    "close_time_unix",
    "envelope_xdr",
    "expires_at_unix_ms",
    "nonce",
    "request_id",
];

/// The original text of `result` after its error flag, with only the
/// volatile spans replaced.
///
/// Each `"<key>": <value>` span of a [`VOLATILE_KEYS`] key becomes
/// `"<key>": "<volatile>"`, and each other occurrence of such a string value
/// becomes `<volatile>`. Every other byte stays as the server wrote it, so a
/// change of whitespace, key order or escaping changes the result.
fn masked(result: &rmcp::model::CallToolResult) -> String {
    fn collect(value: &serde_json::Value, spans: &mut Vec<(String, String)>) {
        match value {
            serde_json::Value::Object(map) => {
                for (key, item) in map {
                    if VOLATILE_KEYS.contains(&key.as_str()) {
                        spans.push((key.clone(), serde_json::to_string(item).unwrap()));
                    } else {
                        collect(item, spans);
                    }
                }
            }
            serde_json::Value::Array(items) => items.iter().for_each(|item| collect(item, spans)),
            _ => {}
        }
    }
    let text = &result.content[0].as_text().unwrap().text;
    let mut spans = Vec::new();
    collect(&wire(result), &mut spans);
    let mut masked = text.clone();
    for (key, raw) in &spans {
        masked = masked.replace(
            &format!("\"{key}\": {raw}"),
            &format!("\"{key}\": \"<volatile>\""),
        );
    }
    for (_, raw) in &spans {
        if let Some(inner) = raw.strip_prefix('"').and_then(|raw| raw.strip_suffix('"')) {
            masked = masked.replace(inner, "<volatile>");
        }
    }
    format!("{:?}\n{masked}", result.is_error)
}

/// The masked results of one tool: the preparation or first call, the
/// commit or second call without a proof, and the partial proof.
struct Results {
    prepared: String,
    unproven: String,
    partial: String,
}

/// The classic commit arguments of the preparation `args` that returned
/// `data`, under its business id and without a proof.
fn unproven_commit_args(args: &serde_json::Value, data: &serde_json::Value) -> serde_json::Value {
    let mut args = args.clone();
    for field in ["envelope_xdr", "nonce", "expires_at_unix_ms"] {
        args[field] = data[field].clone();
    }
    args
}

/// The results of `tool`. The preparation runs under a fresh business id,
/// and both commits repeat it, as a commit must.
async fn classic_results(tool: Tool) -> Results {
    let run = ClassicRun::with(
        tool,
        |raw| require_approval_for(&raw, &classic_names(tool)),
        |_| {},
        |_| {},
    )
    .await;
    let args = run.tool.prepare_args(&run.f);
    let prepared = tool.prepare(&run.f.server, &args).await;
    let data = wire(&prepared)["data"].clone();
    let unproven = tool
        .commit(&run.f.server, unproven_commit_args(&args, &data))
        .await
        .unwrap();
    let mut partial_args = unproven_commit_args(&args, &data);
    partial_args["approval_nonce"] = data["approval"]["approval_nonce"].clone();
    let partial = tool.commit(&run.f.server, partial_args).await.unwrap();
    assert_eq!(run.control.count("sendTransaction"), 0, "{tool:?}");
    Results {
        prepared: masked(&prepared),
        unproven: masked(&unproven),
        partial: masked(&partial),
    }
}

/// An attestation of the right form that no consent recorded.
fn unrecorded_attestation() -> String {
    "A".repeat(43)
}

async fn x402_results() -> Results {
    let run =
        X402Run::with(|raw| require_approval_for(&raw, &["stellar_x402_create_payment"])).await;
    let call = |args| async {
        run.f
            .server
            .call_stellar_x402_create_payment(args)
            .await
            .unwrap()
    };
    let prepared = call(x402_args(&run.f, None)).await;
    let nonce = wire(&prepared)["data"]["approval"]["approval_nonce"]
        .as_str()
        .unwrap()
        .to_owned();
    let unproven = call(x402_args(&run.f, Some((&nonce, &unrecorded_attestation())))).await;
    let mut partial_args = x402_args(&run.f, None);
    partial_args.approval_nonce = Some(nonce.clone());
    let partial = call(partial_args).await;
    assert!(authorizations(&run.f).is_empty(), "x402");
    Results {
        prepared: masked(&prepared),
        unproven: masked(&unproven),
        partial: masked(&partial),
    }
}

async fn authenticated_results() -> Results {
    let run =
        AuthenticatedRun::with(|raw| authenticated_policy_with(&raw, require_approval_rule)).await;
    let call = |args| async {
        run.f
            .server
            .call_stellar_x402_authenticated_payment(args)
            .await
            .unwrap()
    };
    let prepared = call(run.args(HOME, None)).await;
    let nonce = wire(&prepared)["data"]["approval"]["approval_nonce"]
        .as_str()
        .unwrap()
        .to_owned();
    let unproven = call(run.args(HOME, Some((&nonce, &unrecorded_attestation())))).await;
    let mut partial_args = run.args(HOME, None);
    partial_args.approval_nonce = Some(nonce.clone());
    let partial = call(partial_args).await;
    assert!(signings().is_empty(), "authenticated x402");
    assert!(authorizations(&run.f).is_empty(), "authenticated x402");
    Results {
        prepared: masked(&prepared),
        unproven: masked(&unproven),
        partial: masked(&partial),
    }
}

/// Expected masked responses under RequireApproval.
const EXPECTED: &str = include_str!("require_approval_results.txt");

/// Under a `RequireApproval` rule for both names, every mainnet tool answers
/// its preparation or first call, its proof-free commit or second call, and
/// its partial proof with the same texts.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn require_approval_mainnet_results_stay_byte_identical() {
    let mut actual = Vec::new();
    for tool in Tool::ALL {
        actual.push((format!("{tool:?}"), classic_results(tool).await));
    }
    actual.push(("X402".to_owned(), x402_results().await));
    actual.push((
        "AuthenticatedX402".to_owned(),
        authenticated_results().await,
    ));
    let mut text = String::new();
    for (name, results) in &actual {
        for (call, result) in [
            ("prepared", &results.prepared),
            ("unproven", &results.unproven),
            ("partial", &results.partial),
        ] {
            text.push_str(&format!("=== {name} {call}\n{result}\n"));
        }
    }
    if text != EXPECTED {
        let path = std::env::temp_dir().join("require_approval_results.actual.txt");
        std::fs::write(&path, &text).unwrap();
        panic!(
            "the results differ; the actual texts are in {}",
            path.display()
        );
    }
}

/// The audit rows of `f` whose kind is `kind`.
fn rows_of(f: &Fixture, kind: &str) -> Vec<serde_json::Value> {
    std::fs::read_to_string(&f.server.security_profile().audit_log_path)
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .filter(|row| row["kind"] == kind)
        .collect()
}

/// The commit arguments of `run` without either proof field.
fn proof_free(run: &ClassicRun) -> serde_json::Value {
    let mut args = run.args.clone();
    let fields = args.as_object_mut().unwrap();
    fields.remove("approval_nonce");
    fields.remove("approval_attestation");
    args
}

/// The bytes of the approval store of `f`; `None` before its first write.
fn store_bytes(f: &Fixture) -> Option<Vec<u8>> {
    std::fs::read(store_path(f)).ok()
}

/// Asserts that the one pending row of `run` records `decision` with the
/// verified policy's digest and the deciding rule's index.
/// The deciding rule is the rule of `governing`, the name whose decision
/// governs.
fn assert_pending_row(context: &str, run: &ClassicRun, decision: &str, governing: &str) {
    let rows = rows_of(&run.f, "value_action_pending");
    assert_eq!(rows.len(), 1, "{context}: {rows:?}");
    assert_eq!(rows[0]["policy_decision"], decision, "{context}: {rows:?}");
    let policy = run.f.server.verified_policy.as_deref().unwrap();
    assert_eq!(
        rows[0]["policy_digest"],
        stellar_agent_core::hex::encode(&policy.digest()),
        "{context}: {rows:?}"
    );
    assert_eq!(
        rows[0]["rule_index"],
        rule_index_of(&run.f, governing),
        "{context}: {rows:?}"
    );
}

/// The policy `raw` with every rule of `tools` allowing.
fn allow_rules(raw: &str, tools: &[&str]) -> String {
    let mut doc = raw.parse::<toml_edit::DocumentMut>().unwrap();
    for rule in doc["rules"].as_array_of_tables_mut().unwrap().iter_mut() {
        if rule["match"]["tool"]
            .as_str()
            .is_some_and(|tool| tools.contains(&tool))
        {
            rule["decision"] = toml_edit::value("allow");
            rule.remove("ttl_secs");
            rule.remove("reason");
        }
    }
    doc.to_string()
}

/// Under `Allow` for both names, each classic preparation carries no
/// approval block and leaves the approval store bytes unchanged.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn allow_prepare_records_no_pending_approval_for_every_kind() {
    for tool in Tool::ALL {
        let run = ClassicRun::allowed(tool).await;
        assert!(
            run.prepared.get("approval").is_none(),
            "{tool:?}: {}",
            run.prepared
        );
        let before = store_bytes(&run.f);
        let prepared = wire(
            &tool
                .prepare(&run.f.server, &tool.prepare_args(&run.f))
                .await,
        );
        assert_eq!(prepared["ok"], true, "{tool:?}: {prepared}");
        assert!(
            prepared["data"].get("approval").is_none(),
            "{tool:?}: {prepared}"
        );
        assert_eq!(
            store_bytes(&run.f),
            before,
            "{tool:?}: the store is unchanged"
        );
    }
}

/// Under `Allow` for both names, each classic commit signs without a proof:
/// one send under one policy authorization record, no tombstone and no
/// consent row; the pending row records `allow` with its provenance.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn allow_commit_signs_without_an_approval_for_every_kind() {
    for tool in Tool::ALL {
        let context = format!("{tool:?}");
        let run = ClassicRun::allowed(tool).await;
        let result = run.commit().await;
        assert_eq!(result["ok"], true, "{context}: {result}");
        assert_eq!(run.control.count("sendTransaction"), 1, "{context}");
        assert_eq!(run.seed_reads(), 1, "{context}: one signature");
        let records = authorizations(&run.f);
        assert_eq!(records.len(), 1, "{context}: {records:?}");
        assert!(
            records[0]["approval_nonce"].is_null(),
            "{context}: {records:?}"
        );
        assert_eq!(
            records[0]["policy_authority"]["scope"],
            serde_json::json!({"kind":"classic"}),
            "{context}: {records:?}"
        );
        assert_eq!(
            store_bytes(&run.f),
            None,
            "{context}: no approval is written"
        );
        for kind in ["approval_attested", "approval_attested_remote"] {
            assert!(
                rows_of(&run.f, kind).is_empty(),
                "{context}: no consent row"
            );
        }
        assert_pending_row(&context, &run, "allow", tool.commit_name());
    }
}

/// Under a `RequireApproval` rule, each classic preparation returns its
/// approval block, and the commit without a proof refuses
/// `policy.approval_required` before anything is minted or signed.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn require_approval_commit_without_proof_refuses_for_every_kind() {
    for tool in Tool::ALL {
        let context = format!("{tool:?}");
        let run = ClassicRun::new(tool).await;
        assert!(
            run.prepared["approval"]["approval_nonce"].is_string(),
            "{context}: {}",
            run.prepared
        );
        let result = run.commit_with(proof_free(&run)).await;
        assert_eq!(
            result["error"]["code"], "policy.approval_required",
            "{context}: {result}"
        );
        assert_classic_unsigned(&context, &run, &run.entry);
    }
}

/// A commit is governed by the stricter decision of its own name and its
/// preparation's name. With one of them requiring approval, in either
/// order, the commit without a proof refuses and nothing signs; the proven
/// commit signs under its approval and records `require_approval`.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn commit_requires_approval_when_either_name_requires_it() {
    for tool in Tool::ALL {
        for (order, allowed, governing) in [
            (
                "preparation requires",
                tool.commit_name(),
                tool.prepare_name(),
            ),
            ("commit requires", tool.prepare_name(), tool.commit_name()),
        ] {
            let context = format!("{tool:?} {order}");
            let run =
                ClassicRun::with(tool, |raw| allow_rules(&raw, &[allowed]), |_| {}, |_| {}).await;
            let result = run.commit_with(proof_free(&run)).await;
            assert_eq!(
                result["error"]["code"], "policy.approval_required",
                "{context}: {result}"
            );
            assert_classic_unsigned(&context, &run, &run.entry);
            let result = run.commit().await;
            assert_classic_accepted(&context, &run, &result);
            let records = authorizations(&run.f);
            assert_eq!(records.len(), 1, "{context}: {records:?}");
            assert_eq!(
                records[0]["approval_nonce"], run.entry.approval_nonce,
                "{context}: {records:?}"
            );
            assert!(records[0]["policy_authority"].is_null(), "{context}");
            assert_pending_row(&context, &run, "require_approval", governing);
        }
    }
}

/// Under `Allow`, a complete proof of an attested approval has no durable
/// record, since an allowed preparation opens none, so it refuses at the
/// mainnet gate with the uniform approval-required envelope, before the
/// protocol nonce is consumed, repeatedly, and nothing signs. A forged
/// attestation refuses with the uniform envelope before anything signs.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn allow_with_supplied_proof_without_a_record_refuses() {
    for tool in Tool::ALL {
        let context = format!("{tool:?}");
        let run = ClassicRun::allowed(tool).await;
        let xdr = run.args["envelope_xdr"].as_str().unwrap().to_owned();
        let forged = approval_for(tool, &run.f, &xdr, 600_000);
        run.f.attest(&forged);
        let blob = forge(&run.f, &forged.approval_nonce, Forged::BadSignature);
        let result = run
            .commit_with(run.commit_args_for(&xdr, &forged.approval_nonce, &blob))
            .await;
        assert_uniform(&format!("{context} forged"), &result);
        assert_classic_unsigned(&context, &run, &forged);

        // An allowed preparation opens no durable record, so a valid supplied
        // proof stays inbox material and the mainnet gate refuses it. The
        // repeat carries the same protocol nonce: the gate refuses before
        // the nonce is consumed, so it refuses again the same way.
        let blob = run.f.attest(&run.entry);
        let args = run.commit_args_for(&xdr, &run.entry.approval_nonce, &blob);
        for _ in 0..2 {
            let result = run.commit_with(args.clone()).await;
            crate::tools::common::tests::mainnet::assert_not_found_mapping(
                &context,
                &result,
                &run.entry.approval_nonce,
            );
            assert_classic_unsigned(&context, &run, &run.entry);
        }
    }
}

/// A nonce without an attestation, and an attestation without a nonce,
/// refuse `policy.approval_required` for every kind under both decisions,
/// and nothing is minted.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn partial_proof_refuses_under_both_decisions() {
    for tool in Tool::ALL {
        for require in [false, true] {
            let run = if require {
                ClassicRun::new(tool).await
            } else {
                ClassicRun::allowed(tool).await
            };
            for (field, value) in [
                ("approval_nonce", run.entry.approval_nonce.clone()),
                ("approval_attestation", unrecorded_attestation()),
            ] {
                let context = format!("{tool:?} require={require} {field} only");
                let mut args = proof_free(&run);
                args[field] = serde_json::json!(value);
                let result = run.commit_with(args).await;
                assert_eq!(
                    result["error"]["code"], "policy.approval_required",
                    "{context}: {result}"
                );
                assert_classic_unsigned(&context, &run, &run.entry);
            }
        }
    }
}

/// A real loopback ceremony records a correlated row before the commit signer.
#[tokio::test]
#[serial_test::serial(keyring)]
#[serial_test::serial]
async fn mcp_approve_browser_round_trip_records_before_signing() {
    use stellar_agent_approval_ui::{
        MainnetPresenceConfig, PageIdentity, presence::test_support::PresenceClient,
        start_mainnet_presence,
    };
    use stellar_agent_core::approval::{
        ApprovalContext, ConsentAudit, ConsentAuthorization, MainnetApprovalAuthority, Surface,
        attest_and_persist,
    };
    let run = ClassicRun::new(Tool::Pay).await;
    let xdr = run.args["envelope_xdr"].as_str().unwrap();
    // The ceremony's entry has its own operation and durable record.
    let (business_id, entry) = recorded_fresh_entry(&run);
    let profile = run.f.server.security_profile();
    let context = ApprovalContext::from_profile(PROFILE, profile);
    let authority = MainnetApprovalAuthority::for_profile(PROFILE).unwrap();
    let mut handle = start_mainnet_presence(MainnetPresenceConfig {
        intent: None,
        entry: entry.clone(),
        context: context.clone(),
        authority: authority.clone(),
        store_path: store_path(&run.f),
        page_identity: PageIdentity::neutral(),
    })
    .await
    .unwrap();
    let browser = PresenceClient::connect(handle.bootstrap_url(), &entry.approval_nonce)
        .await
        .unwrap();
    let options = browser.challenge().await.unwrap().json();
    let challenge = URL_SAFE_NO_PAD
        .decode(options["challenge"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let assertion = fixture_authenticator().assert(
        challenge,
        &browser.origin(),
        MAINNET_APPROVAL_RP_ID,
        FLAG_UP | FLAG_UV,
        7,
    );
    let posted = serde_json::json!({"request_id": options["request_id"], "credential_id_b64url": URL_SAFE_NO_PAD.encode(assertion.credential_id),
        "authenticator_data_b64url": URL_SAFE_NO_PAD.encode(assertion.authenticator_data), "client_data_json_b64url": URL_SAFE_NO_PAD.encode(assertion.client_data_json),
        "signature_der_b64url": URL_SAFE_NO_PAD.encode(assertion.signature_der)});
    assert_eq!(
        browser.post("assertion", &posted).await.unwrap().status,
        200
    );
    let presence = handle
        .await_presence(std::time::Instant::now() + std::time::Duration::from_secs(1))
        .await
        .unwrap();
    handle.shutdown().await.unwrap();
    let request_id = presence.request_id().to_owned();
    let fingerprint = presence.credential_fingerprint().to_owned();
    let mut store = PendingApprovalStore::open(store_path(&run.f)).unwrap();
    let readiness =
        stellar_agent_network::mainnet::audit_readiness::audit_readiness(profile, PROFILE).unwrap();
    let current = authority.load_current_compare_only().unwrap();
    let policy_digest = stellar_agent_core::hex::encode(&current.policy().digest());
    let blob = attest_and_persist(
        &mut store,
        &entry,
        &attestation_key(&run.f),
        &context.binding(),
        Surface::Cli,
        ConsentAudit::Writer(&mut readiness.writer().lock().unwrap()),
        ConsentAuthorization::Mainnet {
            presence,
            policy: current.policy(),
        },
        |_, _| unreachable!(),
    )
    .unwrap()
    .unwrap();
    drop(store);
    run.f.complete_consent(&entry.approval_nonce);
    let audit_path = profile.audit_log_path.clone();
    *run.f.on_seed_read.lock().unwrap() = Some(std::sync::Arc::new(move || {
        let rows = std::fs::read_to_string(&audit_path).unwrap();
        let correlated: Vec<_> = rows
            .lines()
            .filter(|row| row.contains(&request_id))
            .collect();
        assert_eq!(correlated.len(), 1);
        assert!(correlated[0].contains("credential_fingerprint"));
        assert!(correlated[0].contains("policy_digest"));
        assert!(correlated[0].contains(&fingerprint));
        assert!(correlated[0].contains(&policy_digest));
    }));
    let mut args = run.commit_args_for(xdr, &entry.approval_nonce, &blob);
    args["business_id"] = business_id;
    let result = run.commit_with(args).await;
    assert_classic_accepted_for("browser consent", &run, &result, &entry.approval_nonce);
    assert!(
        !is_consumed(&stored_approval(&run.f, &run.entry.approval_nonce).unwrap()),
        "browser consent: the preparation's own approval stays unspent"
    );
}

/// The mainnet approval gate decides a proof from the approval's durable
/// record and the call's admitted operation; the inbox grants nothing.
mod durable_gate {
    use super::*;
    use crate::tools::common::{SuppliedProof, approval_consumed_error, mainnet_authority};
    use stellar_agent_core::approval::subject::approval_subject_classic;
    use stellar_agent_network::mainnet::authority::{AuthorityRefusal, MainnetAuthority};
    use stellar_agent_network::policy_state::approvals::facade_calls;
    use stellar_agent_network::policy_state::{
        ApprovalRecorder, ApprovalStatus, BusinessId, OperationId, OperationStatus,
    };

    /// What the mainnet authority wrapper gives the payment commit of `run`
    /// for the proof `nonce` and `blob` under the admitted `operation`.
    enum Gate {
        Approval,
        Policy,
        Refused(rmcp::model::CallToolResult),
    }

    async fn pay_gate(
        run: &ClassicRun,
        proof: SuppliedProof,
        operation: Option<OperationId>,
    ) -> Gate {
        pay_gate_under(run, &pay_decision(run).await, proof, operation).await
    }

    async fn pay_decision(run: &ClassicRun) -> DispatchOutcome {
        run.f
            .server
            .dispatch_gate("stellar_pay_commit", &run.f.args(), "stellar:mainnet")
            .await
            .unwrap()
    }

    /// [`pay_gate`] under the decision `outcome`.
    async fn pay_gate_under(
        run: &ClassicRun,
        outcome: &DispatchOutcome,
        proof: SuppliedProof,
        operation: Option<OperationId>,
    ) -> Gate {
        let xdr = run.args["envelope_xdr"].as_str().unwrap();
        let mut witness = None;
        let result = mainnet_authority(
            &run.f.server,
            outcome,
            GatedApprovalKind::Payment.expectation(approval_subject_classic(xdr)),
            &proof,
            operation,
            "stellar_pay_commit",
            &mut witness,
        )
        .await;
        match result {
            Ok(MainnetAuthority::Approval(_)) => Gate::Approval,
            Ok(MainnetAuthority::Policy(_)) => Gate::Policy,
            Err(AuthorityRefusal::Gate(result)) => Gate::Refused(result),
            Err(_) => panic!("the wrapper refuses only at its gate here"),
        }
    }

    fn proof(nonce: &str, blob: &str) -> SuppliedProof {
        SuppliedProof {
            nonce: Some(nonce.to_owned()),
            attestation: Some(blob.to_owned()),
        }
    }

    fn own_proof(run: &ClassicRun) -> SuppliedProof {
        proof(
            &run.entry.approval_nonce,
            run.args["approval_attestation"].as_str().unwrap(),
        )
    }

    /// Asserts that `gate` refused with exactly `expected`.
    fn assert_refused(context: &str, gate: Gate, expected: &rmcp::model::CallToolResult) {
        let Gate::Refused(result) = gate else {
            panic!("{context}: the gate admitted the proof")
        };
        assert_eq!(
            normalized(wire(&result)),
            normalized(wire(expected)),
            "{context}"
        );
    }

    fn assert_admitted(context: &str, gate: Gate) {
        match gate {
            Gate::Approval => {}
            Gate::Policy => panic!("{context}: a proof gave policy authority"),
            Gate::Refused(result) => panic!("{context}: {}", wire(&result)),
        }
    }

    fn facts_reads(run: &ClassicRun) -> usize {
        facade_calls::count(run.f.server.window_store.path())
    }

    /// A consented durable record admits its proof with the inbox file
    /// removed, locked by an in-process store handle that holds the inbox
    /// through the commit, or contradicting the record. A
    /// valid inbox consent without a record, and a forged or another
    /// approval's valid proof beside a matching live record, refuse with
    /// the uniform envelope.
    #[tokio::test]
    #[serial_test::serial(keyring)]
    #[serial_test::serial]
    async fn mcp_commit_uses_durable_facts_after_collection() {
        for tool in Tool::ALL {
            let run = ClassicRun::new(tool).await;
            std::fs::remove_file(store_path(&run.f)).unwrap();
            let result = run.commit().await;
            assert_eq!(result["ok"], true, "{tool:?} collected: {result}");
            assert_eq!(run.control.count("sendTransaction"), 1, "{tool:?}");
            assert_eq!(authorizations(&run.f).len(), 1, "{tool:?}");
        }

        for case in ["locked", "contradictory"] {
            let run = ClassicRun::new(Tool::Pay).await;
            if case == "contradictory" {
                edit_stored(&run.f, &run.entry.approval_nonce, |entry| {
                    let expires = entry["expires_at_unix_ms"].as_integer().unwrap();
                    entry["expires_at_unix_ms"] = toml_edit::value(expires - 1_000);
                    entry["attestation_blob_b64"] = toml_edit::value("A".repeat(43));
                });
            }
            let held =
                (case == "locked").then(|| PendingApprovalStore::open(store_path(&run.f)).unwrap());
            let gate = pay_gate(&run, own_proof(&run), Some(run.operation_id())).await;
            drop(held);
            assert_admitted(case, gate);
            let result = run.commit().await;
            assert_eq!(result["ok"], true, "{case}: {result}");
        }

        let run = ClassicRun::new(Tool::Pay).await;
        let operation = Some(run.operation_id());
        let (other_args, _) = run.prepare_again().await;
        let uniform = approval_required_indistinguishable(PROFILE);
        for (case, blob) in [
            ("forged", URL_SAFE_NO_PAD.encode([7_u8; 32])),
            (
                "foreign",
                other_args["approval_attestation"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
            ),
        ] {
            let gate = pay_gate(&run, proof(&run.entry.approval_nonce, &blob), operation).await;
            assert_refused(case, gate, &uniform);
        }
        let xdr = run.args["envelope_xdr"].as_str().unwrap();
        let unrecorded = approval_for(Tool::Pay, &run.f, xdr, 600_000);
        let blob = run.f.attest(&unrecorded);
        assert!(
            stored_approval(&run.f, &unrecorded.approval_nonce)
                .unwrap()
                .attestation_blob_b64
                .is_some(),
            "the inbox holds the consent"
        );
        let gate = pay_gate(&run, proof(&unrecorded.approval_nonce, &blob), operation).await;
        assert_refused("inbox consent without a record", gate, &uniform);
        assert_admitted(
            "the genuine proof",
            pay_gate(&run, own_proof(&run), operation).await,
        );
        assert_classic_unsigned("gate only", &run, &run.entry);
    }

    /// Revokes the durable record of `run`'s approval through the recorder.
    fn revoke(run: &ClassicRun) {
        let server = &run.f.server;
        let profile = server.security_profile();
        let record = ApprovalStatus::new(&server.window_store, profile)
            .find_by_nonce(&run.entry.approval_nonce)
            .unwrap()
            .unwrap()
            .record;
        let (writer, _readiness) = server.write_audit().unwrap();
        let mut writer = writer.lock().unwrap();
        ApprovalRecorder::new(&server.window_store, profile, &mut *writer, "revoke")
            .revoke(record.id)
            .unwrap();
    }

    /// A revoked record renders the redacted `approval.revoked` envelope,
    /// also after its lifetime ends, and names no nonce, proof or path. A
    /// corrupt window and another profile's proof stay uniform.
    #[tokio::test]
    #[serial_test::serial(keyring)]
    #[serial_test::serial]
    async fn mcp_durable_state_envelopes() {
        for case in ["revoked", "revoked and expired"] {
            let run = ClassicRun::new(Tool::Pay).await;
            revoke(&run);
            let outcome = pay_decision(&run).await;
            let clock = (case == "revoked and expired").then(|| {
                stellar_agent_network::mainnet::clock::set_now_ms_for_test(
                    run.entry.expires_at_unix_ms + 1,
                )
            });
            let gate =
                pay_gate_under(&run, &outcome, own_proof(&run), Some(run.operation_id())).await;
            drop(clock);
            let Gate::Refused(result) = gate else {
                panic!("{case}: a revoked approval admitted")
            };
            assert_eq!(result.is_error, Some(true), "{case}");
            let text = serde_json::to_string(&wire(&result)).unwrap();
            let value = wire(&result);
            assert_eq!(value["ok"], false, "{case}: {value}");
            assert_eq!(
                value["error"]["code"], "approval.revoked",
                "{case}: {value}"
            );
            assert_eq!(
                value["error"]["message"], "this approval has been revoked",
                "{case}: {value}"
            );
            assert!(value["error"]["details"].is_null(), "{case}: {value}");
            for secret in [
                run.entry.approval_nonce.as_str(),
                run.args["approval_attestation"].as_str().unwrap(),
                PROFILE,
                "toml",
            ] {
                assert!(!text.contains(secret), "{case}: {text}");
            }
            if case == "revoked" {
                let result = run.commit().await;
                assert_eq!(result["error"]["code"], "approval.revoked", "{result}");
                assert_classic_unsigned(case, &run, &run.entry);
            }
        }

        let run = ClassicRun::new(Tool::Pay).await;
        let (business_id, fresh) = recorded_fresh_entry(&run);
        let other = run.f.attest_bound(&fresh, "other", "stellar:mainnet");
        let fresh_operation =
            OperationStatus::new(&run.f.server.window_store, run.f.server.security_profile())
                .view(&BusinessId::parse(business_id.as_str().unwrap()).unwrap())
                .unwrap()
                .unwrap()
                .operation_id;
        let gate = pay_gate(
            &run,
            proof(&fresh.approval_nonce, &other),
            Some(fresh_operation),
        )
        .await;
        assert_refused(
            "another profile's proof",
            gate,
            &approval_required_indistinguishable(PROFILE),
        );
        let outcome = pay_decision(&run).await;
        let operation = Some(run.operation_id());
        std::fs::write(run.f.server.window_store.path(), b"corrupt window").unwrap();
        let gate = pay_gate_under(&run, &outcome, own_proof(&run), operation).await;
        assert_refused(
            "corrupt window",
            gate,
            &approval_required_indistinguishable(PROFILE),
        );
    }

    /// A verified proof binds the operation the call admitted: another
    /// opened operation of the same subject refuses as spent, and a call
    /// without an admitted operation refuses uniformly. A receipt holding
    /// the nonce, and an unreadable receipt store, refuse before any
    /// durable record is read.
    #[tokio::test]
    #[serial_test::serial(keyring)]
    #[serial_test::serial]
    async fn mcp_reuse_keeps_receipt_and_operation_boundaries() {
        let run = ClassicRun::new(Tool::Pay).await;
        let own = run.operation_id();
        let other_id = run.bind_new_business_id();
        let other =
            OperationStatus::new(&run.f.server.window_store, run.f.server.security_profile())
                .view(&BusinessId::parse(&other_id).unwrap())
                .unwrap()
                .unwrap()
                .operation_id;
        assert_ne!(other, own);
        let gate = pay_gate(&run, own_proof(&run), Some(other)).await;
        assert_refused("another operation", gate, &approval_consumed_error());
        let gate = pay_gate(&run, own_proof(&run), None).await;
        assert_refused(
            "no admitted operation",
            gate,
            &approval_required_indistinguishable(PROFILE),
        );
        let mut args = run.args.clone();
        args["business_id"] = serde_json::json!(other_id);
        let result = refused_commit(&run, args).await;
        assert_eq!(
            normalized(result),
            normalized(wire(&approval_consumed_error()))
        );
        assert_admitted(
            "own operation",
            pay_gate(&run, own_proof(&run), Some(own)).await,
        );

        assert_classic_accepted("first use", &run, &run.commit().await);
        std::fs::remove_file(store_path(&run.f)).unwrap();
        let reads = facts_reads(&run);
        let gate = pay_gate(&run, own_proof(&run), Some(own)).await;
        assert_refused(
            "receipt held, inbox collected",
            gate,
            &approval_consumed_error(),
        );
        assert_eq!(
            facts_reads(&run),
            reads,
            "the receipt refuses before the record read"
        );

        let run = ClassicRun::new(Tool::Pay).await;
        let receipts = stellar_agent_core::profile::receipt::ReceiptStore::open(PROFILE).unwrap();
        std::fs::write(receipts.file_path().unwrap(), "{unparsable").unwrap();
        let reads = facts_reads(&run);
        let gate = pay_gate(&run, own_proof(&run), Some(run.operation_id())).await;
        assert_refused(
            "unreadable receipts",
            gate,
            &approval_required_indistinguishable(PROFILE),
        );
        assert_eq!(
            facts_reads(&run),
            reads,
            "an unreadable receipt reads no record"
        );
    }

    /// The commit's early lookup returns the continuing operation from a
    /// read that writes nothing, also while the window holds another
    /// operation whose waiting time has ended, which a recorder lookup
    /// would expire.
    #[tokio::test]
    #[serial_test::serial(keyring)]
    #[serial_test::serial]
    async fn classic_commit_identity_is_read_only() {
        use stellar_agent_network::operation_entry::{self, OpenedEntry};
        use stellar_agent_network::policy_state::{OpenRequest, OperationKind};
        let run = ClassicRun::new(Tool::Pay).await;
        let server = &run.f.server;
        let profile = server.security_profile();
        let xdr = run.args["envelope_xdr"].as_str().unwrap();
        let view = OperationStatus::new(&server.window_store, profile)
            .view(&BusinessId::parse(run.args["business_id"].as_str().unwrap()).unwrap())
            .unwrap()
            .unwrap();
        let stale = crate::tools::common::tests::fresh_business_id();
        let request = OpenRequest {
            business_id: BusinessId::parse(&stale).unwrap(),
            tool: view.tool.unwrap(),
            kind: view.kind.unwrap(),
            intent: operation_entry::envelope_slot(
                &[9; 32],
                xdr,
                operation_entry::envelope_max_time(xdr).unwrap(),
            ),
            envelope_xdr: Some(xdr.to_owned()),
            prepared_decision: None,
            rule_ttl_ms: Some(1),
        };
        let opened = server
            .operation_step(|recorder| operation_entry::open_classic(recorder, &request))
            .unwrap();
        assert!(matches!(opened, OpenedEntry::Resume(_)), "{opened:?}");
        std::thread::sleep(std::time::Duration::from_millis(5));
        let window = std::fs::read(server.window_store.path()).unwrap();
        let audit = std::fs::read(&profile.audit_log_path).ok();
        for _ in 0..2 {
            let found = server.classic_commit_lookup(
                server.current_mainnet_policy(),
                OperationKind::Pay,
                Some(&BusinessId::parse(run.args["business_id"].as_str().unwrap()).unwrap()),
                xdr,
            );
            assert_eq!(found.ok(), Some(Some(view.operation_id)));
        }
        assert_eq!(
            std::fs::read(server.window_store.path()).unwrap(),
            window,
            "the lookup commits no window generation"
        );
        assert_eq!(
            std::fs::read(&profile.audit_log_path).ok(),
            audit,
            "no audit row"
        );
        let stale_view = OperationStatus::new(&server.window_store, profile)
            .view(&BusinessId::parse(&stale).unwrap())
            .unwrap()
            .unwrap();
        assert!(
            stale_view.state.resumes(),
            "the stale record stays as stored"
        );
    }

    /// Without a proof an allowed commit reads no approval record; a forged
    /// proof under `Allow` refuses; a valid proof of a recorded approval
    /// under `Allow` signs under that approval.
    #[tokio::test]
    #[serial_test::serial(keyring)]
    #[serial_test::serial]
    async fn policy_path_reads_no_record() {
        let run = ClassicRun::allowed(Tool::Pay).await;
        let operation = Some(run.operation_id());
        let reads = facts_reads(&run);
        let gate = pay_gate(&run, SuppliedProof::default(), operation).await;
        assert!(
            matches!(gate, Gate::Policy),
            "proof-free Allow is policy authority"
        );
        assert_eq!(facts_reads(&run), reads, "proof-free Allow reads no record");

        let blob = run.record_own_approval();
        let forged = URL_SAFE_NO_PAD.encode([7_u8; 32]);
        let gate = pay_gate(&run, proof(&run.entry.approval_nonce, &forged), operation).await;
        assert_refused(
            "forged proof under Allow",
            gate,
            &approval_required_indistinguishable(PROFILE),
        );
        let mut args = run.args.clone();
        args["approval_nonce"] = serde_json::json!(run.entry.approval_nonce);
        args["approval_attestation"] = serde_json::json!(blob);
        let result = run.commit_with(args).await;
        assert_eq!(result["ok"], true, "{result}");
        let records = authorizations(&run.f);
        assert_eq!(records.len(), 1, "{records:?}");
        assert_eq!(records[0]["approval_nonce"], run.entry.approval_nonce);
        assert!(records[0]["policy_authority"].is_null(), "{records:?}");
    }

    /// The durable verifier decides at the consent evidence floor of an
    /// enforced kind: a floor at the execution end expires the proof while
    /// wall time is still inside it. An unenforced kind decides at wall time.
    #[tokio::test]
    #[serial_test::serial(keyring)]
    #[serial_test::serial]
    async fn mcp_durable_verifier_uses_fresh_floor() {
        use stellar_agent_core::approval::witness::ApprovedKind;
        use stellar_agent_network::policy_state::approvals::ConsentEvidenceEnforcementGuard;
        let run = ClassicRun::new(Tool::Pay).await;
        let server = &run.f.server;
        let profile = server.security_profile();
        let nonce = &run.entry.approval_nonce;
        let facts = ApprovalStatus::new(&server.window_store, profile)
            .facts_by_nonce(nonce)
            .unwrap()
            .unwrap();
        let end = facts
            .record()
            .consent
            .as_ref()
            .unwrap()
            .execution_expires_at_ms;
        let (writer, _readiness) = server.write_audit().unwrap();
        writer
            .lock()
            .unwrap()
            .initialize_consent_evidence()
            .unwrap();
        let (key, anchor) = stellar_agent_network::keyring::keyed_audit_access(
            profile,
            PROFILE,
            stellar_agent_core::audit_log::BindingCheck::Enforce,
        )
        .unwrap()
        .into_parts();
        stellar_agent_core::audit_log::AuditOutbox::for_log_keyed(
            &profile.audit_log_path,
            anchor,
            key,
        )
        .reserve_evidence([9; 32], end + 3_600_000, end)
        .unwrap();
        let presented: [u8; 32] = URL_SAFE_NO_PAD
            .decode(run.args["approval_attestation"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let expected = GatedApprovalKind::Payment.expectation(approval_subject_classic(
            run.args["envelope_xdr"].as_str().unwrap(),
        ));
        let verify = || {
            crate::tools::common::durable_proof_witness(
                server,
                nonce,
                &presented,
                &expected,
                server.current_mainnet_policy().unwrap(),
                Some(run.operation_id()),
            )
        };
        assert!(now_ms() < end, "wall time is inside the execution window");
        let enabled = ConsentEvidenceEnforcementGuard::new(PROFILE, ApprovedKind::Payment);
        assert_eq!(
            verify().unwrap_err().code(),
            "approval.expired",
            "the floor decides an enforced kind"
        );
        drop(enabled);
        assert!(verify().is_ok(), "wall time decides an unenforced kind");
    }

    /// A retried commit answers from its stored operation after the
    /// approval inbox is collected, with the same reply and no new send.
    #[tokio::test]
    #[serial_test::serial(keyring)]
    #[serial_test::serial]
    async fn collected_inbox_keeps_the_stored_replay() {
        for tool in Tool::ALL {
            let run = ClassicRun::new(tool).await;
            assert_eq!(run.commit().await["ok"], true, "{tool:?}");
            let replay = run.commit().await;
            assert_eq!(replay["data"]["status"], "replayed", "{tool:?}: {replay}");
            std::fs::remove_file(store_path(&run.f)).unwrap();
            let seeds = run.seed_reads();
            let reads = facts_reads(&run);
            let collected = run.commit().await;
            assert_eq!(normalized(collected), normalized(replay), "{tool:?}");
            assert_eq!(run.seed_reads(), seeds, "{tool:?}");
            assert_eq!(run.control.count("sendTransaction"), 0, "{tool:?}");
            assert_eq!(
                facts_reads(&run),
                reads,
                "{tool:?}: the replay reads no record"
            );
        }
    }
}
