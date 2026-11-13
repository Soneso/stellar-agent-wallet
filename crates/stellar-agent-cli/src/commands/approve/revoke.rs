//! Revocation of existing authenticated approval records by inbox nonce.

use std::sync::{Arc, Mutex};

use clap::Args;
use stellar_agent_approval_ui::decision::{RevocationAccess, RevocationFailure, RevocationView};
use stellar_agent_core::approval::Surface;
use stellar_agent_core::audit_log::{AuditEntry, AuditWriter};
use stellar_agent_core::envelope::{Envelope, OutputFormat};
use stellar_agent_core::profile::Profile;
use stellar_agent_network::policy_state::approvals::{
    ApprovalRecorder, ApprovalState, ApprovalStatus, ApprovalView,
};
use stellar_agent_network::policy_state::operations::OperationAudit;
use stellar_agent_network::policy_state::{PersistedWindowStore, WindowStoreError};

use crate::commands::smart_account::common::open_audit_writer;
use crate::common::profile_access::{
    ProfileOrigin, load_profile_reconciled, profile_access_envelope,
};
use crate::common::render::{escape_for_terminal, render_json};
use crate::common::resolve_profile_name;

/// Arguments for `approve revoke`.
#[derive(Debug, Args)]
pub struct RevokeArgs {
    /// The existing approval's inbox nonce; a nonce may begin with `-`.
    #[arg(long, value_name = "NONCE", allow_hyphen_values = true)]
    pub id: String,
    /// The profile name, resolved through the standard profile selection.
    #[arg(long, value_name = "NAME")]
    pub profile: Option<String>,
    /// Output format: `json` or one field per line with `table`.
    #[arg(long, default_value_t = OutputFormat::DEFAULT, value_name = "FORMAT")]
    pub output: OutputFormat,
}

fn project(view: &ApprovalView) -> RevocationView {
    let record = &view.record;
    RevocationView {
        state: match record.state {
            ApprovalState::Revoked => "revoked",
            _ if view.expired => "expired",
            ApprovalState::Consumed => "consumed",
            ApprovalState::Pending => "pending",
        }
        .to_owned(),
        expired: view.expired,
        waiting_expires_at_ms: record.waiting_expires_at_ms,
        execution_expires_at_ms: record.consent.as_ref().map(|c| c.execution_expires_at_ms),
        consent_at_ms: record.consent.as_ref().map(|c| c.consent_at_ms),
        revoked_at_ms: record.revoked_at_ms,
        closed_at_ms: record.closed_at_ms,
    }
}

fn failure(code: &str, message: &str) -> RevocationFailure {
    RevocationFailure {
        code: code.to_owned(),
        message: message.to_owned(),
    }
}

fn store_failure(error: &WindowStoreError) -> RevocationFailure {
    failure(
        error.submission_code(),
        "The durable approval request cannot complete.",
    )
}

trait RevocationCalls {
    fn lookup(&mut self, nonce: &str) -> Result<ApprovalView, RevocationFailure>;
    fn revoke(&mut self, id: [u8; 32]) -> Result<ApprovalView, RevocationFailure>;
    fn append(&mut self, entry: AuditEntry) -> Result<(), RevocationFailure>;
}

fn revoke_with(
    calls: &mut impl RevocationCalls,
    nonce: &str,
    origin: Surface,
    attribution: Option<&str>,
) -> Result<RevocationView, RevocationFailure> {
    let before = calls.lookup(nonce)?;
    let view = project(&before);
    if view.is_noop() {
        return Ok(view);
    }
    // Inbox authority covers only live, unconsented pending durable records.
    if origin != Surface::Cli && !view.permits_inbox_revocation() {
        return Err(failure(
            "approval.denied",
            "The inbox cannot revoke this approval.",
        ));
    }
    let after = calls.revoke(before.record.id)?;
    if after.record.state == ApprovalState::Revoked {
        // The row names the authenticated record's kind on every surface.
        calls.append(AuditEntry::new_approval_revoked(
            before.record.kind.kind_name(),
            nonce,
            origin,
            attribution,
            uuid::Uuid::new_v4().to_string(),
        )).map_err(|_| failure(
            "audit.append_failed",
            "The approval record is revoked, but its audit row cannot be appended. Retrying does not repair the audit row.",
        ))?;
    }
    Ok(project(&after))
}

/// The facade performs no operation transition during revocation.
struct NoOperationRows;
impl OperationAudit for NoOperationRows {
    fn append(&mut self, _: AuditEntry) -> Result<(), String> {
        Err("Revocation cannot append an operation row.".to_owned())
    }
}

pub(super) struct DurableRevocations {
    store: PersistedWindowStore,
    profile: Profile,
    writer: Option<Arc<Mutex<AuditWriter>>>,
    name: String,
}

impl DurableRevocations {
    pub(super) fn new(name: &str, profile: &Profile, writer: Arc<Mutex<AuditWriter>>) -> Self {
        Self {
            store: PersistedWindowStore::for_profile(name),
            profile: profile.clone(),
            writer: Some(writer),
            name: name.to_owned(),
        }
    }
}

impl RevocationCalls for &DurableRevocations {
    fn lookup(&mut self, nonce: &str) -> Result<ApprovalView, RevocationFailure> {
        ApprovalStatus::new(&self.store, &self.profile)
            .find_by_nonce(nonce)
            .map_err(|error| store_failure(&error))?
            .ok_or_else(|| failure("approval.not_found", "No durable approval has that nonce."))
    }

    fn revoke(&mut self, id: [u8; 32]) -> Result<ApprovalView, RevocationFailure> {
        ApprovalRecorder::new(
            &self.store,
            &self.profile,
            &mut NoOperationRows,
            uuid::Uuid::new_v4().to_string(),
        )
        .revoke(id)
        .map_err(|error| store_failure(&error))
    }

    fn append(&mut self, entry: AuditEntry) -> Result<(), RevocationFailure> {
        let writer = match &self.writer {
            Some(writer) => writer.clone(),
            None => {
                open_audit_writer(&self.profile, ProfileOrigin::Persisted, &self.name)
                    .map_err(|_| {
                        failure("audit.append_failed", "The audit writer is unavailable.")
                    })?
                    .0
            }
        };
        writer
            .lock()
            .map_err(|_| failure("audit.append_failed", "The audit writer is unavailable."))?
            .append(entry)
            .map_err(|_| failure("audit.append_failed", "The audit row cannot be appended."))
    }
}

impl RevocationAccess for DurableRevocations {
    fn lookup(&self, nonce: &str) -> Result<RevocationView, RevocationFailure> {
        RevocationCalls::lookup(&mut &*self, nonce).map(|view| project(&view))
    }

    fn revoke(
        &self,
        nonce: &str,
        origin: Surface,
        attribution: Option<&str>,
    ) -> Result<RevocationView, RevocationFailure> {
        revoke_with(&mut &*self, nonce, origin, attribution)
    }
}

fn render_view(view: &RevocationView) -> String {
    let optional = |value: Option<u64>| value.map_or_else(|| "none".to_owned(), |n| n.to_string());
    [
        ("state", view.state.clone()),
        ("expired", view.expired.to_string()),
        (
            "waiting_expires_at_ms",
            view.waiting_expires_at_ms.to_string(),
        ),
        (
            "execution_expires_at_ms",
            optional(view.execution_expires_at_ms),
        ),
        ("consent_at_ms", optional(view.consent_at_ms)),
        ("revoked_at_ms", optional(view.revoked_at_ms)),
        ("closed_at_ms", optional(view.closed_at_ms)),
    ]
    .into_iter()
    .map(|(key, value)| format!("{key}: {}", escape_for_terminal(&value)))
    .collect::<Vec<_>>()
    .join("\n")
}

fn print_result(result: Result<RevocationView, RevocationFailure>, output: OutputFormat) -> i32 {
    match result {
        Ok(view) => {
            if output == OutputFormat::Table {
                #[allow(clippy::print_stdout, reason = "CLI output")]
                {
                    println!("{}", render_view(&view));
                }
            } else {
                render_json(&Envelope::ok(view));
            }
            0
        }
        Err(error) => {
            render_json(&Envelope::<()>::err_raw(error.code, error.message));
            1
        }
    }
}

/// Revokes an existing durable approval in the selected profile.
///
/// Returns zero for a view, including no-ops, and one for a refusal.
pub async fn run(args: RevokeArgs) -> i32 {
    let resolved = resolve_profile_name(args.profile.as_deref());
    let profile = match load_profile_reconciled(&resolved) {
        Ok(profile) => profile,
        Err(error) => {
            render_json(&profile_access_envelope(&error));
            return 1;
        }
    };
    if let Err(error) = stellar_agent_network::keyring::init_platform_keyring_store() {
        render_json(&Envelope::<()>::err(&error));
        return 1;
    }
    let access = DurableRevocations {
        store: PersistedWindowStore::for_profile(&resolved.name),
        profile,
        writer: None,
        name: resolved.name,
    };
    print_result(
        RevocationAccess::revoke(&access, &args.id, Surface::Cli, None),
        args.output,
    )
}

#[cfg(test)]
pub(super) mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test assertions"
    )]

    use super::*;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
    use clap::Parser;
    use serde_json::{Value, json};
    use stellar_agent_core::approval::{
        ApprovalContext, ConsentAudit, ConsentAuthorization, PendingApproval, PendingApprovalStore,
        attest_and_persist,
        mainnet_fixtures::{ATTESTATION_KEY, MainnetConsentFixture},
        subject::{SubjectKind, approval_subject_classic},
        witness::{ApprovalExpectation, ApprovedKind, verify_approval},
    };
    use stellar_agent_network::mainnet::{
        MainnetConsumer, MainnetPrecondition,
        clock::{TestClockGuard, set_now_ms_for_test},
        digest::BindingFacts,
    };
    use stellar_agent_network::policy_state::{
        approvals::{ConsentPayload, PendingApprovalFacts},
        ledger::{DomainBinding, MintAuthority, MintRequest},
        operations::{
            AttemptAuthorization, AttemptEnvelope, AttemptRequest, BusinessId, IntentSlot,
            OpenOutcome, OpenRequest, OperationHandle, OperationKind, OperationLink,
            OperationRecorder, OperationTool,
        },
    };

    /// The fixture entry's kind name.
    const KIND: &str = "PaymentSimulated";

    /// The production adapter with a count of its calls.
    struct CountedRevocations {
        inner: DurableRevocations,
        calls: std::sync::atomic::AtomicUsize,
    }
    impl RevocationAccess for CountedRevocations {
        fn lookup(&self, nonce: &str) -> Result<RevocationView, RevocationFailure> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            RevocationAccess::lookup(&self.inner, nonce)
        }
        fn revoke(
            &self,
            nonce: &str,
            origin: Surface,
            attribution: Option<&str>,
        ) -> Result<RevocationView, RevocationFailure> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            RevocationAccess::revoke(&self.inner, nonce, origin, attribution)
        }
    }

    #[derive(Default)]
    struct Rows(Vec<AuditEntry>);
    impl OperationAudit for Rows {
        fn append(&mut self, row: AuditEntry) -> Result<(), String> {
            self.0.push(row);
            Ok(())
        }
    }

    /// A mainnet profile with one pending durable record and its inbox entry,
    /// shared with the other `approve` command tests.
    pub(in crate::commands::approve) struct Fixture {
        pub(in crate::commands::approve) core: MainnetConsentFixture,
        pub(in crate::commands::approve) store: PersistedWindowStore,
        clock: TestClockGuard,
        pub(in crate::commands::approve) entry: PendingApproval,
        handle: OperationHandle,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            stellar_agent_network::keyring::KEEP_REGISTERED_STORE
                .store(false, std::sync::atomic::Ordering::SeqCst);
        }
    }
    impl Fixture {
        pub(in crate::commands::approve) fn new() -> Self {
            Self::from_core(MainnetConsentFixture::new("revocation"))
        }
        fn from_core(core: MainnetConsentFixture) -> Self {
            stellar_agent_network::keyring::KEEP_REGISTERED_STORE
                .store(true, std::sync::atomic::Ordering::SeqCst);
            let entry = core.payment(300_000);
            let clock = set_now_ms_for_test(entry.created_at_unix_ms);
            let store = PersistedWindowStore::for_profile(core.name());
            let handle = open_record(&store, core.profile(), &entry, "revocation-order");
            PendingApprovalStore::open(core.store_path())
                .unwrap()
                .insert(entry.clone(), entry.created_at_unix_ms)
                .unwrap();
            Self {
                core,
                store,
                clock,
                entry,
                handle,
            }
        }
    }

    /// Opens operation `business` and the pending durable record of `entry`
    /// in `store`.
    fn open_record(
        store: &PersistedWindowStore,
        profile: &Profile,
        entry: &PendingApproval,
        business: &str,
    ) -> OperationHandle {
        let mut rows = Rows::default();
        let opened = OperationRecorder::new(store, profile, &mut rows, "open")
            .open(&OpenRequest {
                business_id: BusinessId::parse(business).unwrap(),
                tool: OperationTool::CliPay,
                kind: OperationKind::Pay,
                intent: IntentSlot::Canonical {
                    intent_digest: [1; 32],
                    intent: json!({"op":"pay"}),
                },
                envelope_xdr: Some("AAAA".to_owned()),
                prepared_decision: None,
                rule_ttl_ms: Some(300_000),
            })
            .unwrap();
        let OpenOutcome::New(handle) = opened else {
            panic!("new operation")
        };
        let stellar_agent_core::approval::ApprovalKind::PaymentSimulated {
            envelope_xdr_b64, ..
        } = &entry.kind
        else {
            panic!("payment")
        };
        ApprovalRecorder::new(store, profile, &mut rows, "pending")
            .open_pending(
                handle.id(),
                &PendingApprovalFacts {
                    nonce: entry.approval_nonce.clone(),
                    kind: ApprovedKind::Payment,
                    subject_kind: SubjectKind::EnvelopeText,
                    subject: approval_subject_classic(envelope_xdr_b64),
                    intent_digest: [1; 32],
                    created_at_ms: entry.created_at_unix_ms,
                    waiting_expires_at_ms: entry.expires_at_unix_ms,
                    rule_ttl_ms: 300_000,
                },
            )
            .unwrap();
        handle
    }

    impl Fixture {
        pub(in crate::commands::approve) fn view(&self) -> ApprovalView {
            ApprovalStatus::new(&self.store, self.core.profile())
                .find_by_nonce(&self.entry.approval_nonce)
                .unwrap()
                .unwrap()
        }
        fn bytes(&self) -> Vec<u8> {
            std::fs::read(self.store.path()).unwrap()
        }
        fn unchanged_sections(&self) -> Value {
            let mut value: Value = serde_json::from_slice(&self.bytes()[32..]).unwrap();
            let object = value.as_object_mut().unwrap();
            object.remove("generation");
            object.remove("approvals");
            value
        }
        pub(in crate::commands::approve) fn access(&self) -> DurableRevocations {
            DurableRevocations::new(
                self.core.name(),
                self.core.profile(),
                Arc::new(Mutex::new(self.core.audit_writer())),
            )
        }
        fn base_context(&self) -> stellar_agent_approval_ui::DecisionContext {
            stellar_agent_approval_ui::DecisionContext::new(
                ApprovalContext::from_profile(self.core.name(), self.core.profile()),
                self.core.store_path(),
                self.core.profile().attestation_key_id.clone(),
                stellar_agent_core::profile::owner_key::OwnerKeyContext::for_profile(
                    self.core.name(),
                    self.core.profile(),
                ),
                Arc::new(Mutex::new(self.core.audit_writer())),
                None,
            )
            .with_mainnet_authority(self.core.authority())
        }
        fn context(&self) -> stellar_agent_approval_ui::DecisionContext {
            super::super::serve::install_revocation(
                self.base_context(),
                self.core.name(),
                self.core.profile(),
            )
        }
        /// A context whose real adapter counts its calls.
        fn counted_context(
            &self,
        ) -> (
            stellar_agent_approval_ui::DecisionContext,
            Arc<CountedRevocations>,
        ) {
            let context = self.base_context();
            let access = Arc::new(CountedRevocations {
                inner: DurableRevocations::new(
                    self.core.name(),
                    self.core.profile(),
                    context.audit_writer.clone(),
                ),
                calls: std::sync::atomic::AtomicUsize::new(0),
            });
            (context.with_revocation_access(access.clone()), access)
        }
        pub(in crate::commands::approve) fn consent(&mut self) {
            let policy = self.core.current_policy();
            let presence = self.presence();
            let mut store = PendingApprovalStore::open(self.core.store_path()).unwrap();
            let blob = attest_and_persist(
                &mut store,
                &self.entry,
                &ATTESTATION_KEY,
                &self.core.binding(),
                Surface::Cli,
                ConsentAudit::Writer(&mut self.core.audit_writer()),
                ConsentAuthorization::Mainnet {
                    presence,
                    policy: &policy,
                },
                |_, _| Err("unsupported grant".to_owned()),
            )
            .unwrap()
            .unwrap();
            let attestation = B64.decode(blob).unwrap().try_into().unwrap();
            let entry = store.get(&self.entry.approval_nonce).unwrap();
            let payload = ConsentPayload {
                attestation,
                receipt: entry.mainnet_presence.clone().unwrap(),
                process_uid: entry.process_uid.clone(),
            };
            self.clock.set(payload.receipt.verified_at_unix_ms());
            let view = self.view();
            let witness = verify_approval(
                &store,
                self.core.profile(),
                self.core.name(),
                &self.entry.approval_nonce,
                &attestation,
                &ApprovalExpectation {
                    kind: ApprovedKind::Payment,
                    subject: view.record.subject,
                },
                &policy,
                payload.receipt.verified_at_unix_ms(),
            )
            .unwrap();
            ApprovalRecorder::new(
                &self.store,
                self.core.profile(),
                &mut Rows::default(),
                "consent",
            )
            .record_consent(view.record.id, &witness, &payload)
            .unwrap();
        }
        fn presence(&self) -> stellar_agent_core::approval::VerifiedMainnetPresence {
            use stellar_agent_core::approval::presence::{
                ListenerIdentity, PresenceListener, issue_mainnet_intent_presence,
                verify_mainnet_presence,
            };
            let policy = self.core.current_policy();
            if policy.mainnet().unwrap().approval_origin.is_none() {
                return self.core.presence(&self.entry, &policy);
            }
            let identity = ListenerIdentity::capture(&policy).unwrap();
            let pending = issue_mainnet_intent_presence(
                &self.entry,
                &self.core.binding(),
                &policy,
                PresenceListener::SignedOrigin(&identity),
                None,
                stellar_agent_core::timefmt::now_unix_ms().unwrap(),
                std::time::Instant::now(),
            )
            .unwrap();
            let assertion = MainnetConsentFixture::sign_issued(
                &stellar_agent_test_support::webauthn::fixture_authenticator(),
                &pending,
            );
            verify_mainnet_presence(
                pending,
                MainnetConsentFixture::input(&assertion),
                stellar_agent_core::timefmt::now_unix_ms().unwrap(),
                std::time::Instant::now(),
            )
            .unwrap()
        }
        pub(in crate::commands::approve) fn mint(&self) -> MintRequest {
            let policy = self.core.current_policy();
            MintRequest {
                chain: self.core.profile().chain_id,
                consumer: MainnetConsumer::CliPay,
                binding: DomainBinding::Transaction {
                    unsigned_envelope_sha256: [1; 32],
                    tx_hash: [2; 32],
                    source: "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF".to_owned(),
                    sequence: 1,
                },
                policy_sequence: policy.sequence(),
                policy_digest: policy.digest(),
                authority: MintAuthority::Approval {
                    nonce: self.entry.approval_nonce.clone(),
                    expires_at_ms: u64::MAX,
                },
                chain_deadline_ms: None,
                authorization_ttl_ms: 1,
                bindings: BindingFacts {
                    endpoint: None,
                    signer: [2; 32],
                    policy: [3; 32],
                    enablement: [4; 32],
                    witness: None,
                    reservation: None,
                    authority: [7; 32],
                    audit: [8; 32],
                },
                holds: vec![stellar_agent_core::policy::v1::criteria::state_store::WindowEntry::new(
                    stellar_agent_core::policy::v1::criteria::state_store::StateKey::new(self.core.name(), 1, "native", 86_400),
                    self.entry.created_at_unix_ms,
                    10,
                    stellar_agent_core::policy::v1::criteria::state_store::WindowLimit::Amount {
                        asset: "native".to_owned(), window: "1d".to_owned(), max_stroops: 100_000,
                    },
                )],
                parent: None,
                operation: Some(OperationLink {
                    operation_id: self.handle.id(),
                    attempt_index: 1,
                }),
                native_reservation: None,
            }
        }
    }

    #[derive(Debug, Parser)]
    struct Command {
        #[command(flatten)]
        args: super::super::ApproveArgs,
    }
    /// Mints the audit chain key that CLI and serve audit writers require.
    async fn mint_audit_key(name: &str) {
        let args = crate::commands::profile::rotate_audit_key::RotateAuditKeyArgs {
            name: Some(name.to_owned()),
            profile: None,
        };
        assert_eq!(
            crate::commands::profile::rotate_audit_key::run(&args).await,
            0
        );
    }

    async fn dispatch(f: &Fixture, id: &str) -> i32 {
        let parsed =
            Command::try_parse_from(["approve", "revoke", "--id", id, "--profile", f.core.name()])
                .unwrap();
        assert_eq!(parsed.args.profile_flag(), Some(f.core.name()));
        super::super::dispatch(parsed.args).await
    }

    /// A supplied nonce that starts with a hyphen keeps the options after it.
    /// An omitted nonce takes the next token as its value, as `approve --id`
    /// does.
    #[test]
    fn revoke_id_accepts_hyphen_values_like_approve_id() {
        let nonce = "-AbCdEfGhIjKlMnOpQrStU";
        let parsed =
            Command::try_parse_from(["approve", "revoke", "--id", nonce, "--profile", "p"])
                .unwrap();
        let Some(super::super::ApproveSubcommand::Revoke(args)) = &parsed.args.subcommand else {
            panic!("revoke arguments")
        };
        assert_eq!(args.id, nonce);
        assert_eq!(args.profile.as_deref(), Some("p"));

        let parsed = Command::try_parse_from(["approve", "revoke", "--id", "--profile"]).unwrap();
        let Some(super::super::ApproveSubcommand::Revoke(args)) = &parsed.args.subcommand else {
            panic!("revoke arguments")
        };
        assert_eq!(args.id, "--profile");
        assert_eq!(args.profile, None);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn revocation_cli_selects_the_profile_and_record() {
        // A profile name of its own keeps earlier audit keys out of this test.
        let f = Fixture::from_core(MainnetConsentFixture::new("revocation-select"));
        mint_audit_key(f.core.name()).await;
        // The keyed log refuses an unkeyed writer, so lookups open none.
        let access = DurableRevocations {
            store: PersistedWindowStore::for_profile(f.core.name()),
            profile: f.core.profile().clone(),
            writer: None,
            name: f.core.name().to_owned(),
        };
        assert_eq!(
            RevocationAccess::lookup(&access, &f.entry.approval_nonce).unwrap(),
            project(&f.view())
        );
        let before = f.bytes();
        for id in [
            "malformed",
            "AAAAAAAAAAAAAAAAAAAAAA",
            "",
            "-AAAAAAAAAAAAAAAAAAAAA",
        ] {
            assert_eq!(dispatch(&f, id).await, 1);
            assert_eq!(f.bytes(), before);
            assert_eq!(
                RevocationAccess::lookup(&access, id).unwrap_err().code,
                "approval.not_found"
            );
        }
        let other = Profile::builder_mainnet_named(
            "other",
            "https://rpc.example.invalid",
            "other-signer",
            "default",
            "other-nonce",
            "default",
        )
        .build();
        // The other profile keeps its own audit log and chain key.
        let mut other = other;
        other.audit_log_path = f.core.home().join("other-audit.jsonl");
        other.audit_log_hash_chain_key_id.service = "stellar-agent-audit-other".to_owned();
        stellar_agent_core::profile::loader::save_to_dir(
            "other",
            &other,
            &f.core.home().join("profiles"),
        )
        .unwrap();
        let other_store = PersistedWindowStore::for_profile("other");
        open_record(&other_store, &other, &f.entry, "revocation-order");
        let other_state = || {
            ApprovalStatus::new(&other_store, &other)
                .find_by_nonce(&f.entry.approval_nonce)
                .unwrap()
                .unwrap()
                .record
                .state
        };
        let other_before = std::fs::read(other_store.path()).unwrap();
        assert_eq!(dispatch(&f, &f.entry.approval_nonce).await, 0);
        mint_audit_key("other").await;
        assert_eq!(f.view().record.state, ApprovalState::Revoked);
        assert_eq!(std::fs::read(other_store.path()).unwrap(), other_before);
        assert_eq!(other_state(), ApprovalState::Pending);
        let revoked = f.bytes();
        let parsed = Command::try_parse_from([
            "approve",
            "revoke",
            "--id",
            &f.entry.approval_nonce,
            "--profile",
            "other",
        ])
        .unwrap();
        assert_eq!(parsed.args.profile_flag(), Some("other"));
        assert_eq!(super::super::dispatch(parsed.args).await, 0);
        assert_eq!(other_state(), ApprovalState::Revoked);
        assert_eq!(f.bytes(), revoked);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn cli_revocation_persists_through_the_facade() {
        let f = Fixture::new();
        mint_audit_key(f.core.name()).await;
        assert_eq!(dispatch(&f, &f.entry.approval_nonce).await, 0);
        assert_eq!(f.view().record.state, ApprovalState::Revoked);
        let audit = std::fs::read_to_string(f.core.audit_path()).unwrap();
        let row: Value = serde_json::from_str(audit.lines().last().unwrap()).unwrap();
        assert_eq!(row["kind"], "approval_revoked");
        assert_eq!(row["approval_kind"], KIND);
        let bytes = f.bytes();
        assert_eq!(dispatch(&f, &f.entry.approval_nonce).await, 0);
        assert_eq!(f.bytes(), bytes);
        let reopened = PersistedWindowStore::for_profile(f.core.name());
        assert_eq!(
            ApprovalStatus::new(&reopened, f.core.profile())
                .find_by_nonce(&f.entry.approval_nonce)
                .unwrap()
                .unwrap(),
            f.view()
        );
        drop(f);
        let f = Fixture::new();
        f.clock.set(f.entry.created_at_unix_ms - 1);
        let before = f.bytes();
        let error =
            RevocationAccess::revoke(&f.access(), &f.entry.approval_nonce, Surface::Cli, None)
                .unwrap_err();
        assert_eq!(error.code, "internal.unexpected_state");
        assert_eq!(print_result(Err(error), OutputFormat::Json), 1);
        assert_eq!(dispatch(&f, &f.entry.approval_nonce).await, 1);
        assert_eq!(f.bytes(), before);
    }

    struct ScriptedClockAndCalls<'a> {
        real: &'a DurableRevocations,
        clock: &'a TestClockGuard,
        during_revoke: Option<u64>,
        calls: Vec<&'static str>,
        fail_append: bool,
    }
    impl RevocationCalls for ScriptedClockAndCalls<'_> {
        fn lookup(&mut self, nonce: &str) -> Result<ApprovalView, RevocationFailure> {
            self.calls.push("lookup");
            RevocationCalls::lookup(&mut self.real, nonce)
        }
        fn revoke(&mut self, id: [u8; 32]) -> Result<ApprovalView, RevocationFailure> {
            self.calls.push("revoke");
            if let Some(at) = self.during_revoke {
                self.clock.set(at);
            }
            RevocationCalls::revoke(&mut self.real, id)
        }
        fn append(&mut self, entry: AuditEntry) -> Result<(), RevocationFailure> {
            self.calls.push("append");
            let nonce = self.real_nonce();
            assert_eq!(
                RevocationCalls::lookup(&mut self.real, &nonce)?
                    .record
                    .state,
                ApprovalState::Revoked
            );
            if self.fail_append {
                return Err(failure("audit.append_failed", "test append refusal"));
            }
            RevocationCalls::append(&mut self.real, entry)
        }
    }
    impl ScriptedClockAndCalls<'_> {
        fn real_nonce(&self) -> String {
            PendingApprovalStore::open(
                super::super::common::approval_store_dir()
                    .unwrap()
                    .join(format!("{}.toml", self.real.name)),
            )
            .unwrap()
            .snapshot(stellar_agent_core::timefmt::now_unix_ms().unwrap())[0]
                .approval_nonce
                .clone()
        }
    }

    #[test]
    #[serial_test::serial]
    fn revocation_audit_single_call_order_and_failures() {
        for (consented, scenario) in [false, true].into_iter().flat_map(|consented| {
            [
                "success",
                "expired",
                "during-expiry",
                "facade-error",
                "append-error",
            ]
            .map(move |scenario| (consented, scenario))
        }) {
            let mut f = Fixture::new();
            if consented {
                f.consent();
            }
            let view = f.view();
            let expiry = view
                .record
                .consent
                .as_ref()
                .map_or(view.record.waiting_expires_at_ms, |consent| {
                    consent.execution_expires_at_ms
                });
            let access = f.access();
            let before = f.bytes();
            let unchanged = f.unchanged_sections();
            if scenario == "expired" {
                f.clock.set(expiry);
            }
            let mut calls = ScriptedClockAndCalls {
                real: &access,
                clock: &f.clock,
                during_revoke: match scenario {
                    "during-expiry" => Some(expiry),
                    "facade-error" => Some(f.entry.created_at_unix_ms - 1),
                    _ => None,
                },
                calls: vec![],
                fail_append: scenario == "append-error",
            };
            let result = revoke_with(&mut calls, &f.entry.approval_nonce, Surface::Cli, None);
            let expected: &[&str] = match scenario {
                "expired" => &["lookup"],
                "during-expiry" | "facade-error" => &["lookup", "revoke"],
                _ => &["lookup", "revoke", "append"],
            };
            assert_eq!(calls.calls, expected, "{scenario}");
            assert_eq!(f.unchanged_sections(), unchanged);
            match scenario {
                "facade-error" => {
                    assert_eq!(result.unwrap_err().code, "internal.unexpected_state");
                    assert_eq!(f.bytes(), before);
                }
                "expired" | "during-expiry" => {
                    assert!(result.unwrap().expired);
                    assert_eq!(f.bytes(), before);
                }
                "append-error" => {
                    let error = result.unwrap_err();
                    assert_eq!(error.code, "audit.append_failed");
                    assert!(error.message.contains("record is revoked"));
                    assert_eq!(f.view().record.state, ApprovalState::Revoked);
                }
                _ => assert_eq!(result.unwrap().state, "revoked"),
            }
            if scenario != "facade-error" {
                calls.calls.clear();
                calls.during_revoke = None;
                let bytes = f.bytes();
                let audit = std::fs::read(f.core.audit_path()).unwrap();
                assert!(
                    revoke_with(&mut calls, &f.entry.approval_nonce, Surface::Cli, None).is_ok()
                );
                assert_eq!(calls.calls, ["lookup"]);
                assert_eq!(f.bytes(), bytes);
                assert_eq!(std::fs::read(f.core.audit_path()).unwrap(), audit);
            }
        }
    }

    #[test]
    #[serial_test::serial]
    fn revocation_surfaces_preserve_windows_and_noops() {
        for state in ["pending", "consented", "consumed"] {
            for expired in [false, true] {
                let mut f = Fixture::new();
                if state != "pending" {
                    f.consent();
                }
                if state == "consumed" {
                    let mut mint = f.mint();
                    mint.authorization_ttl_ms = 300_000;
                    f.store.mint_authorization(f.core.profile(), &mint).unwrap();
                }
                let before = f.view();
                let expiry = before
                    .record
                    .consent
                    .as_ref()
                    .map_or(before.record.waiting_expires_at_ms, |c| {
                        c.execution_expires_at_ms
                    });
                f.clock.set(if expired { expiry } else { expiry - 1 });
                let bytes = f.bytes();
                let sections = f.unchanged_sections();
                let access = f.access();
                let result =
                    RevocationAccess::revoke(&access, &f.entry.approval_nonce, Surface::Cli, None)
                        .unwrap();
                assert_eq!(print_result(Ok(result.clone()), OutputFormat::Json), 0);
                assert_eq!(result.expired, expired);
                assert_eq!(
                    result.waiting_expires_at_ms,
                    before.record.waiting_expires_at_ms
                );
                assert_eq!(
                    result.consent_at_ms,
                    before.record.consent.as_ref().map(|c| c.consent_at_ms)
                );
                assert_eq!(
                    result.execution_expires_at_ms,
                    before
                        .record
                        .consent
                        .as_ref()
                        .map(|c| c.execution_expires_at_ms)
                );
                assert_eq!(f.unchanged_sections(), sections);
                assert_eq!(f.view().record.consumed_at_ms, before.record.consumed_at_ms);
                assert_eq!(f.view().record.operation_id, before.record.operation_id);
                if expired {
                    assert_eq!(f.bytes(), bytes);
                } else {
                    assert_eq!(f.view().record.consent, before.record.consent);
                    assert_eq!(result.state, "revoked");
                    assert_eq!(result.revoked_at_ms, Some(expiry - 1));
                }
            }
        }
    }

    #[test]
    #[serial_test::serial]
    fn surface_revocation_blocks_first_mint_and_remint() {
        for carrier in [false, true] {
            let mut f = Fixture::new();
            f.consent();
            let request = f.mint();
            if carrier {
                f.store
                    .mint_authorization(f.core.profile(), &request)
                    .unwrap();
            }
            let access = f.access();
            RevocationAccess::revoke(&access, &f.entry.approval_nonce, Surface::Cli, None).unwrap();
            if carrier {
                assert!(matches!(
                    f.store.mint_authorization(f.core.profile(), &request),
                    Err(WindowStoreError::AuthorizationRefused {
                        precondition: MainnetPrecondition::DuplicateOpen
                    })
                ));
                f.clock
                    .set(f.view().record.consent.as_ref().unwrap().consent_at_ms + 2);
                let mut reused = request.clone();
                let DomainBinding::Transaction { tx_hash, .. } = &mut reused.binding else {
                    panic!("transaction")
                };
                *tx_hash = [9; 32];
                let earlier = f.store.mint_authorization(f.core.profile(), &reused);
                assert!(
                    matches!(
                        earlier,
                        Err(WindowStoreError::AuthorizationRefused {
                            precondition: MainnetPrecondition::ApprovalNonceReused
                        })
                    ),
                    "{earlier:?}"
                );
            }
            let before = f.bytes();
            let result = if carrier {
                OperationRecorder::new(&f.store, f.core.profile(), &mut Rows::default(), "remint")
                    .begin_attempt(
                        &f.handle,
                        &AttemptRequest {
                            envelope: Some(AttemptEnvelope {
                                xdr: "AAAA".to_owned(),
                                unsigned_envelope_sha256: [1; 32],
                            }),
                            authorization: AttemptAuthorization::Mint(Box::new(request.clone())),
                            send_by_ms: u64::MAX,
                        },
                    )
                    .map(|_| ())
            } else {
                f.store
                    .mint_authorization(f.core.profile(), &request)
                    .map(|_| ())
            };
            assert!(
                matches!(
                    result,
                    Err(WindowStoreError::AuthorizationRefused {
                        precondition: MainnetPrecondition::ApprovalRevoked
                    })
                ),
                "{result:?}"
            );
            assert_eq!(f.bytes(), before);
            if !carrier {
                f.clock.set(f.entry.expires_at_unix_ms + 1);
                assert!(matches!(
                    f.store.mint_authorization(f.core.profile(), &request),
                    Err(WindowStoreError::AuthorizationRefused {
                        precondition: MainnetPrecondition::ApprovalRevoked
                    })
                ));
            }
        }
        let f = Fixture::new();
        let ctx = f.context();
        assert!(matches!(
            stellar_agent_approval_ui::decision::apply_decision(
                &ctx,
                stellar_agent_approval_ui::decision::Decision::Revoke {
                    nonce: f.entry.approval_nonce.clone()
                },
                stellar_agent_approval_ui::decision::RequestIdentity::Local
            ),
            stellar_agent_approval_ui::decision::Outcome::Revocation(_)
        ));
        assert!(matches!(
            f.store.mint_authorization(f.core.profile(), &f.mint()),
            Err(WindowStoreError::AuthorizationRefused {
                precondition: MainnetPrecondition::ApprovalRevoked
            })
        ));
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn revocation_survives_restart_and_inbox_collection() {
        // A profile name of its own keeps earlier audit keys out of this test.
        let mut f = Fixture::from_core(MainnetConsentFixture::new("revocation-collected"));
        f.consent();
        mint_audit_key(f.core.name()).await;
        f.store
            .mint_authorization(f.core.profile(), &f.mint())
            .unwrap();
        PendingApprovalStore::open(f.core.store_path())
            .unwrap()
            .consume(
                &f.entry.approval_nonce,
                &"ab".repeat(32),
                stellar_agent_core::approval::store::ConsumedOutcome::Confirmed,
            )
            .unwrap();
        let parsed = Command::try_parse_from([
            "approve",
            "gc",
            "--include-consumed",
            "--profile",
            f.core.name(),
        ])
        .unwrap();
        assert_eq!(super::super::dispatch(parsed.args).await, 0);
        assert!(
            PendingApprovalStore::open(f.core.store_path())
                .unwrap()
                .get(&f.entry.approval_nonce)
                .is_none()
        );
        // The CLI names the authenticated record's kind without an inbox entry.
        assert_eq!(dispatch(&f, &f.entry.approval_nonce).await, 0);
        let audit = std::fs::read_to_string(f.core.audit_path()).unwrap();
        let row: Value = serde_json::from_str(audit.lines().last().unwrap()).unwrap();
        assert_eq!(row["kind"], "approval_revoked");
        assert_eq!(row["approval_kind"], KIND);
        let result = project(&f.view());
        assert_eq!(result.state, "revoked");
        let reopened = PersistedWindowStore::for_profile(f.core.name());
        assert_eq!(
            project(
                &ApprovalStatus::new(&reopened, f.core.profile())
                    .find_by_nonce(&f.entry.approval_nonce)
                    .unwrap()
                    .unwrap()
            ),
            result
        );
        f.clock
            .set(f.view().record.consent.as_ref().unwrap().consent_at_ms + 2);
        let remint = OperationRecorder::new(
            &f.store,
            f.core.profile(),
            &mut Rows::default(),
            "after-collection",
        )
        .begin_attempt(
            &f.handle,
            &AttemptRequest {
                envelope: Some(AttemptEnvelope {
                    xdr: "AAAA".to_owned(),
                    unsigned_envelope_sha256: [1; 32],
                }),
                authorization: AttemptAuthorization::Mint(Box::new(f.mint())),
                send_by_ms: u64::MAX,
            },
        );
        assert!(matches!(
            remint,
            Err(WindowStoreError::AuthorizationRefused {
                precondition: MainnetPrecondition::ApprovalRevoked
            })
        ));
    }

    /// The existing approval rows from fixed inputs, each with its fixed
    /// time and request id.
    fn existing_approval_rows() -> Vec<(&'static str, String)> {
        let nonce = "AAAAAAAAAAAAAAAAAAAAAA";
        let digest = Some("ab".repeat(32));
        [
            (
                "attested",
                AuditEntry::new_approval_attested(
                    KIND,
                    "stellar_pay_commit",
                    digest.clone(),
                    nonce,
                    "serve",
                    "request",
                ),
            ),
            (
                "rejected",
                AuditEntry::new_approval_rejected(KIND, nonce, "cli", "request"),
            ),
            (
                "attested_remote",
                AuditEntry::new_approval_attested_remote(
                    KIND,
                    "stellar_pay_commit",
                    digest,
                    nonce,
                    "credential",
                    "request",
                ),
            ),
            (
                "rejected_remote",
                AuditEntry::new_approval_rejected_remote(KIND, nonce, "credential", "request"),
            ),
        ]
        .into_iter()
        .map(|(label, mut row)| {
            row.ts = "2026-01-01T00:00:00.000Z".to_owned();
            (label, serde_json::to_string(&row).unwrap())
        })
        .collect()
    }

    /// The rows of [`existing_approval_rows`] as the base tree serializes them.
    const BASE_ROWS: &[(&str, &str)] = &[
        (
            "attested",
            r#"{"ts":"2026-01-01T00:00:00.000Z","tool":"approval.attested","arg_keys":[],"policy_decision":"allow","request_id":"request","kind":"approval_attested","approval_kind":"PaymentSimulated","gated_tool":"stellar_pay_commit","envelope_sha256_hex":"abababababababababababababababababababababababababababababababab","nonce_prefix":"AAAAAAAA","origin":"serve","previous_entry_hash":""}"#,
        ),
        (
            "rejected",
            r#"{"ts":"2026-01-01T00:00:00.000Z","tool":"approval.rejected","arg_keys":[],"policy_decision":"allow","request_id":"request","kind":"approval_rejected","approval_kind":"PaymentSimulated","nonce_prefix":"AAAAAAAA","origin":"cli","previous_entry_hash":""}"#,
        ),
        (
            "attested_remote",
            r#"{"ts":"2026-01-01T00:00:00.000Z","tool":"approval.attested","arg_keys":[],"policy_decision":"allow","request_id":"request","kind":"approval_attested_remote","approval_kind":"PaymentSimulated","gated_tool":"stellar_pay_commit","envelope_sha256_hex":"abababababababababababababababababababababababababababababababab","nonce_prefix":"AAAAAAAA","operator_credential_id_redacted":"e265b6f5","previous_entry_hash":""}"#,
        ),
        (
            "rejected_remote",
            r#"{"ts":"2026-01-01T00:00:00.000Z","tool":"approval.rejected","arg_keys":[],"policy_decision":"allow","request_id":"request","kind":"approval_rejected_remote","approval_kind":"PaymentSimulated","nonce_prefix":"AAAAAAAA","operator_credential_id_redacted":"e265b6f5","previous_entry_hash":""}"#,
        ),
    ];

    #[test]
    fn unaffected_approval_outputs_keep_base_bytes() {
        let rows = existing_approval_rows();
        assert_eq!(rows.len(), BASE_ROWS.len());
        for ((label, row), (base_label, base)) in rows.iter().zip(BASE_ROWS) {
            assert_eq!((*label, row.as_str()), (*base_label, *base));
        }
    }

    /// A signed-origin fixture whose listener binds an OS-assigned port.
    fn signed_fixture() -> (Fixture, tempfile::TempDir) {
        use stellar_agent_core::approval::mainnet_fixtures::SIGNED_RP_ID;
        let files = tempfile::tempdir().unwrap();
        let leaf = stellar_agent_approval_remote::signed_origin_test_leaf(SIGNED_RP_ID);
        let cert = files.path().join("cert.pem");
        let key = files.path().join("key.pem");
        std::fs::write(&cert, leaf.chain_pem()).unwrap();
        std::fs::write(&key, &leaf.key_pem).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let remote = json!({
            "enabled":true,"bind":"127.0.0.1:0","rp_id":SIGNED_RP_ID,"cert_path":cert,"key_path":key
        });
        let mut core = MainnetConsentFixture::with_profile("revocation", |profile| {
            profile.remote_approval = Some(serde_json::from_value(remote).unwrap());
        });
        core.sign_signed_origin_policy(
            &[&stellar_agent_test_support::webauthn::fixture_authenticator()],
            &leaf.pin,
        );
        (Fixture::from_core(core), files)
    }

    #[test]
    #[serial_test::serial]
    fn consumed_revocation_enforces_the_selected_authority() {
        use stellar_agent_approval_ui::decision::{
            Decision, Outcome, RequestIdentity, apply_decision,
        };
        for signed in [false, true] {
            for consumed in [false, true] {
                let (mut f, _files) = if signed {
                    let (f, files) = signed_fixture();
                    (f, Some(files))
                } else {
                    (Fixture::new(), None)
                };
                let requester = if signed {
                    RequestIdentity::SignedOrigin(f.presence())
                } else {
                    RequestIdentity::Local
                };
                f.consent();
                if consumed {
                    f.store
                        .mint_authorization(f.core.profile(), &f.mint())
                        .unwrap();
                    PendingApprovalStore::open(f.core.store_path())
                        .unwrap()
                        .consume(
                            &f.entry.approval_nonce,
                            &"ab".repeat(32),
                            stellar_agent_core::approval::store::ConsumedOutcome::Confirmed,
                        )
                        .unwrap();
                }
                let bytes = f.bytes();
                let audit = std::fs::read(f.core.audit_path()).unwrap();
                assert!(!matches!(
                    apply_decision(
                        &f.context(),
                        Decision::Revoke {
                            nonce: f.entry.approval_nonce.clone()
                        },
                        requester
                    ),
                    Outcome::Revocation(_)
                ));
                assert_eq!(f.bytes(), bytes);
                assert_eq!(std::fs::read(f.core.audit_path()).unwrap(), audit);
                assert_eq!(
                    RevocationAccess::revoke(
                        &f.access(),
                        &f.entry.approval_nonce,
                        Surface::Cli,
                        None
                    )
                    .unwrap()
                    .state,
                    "revoked"
                );
            }
        }
        let mut f = Fixture::new();
        f.consent();
        let attempt =
            OperationRecorder::new(&f.store, f.core.profile(), &mut Rows::default(), "attempt")
                .begin_attempt(
                    &f.handle,
                    &AttemptRequest {
                        envelope: Some(AttemptEnvelope {
                            xdr: "AAAA".to_owned(),
                            unsigned_envelope_sha256: [1; 32],
                        }),
                        authorization: AttemptAuthorization::Mint(Box::new(f.mint())),
                        send_by_ms: u64::MAX,
                    },
                );
        assert!(attempt.is_ok(), "{attempt:?}");
        OperationRecorder::new(&f.store, f.core.profile(), &mut Rows::default(), "terminal")
            .transition(
                f.handle.id(),
                Some(1),
                stellar_agent_network::policy_state::operations::OperationState::NotSent,
                &Default::default(),
            )
            .unwrap();
        OperationRecorder::new(&f.store, f.core.profile(), &mut Rows::default(), "prune")
            .expire_due(f.entry.created_at_unix_ms)
            .unwrap();
        let view = f.view();
        assert!(view.record.closed_at_ms.is_some());
        assert!(!view.expired);
        let bytes = f.bytes();
        let audit = std::fs::read(f.core.audit_path()).unwrap();
        assert_eq!(
            RevocationAccess::revoke(&f.access(), &f.entry.approval_nonce, Surface::Cli, None)
                .unwrap(),
            project(&view)
        );
        assert_eq!(f.bytes(), bytes);
        assert_eq!(std::fs::read(f.core.audit_path()).unwrap(), audit);
        // An attested entry refuses before the adapter, even where the
        // durable record would answer with a no-op view.
        for durable in ["expired", "revoked"] {
            let mut f = Fixture::new();
            f.consent();
            if durable == "revoked" {
                RevocationAccess::revoke(&f.access(), &f.entry.approval_nonce, Surface::Cli, None)
                    .unwrap();
            } else {
                f.clock.set(
                    f.view()
                        .record
                        .consent
                        .as_ref()
                        .unwrap()
                        .execution_expires_at_ms,
                );
            }
            assert!(
                RevocationAccess::lookup(&f.access(), &f.entry.approval_nonce)
                    .unwrap()
                    .is_noop()
            );
            let bytes = f.bytes();
            let audit = std::fs::read(f.core.audit_path()).unwrap();
            let (context, access) = f.counted_context();
            let outcome = apply_decision(
                &context,
                Decision::Revoke {
                    nonce: f.entry.approval_nonce.clone(),
                },
                RequestIdentity::Local,
            );
            assert!(
                !matches!(
                    outcome,
                    Outcome::Revocation(_) | Outcome::RevocationRefused(_)
                ),
                "{durable}: {outcome:?}"
            );
            assert_eq!(
                access.calls.load(std::sync::atomic::Ordering::SeqCst),
                0,
                "{durable}"
            );
            drop(context);
            assert_eq!(f.bytes(), bytes);
            assert_eq!(std::fs::read(f.core.audit_path()).unwrap(), audit);
        }
    }

    #[test]
    #[serial_test::serial]
    fn revocation_entry_and_profile_binding_refuse_before_lookup() {
        use stellar_agent_approval_ui::decision::{
            Decision, Outcome, RequestIdentity, apply_decision,
        };
        for reason in ["identity", "expired", "absent", "rejected"] {
            let f = Fixture::new();
            let mut entry = f.core.payment(300_000);
            let nonce = entry.approval_nonce.clone();
            match reason {
                "identity" => entry.process_uid = "4294967294".to_owned(),
                "expired" => {
                    entry.created_at_unix_ms = 1;
                    entry.expires_at_unix_ms = 2;
                }
                _ => (),
            }
            let mut store = PendingApprovalStore::open(f.core.store_path()).unwrap();
            if reason != "absent" {
                store.insert(entry, 1).unwrap();
            }
            if reason == "rejected" {
                store
                    .reject(
                        &nonce,
                        stellar_agent_core::timefmt::now_unix_ms().unwrap(),
                        300_000,
                    )
                    .unwrap();
            }
            drop(store);
            let context = f.context();
            let bytes = f.bytes();
            let audit = std::fs::read(f.core.audit_path()).unwrap();
            let result =
                apply_decision(&context, Decision::Revoke { nonce }, RequestIdentity::Local);
            if reason == "identity" {
                assert!(matches!(result, Outcome::UserMismatch), "{result:?}");
            }
            assert!(
                !matches!(
                    result,
                    Outcome::Revocation(_) | Outcome::RevocationRefused(_)
                ),
                "{reason}: {result:?}"
            );
            assert_eq!(f.bytes(), bytes);
            assert_eq!(std::fs::read(f.core.audit_path()).unwrap(), audit);
        }
        let (f, _files) = signed_fixture();
        let presence = f.presence();
        let mut context = f.context();
        context.context.profile_name = "different-profile".to_owned();
        let bytes = f.bytes();
        assert!(!matches!(
            apply_decision(
                &context,
                Decision::Revoke {
                    nonce: f.entry.approval_nonce.clone()
                },
                RequestIdentity::SignedOrigin(presence)
            ),
            Outcome::Revocation(_)
        ));
        assert_eq!(f.bytes(), bytes);
    }

    #[test]
    #[serial_test::serial]
    fn inbox_revocation_without_listener_persists_through_the_facade() {
        use stellar_agent_approval_ui::decision::{
            Decision, Outcome, RequestIdentity, apply_decision,
        };
        for signed in [false, true] {
            let (f, _files) = if signed {
                let (f, files) = signed_fixture();
                (f, Some(files))
            } else {
                (Fixture::new(), None)
            };
            let context = f.context();
            let identity = if signed {
                RequestIdentity::SignedOrigin(f.presence())
            } else {
                RequestIdentity::Local
            };
            let bytes = std::fs::read(f.core.store_path()).unwrap();
            let sections = f.unchanged_sections();
            let outcome = apply_decision(
                &context,
                Decision::Revoke {
                    nonce: f.entry.approval_nonce.clone(),
                },
                identity,
            );
            let Outcome::Revocation(view) = outcome else {
                panic!("revoked view: {outcome:?}")
            };
            assert_eq!(view.state, "revoked");
            assert_eq!(f.view().record.state, ApprovalState::Revoked);
            assert_eq!(std::fs::read(f.core.store_path()).unwrap(), bytes);
            assert_eq!(f.unchanged_sections(), sections);
            let audit = std::fs::read_to_string(f.core.audit_path()).unwrap();
            let row: Value = serde_json::from_str(audit.lines().last().unwrap()).unwrap();
            assert_eq!(row["kind"], "approval_revoked");
            assert_eq!(row["approval_kind"], KIND);
            assert_eq!(row["origin"], if signed { "serve-remote" } else { "serve" });
            assert_eq!(row.get("operator_credential_id_redacted").is_some(), signed);
            assert!(!audit.contains(&f.entry.approval_nonce));
        }
    }

    enum Listener {
        Local(stellar_agent_approval_ui::ServeHandle),
        Signed(stellar_agent_approval_remote::RemoteServeHandle),
    }
    impl Listener {
        async fn shutdown(self) {
            match self {
                Self::Local(handle) => handle.shutdown().await.unwrap(),
                Self::Signed(handle) => handle.shutdown().await.unwrap(),
            }
        }
    }

    struct Browser {
        client: reqwest::Client,
        address: String,
        origin: String,
        cookie: String,
        proof: Option<String>,
    }
    fn island(html: &str, id: &str) -> Value {
        let text = html.split(&format!("id=\"{id}\"")).nth(1).unwrap();
        serde_json::from_str(
            text.split_once('>')
                .unwrap()
                .1
                .split("</script>")
                .next()
                .unwrap(),
        )
        .unwrap()
    }
    impl Browser {
        fn new() -> Self {
            Self {
                client: reqwest::Client::builder()
                    .no_proxy()
                    .danger_accept_invalid_certs(true)
                    .redirect(reqwest::redirect::Policy::none())
                    // Every request ends within the bound, so a silent listener fails the test.
                    .timeout(std::time::Duration::from_secs(10))
                    .build()
                    .unwrap(),
                address: String::new(),
                origin: String::new(),
                cookie: String::new(),
                proof: None,
            }
        }
        /// Logs in with the fixture passkey at the signed listener on `address`.
        ///
        /// Requests carry the signed canonical origin, never the listener's
        /// own report of it.
        async fn login_signed(&mut self, address: std::net::SocketAddr) {
            self.address = format!("https://{address}");
            self.origin = stellar_agent_core::approval::mainnet_fixtures::SIGNED_ORIGIN.to_owned();
            let options: Value = self
                .request("POST", "/login/challenge")
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            let assertion = self.signed_assertion(
                &options,
                0,
                stellar_agent_core::approval::mainnet_fixtures::SIGNED_RP_ID,
            );
            let body = json!({"assertion":{"id":assertion["credential_id_b64url"],"response":{
                "authenticator_data":assertion["authenticator_data_b64url"],"client_data_json":assertion["client_data_json_b64url"],"signature":assertion["signature_der_b64url"]}}});
            let response = self
                .request("POST", "/login/assertion")
                .json(&body)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), 200);
            self.cookie = response.headers()["set-cookie"]
                .to_str()
                .unwrap()
                .split(';')
                .next()
                .unwrap()
                .to_owned();
        }
        async fn start(f: &Fixture, signed: bool) -> (Listener, Self) {
            let mut browser = Self::new();
            if signed {
                let profile = f.core.authority().load_current().unwrap().profile().clone();
                let remote = profile.remote_approval.as_ref().unwrap();
                let config = stellar_agent_approval_remote::RemoteServeConfig::from_profile(
                    remote.bind.parse().unwrap(),
                    remote,
                    stellar_agent_core::approval::RemoteApprovalAuthority::for_profile(
                        f.core.name(),
                    )
                    .unwrap(),
                    f.context(),
                )
                .await
                .unwrap();
                let handle = stellar_agent_approval_remote::start_remote_serve(config)
                    .await
                    .unwrap();
                browser.login_signed(handle.local_addr()).await;
                (Listener::Signed(handle), browser)
            } else {
                let (sender, _) = tokio::sync::mpsc::unbounded_channel();
                let handle = stellar_agent_approval_ui::start_serve(
                    stellar_agent_approval_ui::ServeConfig::new(
                        "127.0.0.1:0".parse().unwrap(),
                        f.context(),
                        sender,
                        false,
                    ),
                )
                .await
                .unwrap();
                browser.address = format!("http://{}", handle.local_addr());
                browser.origin = format!("http://localhost:{}", handle.local_addr().port());
                let response = browser
                    .request(
                        "GET",
                        &format!("/bootstrap/{}", handle.bootstrap_token_hex()),
                    )
                    .send()
                    .await
                    .unwrap();
                assert_eq!(response.status(), 200);
                browser.cookie = response.headers()["set-cookie"]
                    .to_str()
                    .unwrap()
                    .split(';')
                    .next()
                    .unwrap()
                    .to_owned();
                browser.proof = Some(
                    island(&response.text().await.unwrap(), "session-bootstrap-data")["proof"]
                        .as_str()
                        .unwrap()
                        .to_owned(),
                );
                (Listener::Local(handle), browser)
            }
        }
        fn request(&self, method: &str, path: &str) -> reqwest::RequestBuilder {
            self.client
                .request(method.parse().unwrap(), format!("{}{path}", self.address))
                .header("host", self.origin.split_once("://").unwrap().1)
                .header("origin", &self.origin)
                .header("cookie", &self.cookie)
        }
        async fn page(&self, nonce: &str) -> String {
            let response = self
                .request("GET", &format!("/approval/{nonce}"))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), 200);
            response.text().await.unwrap()
        }
        fn action(
            &self,
            nonce: &str,
            csrf: &str,
            action: &str,
            body: &Value,
        ) -> reqwest::RequestBuilder {
            let request = self
                .request("POST", &format!("/approval/{nonce}/{action}"))
                .header("x-stellar-approval-csrf", csrf)
                .json(body);
            match &self.proof {
                Some(proof) => request.header("x-session-proof", proof),
                None => request,
            }
        }
        fn signed_assertion(&self, options: &Value, count: u32, rp: &str) -> Value {
            let proof = stellar_agent_test_support::webauthn::fixture_authenticator().assert(
                B64.decode(options["challenge"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap(),
                &self.origin,
                rp,
                5,
                count,
            );
            json!({"request_id":options["request_id"],"credential_id_b64url":B64.encode(proof.credential_id),
                "authenticator_data_b64url":B64.encode(proof.authenticator_data),"client_data_json_b64url":B64.encode(proof.client_data_json),"signature_der_b64url":B64.encode(proof.signature_der)})
        }
        async fn assertion(&self, nonce: &str, count: u32, rp: &str) -> (String, Value) {
            let page = island(&self.page(nonce).await, "presence-data");
            let csrf = page["csrf"].as_str().unwrap().to_owned();
            let response = self
                .action(
                    nonce,
                    &csrf,
                    "challenge",
                    &json!({"consent_view_digest":page["consent_view_digest"]}),
                )
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), 200);
            let options: Value = response.json().await.unwrap();
            assert_eq!(
                options["rp_id"],
                stellar_agent_core::approval::mainnet_fixtures::SIGNED_RP_ID
            );
            (csrf, self.signed_assertion(&options, count, rp))
        }
        async fn revoke(&self, nonce: &str) -> reqwest::Response {
            let (csrf, body) = if self.proof.is_some() {
                (
                    island(&self.page(nonce).await, "revoke-data")["csrf"]
                        .as_str()
                        .unwrap()
                        .to_owned(),
                    json!({}),
                )
            } else {
                self.assertion(
                    nonce,
                    0,
                    stellar_agent_core::approval::mainnet_fixtures::SIGNED_RP_ID,
                )
                .await
            };
            self.action(nonce, &csrf, "revoke", &body)
                .send()
                .await
                .unwrap()
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn inbox_revocation_persists_through_the_facade() {
        use stellar_agent_core::approval::mainnet_fixtures::SIGNED_ORIGIN;
        // The child process runs `approve serve --remote` itself.
        let Some((stdout, _)) = crate::common::test_support::capture_within(
            "commands::approve::revoke::tests::inbox_revocation_persists_through_the_facade",
            std::time::Duration::from_secs(60),
        ) else {
            return serve_run_revokes().await;
        };
        assert!(
            stdout.contains(&format!("Remote approval inbox: {SIGNED_ORIGIN}/")),
            "{stdout}"
        );
        for signed in [false, true] {
            let (f, _files) = if signed {
                let (f, files) = signed_fixture();
                (f, Some(files))
            } else {
                (Fixture::new(), None)
            };
            let inbox = std::fs::read(f.core.store_path()).unwrap();
            let sections = f.unchanged_sections();
            let (listener, browser) = Browser::start(&f, signed).await;
            let response = browser.revoke(&f.entry.approval_nonce).await;
            assert_eq!(response.status(), 200);
            let body: Value = response.json().await.unwrap();
            assert_eq!(body["view"]["state"], "revoked");
            assert_eq!(f.view().record.state, ApprovalState::Revoked);
            assert_eq!(f.unchanged_sections(), sections);
            assert_eq!(std::fs::read(f.core.store_path()).unwrap(), inbox);
            assert!(matches!(
                f.store.mint_authorization(f.core.profile(), &f.mint()),
                Err(WindowStoreError::AuthorizationRefused {
                    precondition: MainnetPrecondition::ApprovalRevoked
                })
            ));
            listener.shutdown().await;
        }
    }

    /// Revokes through the listener that `serve::run` starts and installs.
    async fn serve_run_revokes() {
        let (f, _files) = signed_fixture();
        mint_audit_key(f.core.name()).await;
        let parsed = Command::try_parse_from([
            "approve",
            "serve",
            "--remote",
            "--confirm-remote-exposure",
            "--profile",
            f.core.name(),
        ])
        .unwrap();
        let Some(super::super::ApproveSubcommand::Serve(args)) = parsed.args.subcommand else {
            panic!("serve arguments")
        };
        // The listener binds port 0; its bound address comes from the test seam.
        let browser = async {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            let address = loop {
                if let Some(address) = crate::common::mainnet_presence::bound_listener::take() {
                    break address;
                }
                assert!(std::time::Instant::now() < deadline, "serve binds");
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            };
            let mut browser = Browser::new();
            browser.login_signed(address).await;
            let response = browser.revoke(&f.entry.approval_nonce).await;
            assert_eq!(response.status(), 200);
            let body: Value = response.json().await.unwrap();
            assert_eq!(body["view"]["state"], "revoked");
        };
        tokio::select! {
            exit = super::super::serve::run(args) => panic!("serve exits with {exit}"),
            () = browser => {}
        }
        assert_eq!(f.view().record.state, ApprovalState::Revoked);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn revocation_control_matches_record_eligibility() {
        for signed in [false, true] {
            let (f, _files) = if signed {
                let (f, files) = signed_fixture();
                (f, Some(files))
            } else {
                (Fixture::new(), None)
            };
            let (listener, browser) = Browser::start(&f, signed).await;
            let html = browser.page(&f.entry.approval_nonce).await;
            for marker in [
                "id=\"revoke-btn\"",
                "id=\"revoke-data\"",
                "/static/revoke.js",
                "/static/revoke.css",
            ] {
                assert!(html.contains(marker), "{marker}");
            }
            assert_eq!(
                island(&html, "revoke-data")["nonce"],
                f.entry.approval_nonce
            );
            for (path, source) in [
                (
                    "/static/revoke.js",
                    include_str!("../../../../stellar-agent-approval-ui/src/web/revoke.js"),
                ),
                (
                    "/static/revoke.css",
                    include_str!("../../../../stellar-agent-approval-ui/src/web/revoke.css"),
                ),
            ] {
                let response = browser.request("GET", path).send().await.unwrap();
                assert_eq!(response.status(), 200);
                assert_eq!(response.text().await.unwrap(), source);
            }
            let response = browser.revoke(&f.entry.approval_nonce).await;
            assert_eq!(response.status(), 200);
            assert_eq!(f.view().record.state, ApprovalState::Revoked);
            assert!(
                !browser
                    .page(&f.entry.approval_nonce)
                    .await
                    .contains("revoke-data")
            );
            listener.shutdown().await;
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn revocation_authentication_matrix() {
        for signed in [false, true] {
            let (f, _files) = if signed {
                let (f, files) = signed_fixture();
                (f, Some(files))
            } else {
                (Fixture::new(), None)
            };
            let (listener, browser) = Browser::start(&f, signed).await;
            let nonce = &f.entry.approval_nonce;
            let csrf = island(&browser.page(nonce).await, "revoke-data")["csrf"]
                .as_str()
                .unwrap()
                .to_owned();
            let before = f.bytes();
            let audit = std::fs::read(f.core.audit_path()).unwrap();
            for header in ["cookie", "x-stellar-approval-csrf", "x-session-proof"] {
                if signed && header == "x-session-proof" {
                    continue;
                }
                for value in [None, Some("invalid")] {
                    let (csrf, assertion) = if signed {
                        browser
                            .assertion(
                                nonce,
                                0,
                                stellar_agent_core::approval::mainnet_fixtures::SIGNED_RP_ID,
                            )
                            .await
                    } else {
                        (csrf.clone(), json!({}))
                    };
                    let mut request = browser
                        .action(nonce, &csrf, "revoke", &assertion)
                        .build()
                        .unwrap();
                    request.headers_mut().remove(header);
                    if let Some(value) = value {
                        request.headers_mut().insert(header, value.parse().unwrap());
                    }
                    assert!(
                        !browser
                            .client
                            .execute(request)
                            .await
                            .unwrap()
                            .status()
                            .is_success(),
                        "{signed}/{header}/{value:?}"
                    );
                    assert_eq!(f.bytes(), before);
                    assert_eq!(std::fs::read(f.core.audit_path()).unwrap(), audit);
                }
            }
            if signed {
                assert!(
                    !browser
                        .action(nonce, &csrf, "revoke", &json!({}))
                        .send()
                        .await
                        .unwrap()
                        .status()
                        .is_success()
                );
                let (csrf, body) = browser
                    .assertion(
                        nonce,
                        0,
                        stellar_agent_core::approval::mainnet_fixtures::SIGNED_RP_ID,
                    )
                    .await;
                assert!(
                    !browser
                        .action("another-nonce", &csrf, "revoke", &body)
                        .send()
                        .await
                        .unwrap()
                        .status()
                        .is_success()
                );
                assert_eq!(f.bytes(), before);
                assert_eq!(
                    browser
                        .action(nonce, &csrf, "revoke", &body)
                        .send()
                        .await
                        .unwrap()
                        .status(),
                    200
                );
                let after = f.bytes();
                assert!(
                    !browser
                        .action(nonce, &csrf, "revoke", &body)
                        .send()
                        .await
                        .unwrap()
                        .status()
                        .is_success()
                );
                assert_eq!(f.bytes(), after);
            }
            listener.shutdown().await;
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn signed_revocation_keeps_origin_policy_and_counter_checks() {
        use stellar_agent_core::approval::mainnet_fixtures::SIGNED_RP_ID;
        let (mut f, _files) = signed_fixture();
        let (listener, browser) = Browser::start(&f, true).await;
        let nonce = f.entry.approval_nonce.clone();
        let before = f.bytes();
        for header in ["host", "origin"] {
            for value in [
                None,
                Some("https://untrusted.example.invalid"),
                Some("approve.example.invalid"),
            ] {
                let (csrf, assertion) = browser.assertion(&nonce, 0, SIGNED_RP_ID).await;
                let mut request = browser
                    .action(&nonce, &csrf, "revoke", &assertion)
                    .build()
                    .unwrap();
                request.headers_mut().remove(header);
                if let Some(value) = value {
                    request.headers_mut().insert(header, value.parse().unwrap());
                }
                assert!(
                    !browser
                        .client
                        .execute(request)
                        .await
                        .unwrap()
                        .status()
                        .is_success()
                );
                assert_eq!(f.bytes(), before);
            }
        }
        let (csrf, body) = browser.assertion(&nonce, 0, "wrong.example.invalid").await;
        assert!(
            !browser
                .action(&nonce, &csrf, "revoke", &body)
                .send()
                .await
                .unwrap()
                .status()
                .is_success()
        );
        assert_eq!(f.bytes(), before);
        let credentials =
            stellar_agent_core::approval::RemoteApprovalAuthority::for_profile(f.core.name())
                .unwrap()
                .credentials_path()
                .to_owned();
        for (count, accepted) in [
            (0, true),
            (0, true),
            (2, true),
            (2, false),
            (1, false),
            (0, false),
            (3, true),
        ] {
            let (csrf, body) = browser.assertion(&nonce, count, SIGNED_RP_ID).await;
            let bytes = std::fs::read(&credentials).unwrap();
            let response = browser
                .action(&nonce, &csrf, "revoke", &body)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status().is_success(), accepted, "counter {count}");
            let after = std::fs::read(&credentials).unwrap();
            if !accepted {
                assert_eq!(after, bytes);
            }
            assert!(
                !browser
                    .action(&nonce, &csrf, "revoke", &body)
                    .send()
                    .await
                    .unwrap()
                    .status()
                    .is_success()
            );
            assert_eq!(std::fs::read(&credentials).unwrap(), after);
        }
        // A second entry holds the other outstanding challenge. Both
        // assertions verify under the policy the listener holds.
        let second = f.core.payment(300_000);
        PendingApprovalStore::open(f.core.store_path())
            .unwrap()
            .insert(second.clone(), second.created_at_unix_ms)
            .unwrap();
        // Its own durable record makes the removal refusal a policy refusal,
        // not a missing record.
        open_record(&f.store, f.core.profile(), &second, "revocation-second");
        let (stale_csrf, stale) = browser.assertion(&nonce, 4, SIGNED_RP_ID).await;
        let (removed_csrf, removed) = browser
            .assertion(&second.approval_nonce, 5, SIGNED_RP_ID)
            .await;
        let fixture = stellar_agent_test_support::webauthn::fixture_authenticator();
        let other = stellar_agent_test_support::webauthn::TestAuthenticator::from_seed(
            [7; 32],
            vec![7; 16],
        );
        let bytes = f.bytes();
        // A new pin and digest leave the listener stale; the credential stays current.
        f.core
            .sign_signed_origin_policy(&[&fixture, &other], &[9; 32]);
        let response = browser
            .action(&nonce, &stale_csrf, "revoke", &stale)
            .send()
            .await
            .unwrap();
        assert!(!response.status().is_success(), "stale listener");
        assert_eq!(f.bytes(), bytes);
        // The policy then names only the other credential.
        f.core.sign_signed_origin_policy(&[&other], &[9; 32]);
        let response = browser
            .action(&second.approval_nonce, &removed_csrf, "revoke", &removed)
            .send()
            .await
            .unwrap();
        // A session whose credential the current policy omits fails
        // authentication, so the refusal precedes the durable lookup; a
        // missing record answers 409 with `approval.not_found`.
        let status = response.status();
        let refusal = response.text().await.unwrap();
        assert_eq!((status.as_u16(), refusal.as_str()), (404, ""));
        assert_eq!(f.bytes(), bytes);
        assert_eq!(
            ApprovalStatus::new(&f.store, f.core.profile())
                .find_by_nonce(&second.approval_nonce)
                .unwrap()
                .unwrap()
                .record
                .state,
            ApprovalState::Pending
        );
        listener.shutdown().await;
    }

    /// The link formatter yields the signed origin's token-free page link,
    /// and the served link redirects to that page alone.
    ///
    /// The ceremony prints through `eprintln!` with no capturable writer;
    /// `cli/tests/cli/mainnet_presence.rs:753` guards the printed line.
    #[tokio::test]
    #[serial_test::serial]
    async fn revocation_link_formatter_and_served_location_use_the_signed_origin() {
        let (f, _files) = signed_fixture();
        let (listener, browser) = Browser::start(&f, true).await;
        let Listener::Signed(handle) = &listener else {
            panic!("signed listener")
        };
        use stellar_agent_core::approval::mainnet_fixtures::SIGNED_ORIGIN;
        let nonce = &f.entry.approval_nonce;
        // The line the ceremony prints, from the listener's public origin.
        let link =
            crate::common::mainnet_presence::signed_approval_link(handle.public_origin(), nonce);
        assert_eq!(link, format!("{SIGNED_ORIGIN}/approvals/{nonce}"));
        assert!(!link.contains(&handle.local_addr().to_string()));
        assert!(!link.contains('?'));
        // The served link names the selected page alone, whatever forwarding
        // headers the request carries.
        let path = link.strip_prefix(SIGNED_ORIGIN).unwrap();
        for forwarded in [None, Some("untrusted.example.invalid")] {
            let mut request = browser.request("GET", path);
            if let Some(host) = forwarded {
                request = request
                    .header("x-forwarded-host", host)
                    .header("forwarded", format!("host={host}"));
            }
            let response = request.send().await.unwrap();
            assert_eq!(response.status(), 307);
            assert_eq!(
                response.headers()["location"].to_str().unwrap(),
                format!("/approval/{nonce}")
            );
        }
        listener.shutdown().await;
    }

    #[test]
    #[serial_test::serial]
    fn revocation_status_is_revoked_and_read_only() {
        let f = Fixture::new();
        let access = f.access();
        RevocationAccess::revoke(&access, &f.entry.approval_nonce, Surface::Cli, None).unwrap();
        f.clock.set(f.entry.expires_at_unix_ms);
        let bytes = f.bytes();
        let audit = std::fs::read(f.core.audit_path()).unwrap();
        for _ in 0..3 {
            let view = RevocationAccess::lookup(&access, &f.entry.approval_nonce).unwrap();
            assert_eq!(view.state, "revoked");
            assert!(view.expired);
            assert_eq!(f.bytes(), bytes);
            assert_eq!(std::fs::read(f.core.audit_path()).unwrap(), audit);
        }
    }

    #[test]
    #[serial_test::serial]
    fn revocation_results_expose_no_consent_payload() {
        let mut f = Fixture::new();
        f.consent();
        let access = f.access();
        let before = f.view();
        let payload = before.record.consent.unwrap().payload.unwrap();
        let view =
            RevocationAccess::revoke(&access, &f.entry.approval_nonce, Surface::Cli, None).unwrap();
        let mut hostile = view.clone();
        hostile.state = "pending\nforged\u{1b}[31m".to_owned();
        let escaped = render_view(&hostile);
        assert_eq!(escaped.lines().count(), 7);
        assert!(!escaped.contains('\u{1b}'));
        let output = format!(
            "{}{}{}",
            serde_json::to_string(&view).unwrap(),
            render_view(&view),
            std::fs::read_to_string(f.core.audit_path())
                .unwrap()
                .lines()
                .last()
                .unwrap()
        );
        for secret in [
            B64.encode(payload.attestation),
            payload.receipt.credential_id_b64url(),
            f.entry.approval_nonce.clone(),
        ] {
            assert!(!output.contains(&secret));
        }
        let keys: Vec<_> = serde_json::to_value(view)
            .unwrap()
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        assert_eq!(
            keys,
            [
                "closed_at_ms",
                "consent_at_ms",
                "execution_expires_at_ms",
                "expired",
                "revoked_at_ms",
                "state",
                "waiting_expires_at_ms"
            ]
        );
    }
}
