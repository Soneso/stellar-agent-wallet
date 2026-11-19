//! The business-id entry of the value tools.
//!
//! A mainnet value call names itself with a business id. The preparation
//! looks the id up before it builds anything. A retained operation answers
//! with its stored state, and a waiting record answers with its stored
//! envelope. An unknown id builds and opens a record. The commit looks the
//! id up before its gates and continues the record its preparation opened.
//! Off mainnet a supplied id is validated and echoed, and no record exists.

use rmcp::model::{CallToolResult, Content};
use serde_json::Value;
use stellar_agent_core::approval::{
    ApprovalError, ApprovalKind, PendingApproval, PendingApprovalStore,
    attest::record_error,
    retry::{DEFAULT_RETRY_ATTEMPTS, DEFAULT_RETRY_BACKOFF, open_with_retry},
    witness::ApprovedKind,
};
use stellar_agent_core::audit_log::{AuditOutbox, PolicyDecision};
use stellar_agent_core::error::{ApprovalFailure, InternalError, SubmissionError, WalletError};
use stellar_agent_core::mainnet::verified_policy::VerifiedPolicy;
use stellar_agent_network::fees::ClassicFeeChoice;
use stellar_agent_network::mainnet::MainnetConsumer;
use stellar_agent_network::operation_entry::{
    self, ClassicEntry, CommitEntry, CommitPreview, ConsentAdmission, EnvelopeFacts, IdentityFacts,
    IntentBaseFacts, OpenedEntry, Preparation,
};
use stellar_agent_network::policy_state::{
    ApprovalRecorder, ApprovalState, ApprovalStatus, ApprovalView, BusinessId, OperationHandle,
    OperationId, OperationKind, OperationRecorder, OperationState, OperationTool,
    approvals::PendingApprovalFacts,
};

use crate::server::WalletServer;

/// A classic preparation under a business id.
#[derive(Debug)]
pub(crate) struct ClassicOperation {
    business_id: BusinessId,
    /// The binding the record opens with. A canonical preparation learns its
    /// payload and decision only after the account reads and the policy
    /// gate, so [`WalletServer::stage_canonical`] sets it before the open.
    preparation: Option<Preparation>,
    /// The base facts a canonical lookup took, which the staged intent
    /// keeps.
    canonical: Option<CanonicalBase>,
    resume: Option<OperationHandle>,
}

/// The source, fee choice and memo of a canonical preparation, with the
/// digest and signed fee cap of the policy its admission verified.
#[derive(Debug)]
struct CanonicalBase {
    source: String,
    fee_choice: ClassicFeeChoice,
    memo: stellar_agent_core::approval::MemoFact,
    policy_digest: [u8; 32],
    signed_fee_cap: Option<u32>,
}

/// The envelope, protocol nonce and nonce expiry a classic commit presents,
/// each `None` when the call omits it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct EnvelopeFields<'a> {
    pub(crate) envelope_xdr: Option<&'a str>,
    pub(crate) nonce: Option<&'a str>,
    pub(crate) expires_at_unix_ms: Option<u64>,
}

/// How a classic commit proceeds; see [`WalletServer::commit_route`].
pub(crate) enum CommitRoute<'a, 'g> {
    /// The id names a canonical record on mainnet.
    Canonical(&'a crate::server::MainnetWriteGuard<'g>, BusinessId),
    /// The envelope route, with the fields the call presents.
    Envelope {
        envelope_xdr: &'a str,
        nonce: &'a str,
        expires_at_unix_ms: u64,
    },
    /// The call's whole answer.
    Answer(CallToolResult),
}

/// The envelope a classic preparation returns under its business id.
#[derive(Debug)]
pub(crate) struct PreparedEnvelope {
    /// The unsigned envelope in base64.
    pub xdr: String,
    /// The facts read from a stored envelope; `None` for the envelope the
    /// call just built, whose facts the call computed itself.
    pub stored: Option<EnvelopeFacts>,
    /// The retained operation's waiting deadline, when an operation exists.
    pub waiting_end: Option<u64>,
    /// The ID of the winning retained operation.
    pub operation_id: Option<[u8; 16]>,
    /// The retained operation that owns this envelope and its approval.
    pub handle: Option<OperationHandle>,
}

impl ClassicOperation {
    /// The envelope a waiting record holds, which the preparation returns
    /// in place of a new build.
    pub(crate) fn stored_envelope(&self) -> Option<&str> {
        self.resume.as_ref().and_then(OperationHandle::envelope_xdr)
    }

    /// Whether the record this preparation opens holds a canonical intent.
    pub(crate) fn stages_canonical(&self) -> bool {
        matches!(self.preparation, Some(Preparation::Canonical { .. }))
    }
}

/// The successful answer to a call under a retained business id.
pub(crate) fn replay_result(
    view: &stellar_agent_network::policy_state::OperationView,
) -> CallToolResult {
    let envelope = stellar_agent_core::envelope::Envelope::ok(operation_entry::replay_json(view));
    let json = envelope
        .to_json_pretty()
        .unwrap_or_else(|_| String::from("{}"));
    CallToolResult::success(vec![Content::text(json)])
}

/// Adds `business_id` to a result's data when the call names one, on every
/// network; without an id the data stays as it is.
pub(crate) fn echo_business_id(view: &mut Value, business_id: Option<&BusinessId>) {
    if let Some(business_id) = business_id {
        view["business_id"] = Value::String(business_id.as_str().to_owned());
    }
}

/// The refusal result of a wallet error.
fn refusal(error: &WalletError) -> CallToolResult {
    crate::tools::common::ledger_err_result(error)
}

fn approval_io(error: std::io::Error) -> WalletError {
    record_error(&ApprovalError::Io {
        kind: error.kind(),
        source: error,
    })
}

/// Serializes orphan cleanup and record opening across producer processes.
/// The guard precedes the inbox, audit mutex and window locks. Consent paths
/// never acquire it, so they can release the inbox while a producer waits.
fn producer_lock(
    path: &std::path::Path,
) -> Result<stellar_agent_core::file_lock::HeldFileLock, WalletError> {
    let mut options = std::fs::OpenOptions::new();
    options.create(true).read(true).write(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let attempts = DEFAULT_RETRY_ATTEMPTS.max(1);
    let mut attempt = 0_u32;
    loop {
        attempt += 1;
        let file = options.open(path).map_err(approval_io)?;
        match stellar_agent_core::file_lock::HeldFileLock::try_lock(file) {
            Ok(guard) => return Ok(guard),
            Err(std::fs::TryLockError::WouldBlock) if attempt < attempts => {
                std::thread::sleep(DEFAULT_RETRY_BACKOFF);
            }
            Err(std::fs::TryLockError::WouldBlock) => {
                return Err(WalletError::Approval(ApprovalFailure::WriterLocked {
                    detail:
                        "another preparation is opening an approval; retry the same business id"
                            .to_owned(),
                }));
            }
            Err(std::fs::TryLockError::Error(error)) => return Err(approval_io(error)),
        }
    }
}

fn open_inbox(path: &std::path::Path) -> Result<PendingApprovalStore, WalletError> {
    open_with_retry(path, DEFAULT_RETRY_ATTEMPTS, DEFAULT_RETRY_BACKOFF)
        .map_err(|error| record_error(&error))
}

fn linked_entry(path: &std::path::Path, nonce: &str) -> Result<PendingApproval, WalletError> {
    linked_entry_in(&open_inbox(path)?, nonce)
}

fn linked_entry_in(
    inbox: &PendingApprovalStore,
    nonce: &str,
) -> Result<PendingApproval, WalletError> {
    inbox.get(nonce).cloned().ok_or_else(|| {
        WalletError::Approval(ApprovalFailure::NotFound {
            detail: "the operation's approval entry is gone; prepare the operation again"
                .to_owned(),
        })
    })
}

/// Removes live unattested entries of this intent only when authenticated
/// status proves that no durable record names their nonce.
fn remove_orphans(
    store: &mut PendingApprovalStore,
    status: &ApprovalStatus<'_>,
    handle: &OperationHandle,
) -> Result<(), WalletError> {
    let envelope = handle
        .envelope_xdr()
        .map(operation_entry::unsigned_envelope_sha256)
        .map(|digest| stellar_agent_core::hex::encode(&digest));
    let now = stellar_agent_core::timefmt::now_unix_ms().map_err(|error| {
        WalletError::Approval(ApprovalFailure::ClockError {
            detail: error.to_string(),
        })
    })?;
    for view in store.snapshot(now) {
        let Some(stored) = store.get(&view.approval_nonce) else {
            continue;
        };
        let matches = match &stored.kind {
            ApprovalKind::PaymentSimulated {
                envelope_sha256_hex,
                ..
            }
            | ApprovalKind::ClaimSimulated {
                envelope_sha256_hex,
                ..
            }
            | ApprovalKind::TrustlineSimulated {
                envelope_sha256_hex,
                ..
            } => envelope.as_ref() == Some(envelope_sha256_hex),
            ApprovalKind::X402Payment { intent_digest, .. } => {
                *intent_digest == handle.intent().intent_digest()
            }
            _ => false,
        };
        if view.expired
            || stored.attestation_blob_b64.is_some()
            || !matches
            || status
                .find_by_nonce(&view.approval_nonce)
                .map_err(operation_entry::operation_refusal)?
                .is_some()
        {
            continue;
        }
        store
            .remove(&view.approval_nonce)
            .map_err(|error| record_error(&error))?;
    }
    Ok(())
}

/// How a durable producer treats an inbox entry that no durable record names.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Unlinked {
    /// The entry is an orphan: live unattested entries of the operation are
    /// removed before insertion, and after a refused open without a record.
    Replace,
    /// The entry is recoverable work under its recovery binding. It stays
    /// whenever the open's outcome is unresolved, and the entry the producer
    /// returns passes the linked check after its open.
    Recover,
}

/// The inbox write of a durable producer: the entry it builds and how the
/// inbox stores it.
pub(crate) trait InboxWrite {
    /// The producer's inbox refusal.
    type Error;

    /// Builds the entry without storing it. `intent` is the operation's
    /// validated stored canonical intent, when it has one.
    fn build(
        &self,
        intent: Option<&stellar_agent_core::approval::ClassicIntent>,
    ) -> Result<PendingApproval, Self::Error>;

    /// Stores `entry`, which [`Self::build`] returned.
    fn insert(self, entry: PendingApproval) -> Result<PendingApproval, Self::Error>;

    /// Builds and stores the entry: the write of a producer whose consent is
    /// not published.
    fn persist(
        self,
        intent: Option<&stellar_agent_core::approval::ClassicIntent>,
    ) -> Result<PendingApproval, Self::Error>
    where
        Self: Sized,
    {
        let entry = self.build(intent)?;
        self.insert(entry)
    }
}

/// An [`InboxWrite`] from its build and insert steps.
pub(crate) struct Staged<B, I> {
    /// Builds the entry.
    pub(crate) build: B,
    /// Stores the built entry.
    pub(crate) insert: I,
}

impl<B, I, E> InboxWrite for Staged<B, I>
where
    B: Fn(Option<&stellar_agent_core::approval::ClassicIntent>) -> Result<PendingApproval, E>,
    I: FnOnce(PendingApproval) -> Result<PendingApproval, E>,
{
    type Error = E;

    fn build(
        &self,
        intent: Option<&stellar_agent_core::approval::ClassicIntent>,
    ) -> Result<PendingApproval, E> {
        (self.build)(intent)
    }

    fn insert(self, entry: PendingApproval) -> Result<PendingApproval, E> {
        (self.insert)(entry)
    }
}

/// Pre-insert inbox failures keep the insertion protocol's error channel.
enum ProducerError {
    Inbox(ApprovalError),
    Durable(WalletError),
}

impl From<WalletError> for ProducerError {
    fn from(error: WalletError) -> Self {
        Self::Durable(error)
    }
}

impl WalletServer {
    /// Reuses or opens the durable approval for an x402 operation.
    #[cfg(feature = "mainnet-write")]
    pub(crate) fn x402_pending_approval(
        &self,
        handle: Option<&OperationHandle>,
        decision: PolicyDecision,
        write: impl InboxWrite<Error = WalletError>,
    ) -> Result<PendingApproval, WalletError> {
        self.start_approval(
            handle,
            ApprovedKind::X402Payment,
            decision,
            Unlinked::Replace,
            |path, view, _| linked_entry(path, &view.record.nonce).map(Ok),
            write,
        )
        .map_err(|error| match error {
            ProducerError::Inbox(error) => record_error(&error),
            ProducerError::Durable(error) => error,
        })?
    }

    /// Reuses the linked approval or persists and opens it for `handle`.
    /// Inbox insertion retains the tool's protocol-error format. Durable
    /// recorder refusals use the wallet error envelope.
    pub(crate) fn classic_pending_approval(
        &self,
        handle: Option<&OperationHandle>,
        kind: ApprovedKind,
        decision: PolicyDecision,
        write: impl InboxWrite<Error = String>,
    ) -> Result<PendingApproval, crate::tools::common::ToolError> {
        use crate::tools::common::ToolError;
        self.start_approval(
            handle,
            kind,
            decision,
            Unlinked::Replace,
            |path, view, _| linked_entry(path, &view.record.nonce).map(Ok),
            write,
        )
        .map_err(|error| match error {
            ProducerError::Inbox(error) => ToolError::Protocol(rmcp::ErrorData::internal_error(
                format!("approval.store_error: {error}"),
                None,
            )),
            ProducerError::Durable(error) => ToolError::Business(refusal(&error)),
        })?
        .map_err(|error| {
            ToolError::Protocol(rmcp::ErrorData::internal_error(
                format!("approval.store_error: {error}"),
                None,
            ))
        })
    }

    /// Reuses the linked payment approval, or recovers the entry that
    /// `persist` names and opens its durable record for `handle`.
    ///
    /// `interval` is this call's captured approval interval. A linked entry
    /// returns only while both its signed interval and `interval` hold now.
    ///
    /// # Errors
    ///
    /// The outer error is a durable or lock refusal for the wallet error
    /// envelope. The inner error is an inbox refusal for the payment
    /// recovery mapping.
    pub(crate) fn payment_pending_approval(
        &self,
        handle: Option<&OperationHandle>,
        decision: PolicyDecision,
        interval: (u64, u64),
        write: impl InboxWrite<Error = ApprovalError>,
    ) -> Result<Result<PendingApproval, ApprovalError>, WalletError> {
        match self.start_approval(
            handle,
            ApprovedKind::Payment,
            decision,
            Unlinked::Recover,
            |path, view, handle| self.linked_payment(path, view, handle, interval),
            write,
        ) {
            Ok(result) => Ok(result),
            Err(ProducerError::Inbox(error)) => Ok(Err(ApprovalError::Io {
                kind: std::io::ErrorKind::Other,
                source: std::io::Error::other(error),
            })),
            Err(ProducerError::Durable(error)) => Err(error),
        }
    }

    /// The linked payment entry of `view`, read and checked under one inbox
    /// lock.
    ///
    /// The record must be pending, unexpired and match the entry's kind,
    /// subject and signed clocks. The entry must be unique and live, and
    /// any recovery binding must be active; an observed expiry persists first.
    ///
    /// The subject of `handle`'s retained envelope must equal the entry's.
    /// An envelope slot's record binds that subject as envelope text. A
    /// canonical slot's entry and record bind the intent digest, and the
    /// record's subject is the slot's intent digest, as consent requires.
    fn linked_payment(
        &self,
        path: &std::path::Path,
        view: &ApprovalView,
        handle: &OperationHandle,
        (created, expires): (u64, u64),
    ) -> Result<Result<PendingApproval, ApprovalError>, WalletError> {
        let record = &view.record;
        let clock = || {
            self.clock.now_unix_ms().map_err(|error| {
                WalletError::Approval(ApprovalFailure::ClockError {
                    detail: error.to_string(),
                })
            })
        };
        match record.state {
            ApprovalState::Revoked => {
                return Err(WalletError::Approval(ApprovalFailure::Revoked {
                    detail: "the operation's approval has been revoked".to_owned(),
                }));
            }
            ApprovalState::Consumed => return Ok(Err(ApprovalError::Consumed)),
            ApprovalState::Pending if view.expired => {
                // The linked check persists the observed binding expiry, so
                // a later restart or clock rollback keeps this refusal.
                let now = clock()?;
                return Ok(
                    match open_inbox(path)?.check_payment_recovery_at(&record.nonce, now) {
                        Ok(())
                        | Err(
                            ApprovalError::Expired
                            | ApprovalError::Rejected
                            | ApprovalError::Consumed,
                        ) => Err(ApprovalError::Expired),
                        Err(error) => Err(error),
                    },
                );
            }
            ApprovalState::Pending => {}
        }
        let now = clock()?;
        let mut inbox = open_inbox(path)?;
        let copies = inbox
            .snapshot(now)
            .iter()
            .filter(|entry| entry.approval_nonce == record.nonce)
            .count();
        if copies > 1 {
            return Ok(Err(ApprovalError::RecoveryInconsistent));
        }
        let entry = linked_entry_in(&inbox, &record.nonce)?;
        if let Err(error) = inbox.check_payment_recovery_at(&record.nonce, now) {
            return Ok(Err(error));
        }
        drop(inbox);
        match entry.kind {
            ApprovalKind::Rejected { .. } => return Ok(Err(ApprovalError::Rejected)),
            ApprovalKind::Consumed { .. } => return Ok(Err(ApprovalError::Consumed)),
            ApprovalKind::PaymentSimulated { .. } => {}
            _ => return Ok(Err(ApprovalError::RecoveryInconsistent)),
        }
        if now < entry.created_at_unix_ms
            || now >= entry.expires_at_unix_ms
            || now < created
            || now >= expires
        {
            return Ok(Err(ApprovalError::Expired));
        }
        let subject = stellar_agent_core::approval::mainnet_consent_subject(
            &entry,
            &stellar_agent_core::approval::AttestationBinding::new(
                &self.profile_name_for_approval(),
                self.context.chain_id.caip2_str(),
            ),
        )?;
        let (retained, subject_kind, record_subject) =
            if handle.intent().kind() == stellar_agent_network::policy_state::SlotKind::Canonical {
                (
                    handle
                        .envelope_xdr()
                        .map(stellar_agent_core::approval::subject::approval_subject_classic),
                    stellar_agent_core::approval::subject::SubjectKind::IntentDigest,
                    handle.intent().intent_digest(),
                )
            } else {
                (
                    handle.unsigned_envelope_sha256(),
                    stellar_agent_core::approval::subject::SubjectKind::EnvelopeText,
                    subject,
                )
            };
        if record.kind != ApprovedKind::Payment
            || entry.subject_kind != subject_kind
            || record.subject_kind != subject_kind
            || record.subject != record_subject
            || retained != Some(subject)
            || (record.created_at_ms, record.waiting_expires_at_ms)
                != (entry.created_at_unix_ms, entry.expires_at_unix_ms)
        {
            return Ok(Err(ApprovalError::RecoveryInconsistent));
        }
        Ok(Ok(entry))
    }

    /// Runs the durable producer flow for `handle` under the producer lock.
    /// `linked` reads the entry a durable record names for `handle`;
    /// `write` stores the entry this call opens a record for.
    ///
    /// For a kind whose consent is published, every returned entry holds an
    /// evidence reservation: an existing record reacquires its slot before
    /// `linked` runs, a revoked record refuses with `approval.revoked`
    /// before the reacquisition, and a new entry is stored only after its record opens
    /// and reserves (see [`Self::admit_approval`]).
    fn start_approval<E, W: InboxWrite<Error = E>>(
        &self,
        handle: Option<&OperationHandle>,
        kind: ApprovedKind,
        decision: PolicyDecision,
        unlinked: Unlinked,
        linked: impl Fn(
            &std::path::Path,
            &ApprovalView,
            &OperationHandle,
        ) -> Result<Result<PendingApproval, E>, WalletError>,
        write: W,
    ) -> Result<Result<PendingApproval, E>, ProducerError> {
        if !self.context.chain_id.is_mainnet() {
            return Ok(write.persist(None));
        }
        let handle = handle.ok_or_else(|| {
            WalletError::Internal(InternalError::UnexpectedState {
                detail: "a mainnet approval requires its operation record".to_owned(),
            })
        })?;
        let name = self.profile_name_for_approval();
        let directory = self.resolve_approval_dir().map_err(|error| {
            ProducerError::Inbox(ApprovalError::Io {
                kind: std::io::ErrorKind::Other,
                source: std::io::Error::other(error),
            })
        })?;
        let path = directory.join(format!("{name}.toml"));
        // Opening the inbox establishes its private directory before the
        // producer lock is created; this initial guard writes no entry.
        drop(
            open_with_retry(&path, DEFAULT_RETRY_ATTEMPTS, DEFAULT_RETRY_BACKOFF)
                .map_err(ProducerError::Inbox)?,
        );
        let _producer = producer_lock(&directory.join(format!("{name}.producer.lock")))?;
        let status = ApprovalStatus::new(&self.window_store, self.security_profile());
        let published =
            stellar_agent_network::policy_state::approvals::delivery_enforced(&name, kind);
        if let Some(view) = status
            .find_by_operation(handle.id())
            .map_err(operation_entry::operation_refusal)?
        {
            if published {
                // A revoked record holds no slot to reacquire; it answers
                // with its state, as the unpublished route does.
                if view.record.state == ApprovalState::Revoked {
                    return Err(WalletError::Approval(ApprovalFailure::Revoked {
                        detail: "the operation's approval has been revoked".to_owned(),
                    })
                    .into());
                }
                self.reacquire_reservation(&view)?;
            }
            return linked(&path, &view, handle).map_err(Into::into);
        }
        if handle.state() != OperationState::Prepared {
            return Err(operation_entry::approval_requires_prepared().into());
        }
        if unlinked == Unlinked::Replace {
            let mut pending = open_inbox(&path)?;
            remove_orphans(&mut pending, &status, handle)?;
        }
        let intent =
            if handle.intent().kind() == stellar_agent_network::policy_state::SlotKind::Canonical {
                let policy = self.current_mainnet_policy().ok_or(WalletError::Approval(
                    ApprovalFailure::PresencePolicyUnavailable,
                ))?;
                operation_entry::preparation_intent(handle, self.security_profile(), policy)?
            } else {
                None
            };
        if published {
            return self.admit_approval(
                &path,
                handle,
                kind,
                decision,
                unlinked,
                linked,
                write,
                intent.as_ref(),
            );
        }
        let entry = match write.persist(intent.as_ref()) {
            Ok(entry) => entry,
            Err(error) => return Ok(Err(error)),
        };
        let opened = (|| {
            let facts = self.approval_facts(&entry, handle, kind)?;
            self.approval_step(|recorder| {
                recorder
                    .open_pending(handle.id(), &facts, decision)
                    .map_err(operation_entry::operation_refusal)
            })
        })();
        let error = match opened {
            Ok(view) if unlinked == Unlinked::Recover => {
                return linked(&path, &view, handle).map_err(Into::into);
            }
            Ok(_) => return Ok(Ok(entry)),
            Err(error) => error,
        };
        match status.find_by_operation(handle.id()) {
            Ok(Some(view)) if view.record.nonce != entry.approval_nonce => {
                open_inbox(&path)?
                    .remove(&entry.approval_nonce)
                    .map_err(|error| record_error(&error))?;
                return linked(&path, &view, handle).map_err(Into::into);
            }
            Ok(None) if unlinked == Unlinked::Replace => {
                // A failed cleanup leaves an orphan for the next retry.
                if let Ok(mut pending) = open_inbox(&path) {
                    let _ = pending.remove(&entry.approval_nonce);
                }
            }
            // A matching or unreadable outcome keeps the entry for retry.
            _ => {}
        }
        Err(error.into())
    }

    /// The facts of the record `entry` opens for `handle`: the entry's signed
    /// interval and its subject under this server's binding.
    fn approval_facts(
        &self,
        entry: &PendingApproval,
        handle: &OperationHandle,
        kind: ApprovedKind,
    ) -> Result<PendingApprovalFacts, WalletError> {
        let ttl = entry
            .expires_at_unix_ms
            .checked_sub(entry.created_at_unix_ms)
            .ok_or_else(|| {
                WalletError::Internal(InternalError::UnexpectedState {
                    detail: "the signed approval interval ends before it starts".to_owned(),
                })
            })?;
        let subject = stellar_agent_core::approval::mainnet_consent_subject(
            entry,
            &stellar_agent_core::approval::AttestationBinding::new(
                &self.profile_name_for_approval(),
                self.context.chain_id.caip2_str(),
            ),
        )?;
        Ok(operation_entry::pending_approval_facts(
            entry, handle, kind, subject, ttl,
        ))
    }

    /// The keyed outbox that holds this profile's consent evidence.
    fn consent_outbox(&self) -> Result<AuditOutbox, WalletError> {
        let profile = self.security_profile();
        let (key, anchor) = stellar_agent_network::keyring::keyed_audit_access(
            profile,
            &self.profile_name_for_approval(),
            self.audit_binding,
        )?
        .into_parts();
        Ok(AuditOutbox::for_log_keyed(
            &profile.audit_log_path,
            anchor,
            key,
        ))
    }

    /// Reacquires the evidence slot of the record `view` with its
    /// authenticated facts, without an audit writer or the window lock.
    fn reacquire_reservation(&self, view: &ApprovalView) -> Result<(), WalletError> {
        ConsentAdmission::reacquire(
            &self.window_store,
            self.security_profile(),
            view.record.operation_id,
            &view.record.facts(),
            &self.consent_outbox()?,
        )
        .map(drop)
    }

    /// Admits a new published approval for `handle`. It builds the entry
    /// with the operation's canonical `intent`, opens its record with the
    /// held audit writer, and reserves the record's
    /// evidence after the window transaction. Only then, with the writer
    /// released, does it store the entry. A refusal before the insert stores
    /// nothing and keeps the committed record and any reservation. When a
    /// conflicting open's winner names another nonce, the producer answers
    /// with the winner's entry.
    #[allow(
        clippy::too_many_arguments,
        reason = "the producer's kind, decision, recovery mode, inbox steps and intent are each explicit"
    )]
    fn admit_approval<E, W: InboxWrite<Error = E>>(
        &self,
        path: &std::path::Path,
        handle: &OperationHandle,
        kind: ApprovedKind,
        decision: PolicyDecision,
        unlinked: Unlinked,
        linked: impl Fn(
            &std::path::Path,
            &ApprovalView,
            &OperationHandle,
        ) -> Result<Result<PendingApproval, E>, WalletError>,
        write: W,
        intent: Option<&stellar_agent_core::approval::ClassicIntent>,
    ) -> Result<Result<PendingApproval, E>, ProducerError> {
        let entry = match write.build(intent) {
            Ok(entry) => entry,
            Err(error) => return Ok(Err(error)),
        };
        let facts = self.approval_facts(&entry, handle, kind)?;
        let profile = self.security_profile();
        let outbox = self.consent_outbox()?;
        let writer = crate::tools::value_audit::require_value_audit_writer(
            profile,
            &self.profile_name_for_approval(),
            self.audit_binding,
        )?;
        let mut guard = writer.lock().map_err(|_| {
            WalletError::Submission(SubmissionError::RecordUnavailable {
                detail: "the audit writer mutex is poisoned, so the approval cannot be recorded"
                    .to_owned(),
            })
        })?;
        ConsentAdmission {
            store: &self.window_store,
            profile,
            writer: &mut guard,
            outbox: &outbox,
        }
        .admit(
            handle.id(),
            &facts,
            |writer, facts| {
                ApprovalRecorder::new(
                    &self.window_store,
                    profile,
                    writer,
                    uuid::Uuid::new_v4().to_string(),
                )
                .open_pending(handle.id(), facts, decision)
                .map_err(operation_entry::operation_refusal)
            },
            |_, _| Ok(()),
        )?;
        drop(guard);
        let view = ApprovalStatus::new(&self.window_store, profile)
            .find_by_operation(handle.id())
            .map_err(operation_entry::operation_refusal)?
            .ok_or_else(|| {
                WalletError::Internal(InternalError::UnexpectedState {
                    detail: "the admitted approval record is not readable".to_owned(),
                })
            })?;
        if view.record.nonce != entry.approval_nonce {
            return linked(path, &view, handle).map_err(Into::into);
        }
        let entry = match write.insert(entry) {
            Ok(entry) => entry,
            Err(error) => return Ok(Err(error)),
        };
        if unlinked == Unlinked::Recover {
            return linked(path, &view, handle).map_err(Into::into);
        }
        Ok(Ok(entry))
    }

    /// Stores a built classic value `entry` in the approval store of
    /// `profile_name`, creating its directory, and returns it.
    ///
    /// # Errors
    ///
    /// Returns a string error description on any I/O, store-lock, or clock
    /// failure.
    pub(crate) fn insert_classic_pending(
        &self,
        profile_name: &str,
        entry: PendingApproval,
    ) -> Result<PendingApproval, String> {
        let approvals_dir = self
            .resolve_approval_dir()
            .map_err(|e| format!("approval dir resolution failed: {e}"))?;
        std::fs::create_dir_all(&approvals_dir)
            .map_err(|e| format!("approval dir create_all failed: {e}"))?;
        let store_path = approvals_dir.join(format!("{profile_name}.toml"));
        let mut store = open_with_retry(&store_path, DEFAULT_RETRY_ATTEMPTS, DEFAULT_RETRY_BACKOFF)
            .map_err(|e| format!("approval store open failed: {e}"))?;
        let now_ms = stellar_agent_core::timefmt::now_unix_ms()
            .map_err(|e| format!("approval store insert: current time unavailable: {e}"))?;
        store
            .insert(entry.clone(), now_ms)
            .map_err(|e| format!("approval store insert failed: {e}"))?;
        Ok(entry)
    }

    /// The business id a value tool enters with.
    ///
    /// The check runs only for a call on the profile's own chain, so a call
    /// naming another chain keeps the gate's chain refusal. A mainnet call
    /// requires an id; every other chain validates a supplied one.
    ///
    /// # Errors
    ///
    /// `validation.business_id_required` and
    /// `validation.business_id_invalid`, as a tool result.
    pub(crate) fn entry_business_id(
        &self,
        chain_id: &str,
        raw: Option<&str>,
    ) -> Result<Option<BusinessId>, CallToolResult> {
        if chain_id != self.context.chain_id.caip2_str() {
            return Ok(None);
        }
        operation_entry::entry_business_id(self.security_profile(), raw)
            .map_err(|error| refusal(&error))
    }

    /// The business id a value tool echoes off mainnet, validated as
    /// [`Self::entry_business_id`] validates it. A mainnet call gives `None`
    /// here: its record lookup checks the id, after every refusal a call
    /// without one gives.
    ///
    /// # Errors
    ///
    /// `validation.business_id_invalid` for a malformed id off mainnet, as a
    /// tool result.
    pub(crate) fn echoed_business_id(
        &self,
        chain_id: &str,
        raw: Option<&str>,
    ) -> Result<Option<BusinessId>, CallToolResult> {
        if self.context.chain_id.is_mainnet() {
            return Ok(None);
        }
        self.entry_business_id(chain_id, raw)
    }

    /// Runs `step` with an operation recorder over the server's window and
    /// its keyed audit writer, the writer lock taken first.
    pub(crate) fn operation_step<T>(
        &self,
        step: impl FnOnce(&mut OperationRecorder<'_>) -> Result<T, WalletError>,
    ) -> Result<T, WalletError> {
        let profile = self.security_profile();
        let writer = crate::tools::value_audit::require_value_audit_writer(
            profile,
            &self.profile_name_for_approval(),
            self.audit_binding,
        )?;
        let mut guard = writer.lock().map_err(|_| {
            WalletError::Submission(SubmissionError::RecordUnavailable {
                detail: "the audit writer mutex is poisoned, so the operation cannot be recorded"
                    .to_owned(),
            })
        })?;
        let request_id = uuid::Uuid::new_v4().to_string();
        let mut recorder =
            OperationRecorder::new(&self.window_store, profile, &mut *guard, request_id);
        step(&mut recorder)
    }

    /// Runs one approval step with the value audit writer acquired before
    /// the window lock. The caller holds no inbox lock during the step.
    pub(crate) fn approval_step<T>(
        &self,
        step: impl FnOnce(&mut ApprovalRecorder<'_>) -> Result<T, WalletError>,
    ) -> Result<T, WalletError> {
        let profile = self.security_profile();
        let writer = crate::tools::value_audit::require_value_audit_writer(
            profile,
            &self.profile_name_for_approval(),
            self.audit_binding,
        )?;
        let mut guard = writer.lock().map_err(|_| {
            WalletError::Submission(SubmissionError::RecordUnavailable {
                detail: "the audit writer mutex is poisoned, so the approval cannot be recorded"
                    .to_owned(),
            })
        })?;
        step(&mut ApprovalRecorder::new(
            &self.window_store,
            profile,
            &mut *guard,
            uuid::Uuid::new_v4().to_string(),
        ))
    }

    /// Runs `step` as [`Self::operation_step`] does, a refusal rendered as
    /// the call's result.
    fn with_operation_recorder<T>(
        &self,
        step: impl FnOnce(&mut OperationRecorder<'_>) -> Result<T, WalletError>,
    ) -> Result<T, CallToolResult> {
        self.operation_step(step).map_err(|error| refusal(&error))
    }

    /// Looks up `business_id` before a toolset preparation does any work,
    /// with the canonical lookup of [`Self::canonical_prepare_entry`]: a
    /// canonical record of the same intent and an envelope record of the same
    /// identity resume or replay, so either route continues the record the
    /// first preparation opened. A new id opens an envelope record of the
    /// request's [`operation_entry::operation_identity`], whose commit
    /// verifies the toolset's protocol nonce.
    ///
    /// # Errors
    ///
    /// The errors of [`Self::canonical_prepare_entry`].
    pub(crate) fn toolset_prepare_entry(
        &self,
        business_id: BusinessId,
        consumer: MainnetConsumer,
        source: &str,
        fee_choice: ClassicFeeChoice,
        memo: &stellar_xdr::Memo,
        facts: IdentityFacts,
    ) -> Result<ClassicOperation, CallToolResult> {
        let mut operation = self.canonical_prepare_entry(
            business_id,
            consumer,
            source,
            fee_choice,
            memo,
            facts.clone(),
        )?;
        if operation.resume.is_none() {
            let guard = self.mainnet_write_admission(consumer)?;
            let identity = operation_entry::operation_identity(
                IntentBaseFacts::new(
                    self.security_profile(),
                    source,
                    guard.policy,
                    fee_choice,
                    operation_entry::memo_fact(memo),
                ),
                facts,
            )
            .map_err(|error| refusal(&error))?;
            operation.preparation = Some(Preparation::Envelope(identity));
            operation.canonical = None;
        }
        Ok(operation)
    }

    /// Looks up `business_id` before a classic preparation of a lasting
    /// canonical intent does any work, with the canonical lookup of the
    /// request's `facts` under the verified mainnet policy.
    ///
    /// A record of the same intent resumes or replays. An envelope record of
    /// the same identity keeps its stored envelope. The returned preparation
    /// opens a canonical record only after [`Self::stage_canonical`].
    ///
    /// # Errors
    ///
    /// The call's whole answer as a tool result:
    ///
    /// - the replay of a retained operation;
    /// - `operation.business_id_conflict` for an id bound to another intent;
    /// - the admission refusal of a server without mainnet authority;
    /// - the store's refusals.
    pub(crate) fn canonical_prepare_entry(
        &self,
        business_id: BusinessId,
        consumer: MainnetConsumer,
        source: &str,
        fee_choice: ClassicFeeChoice,
        memo: &stellar_xdr::Memo,
        facts: IdentityFacts,
    ) -> Result<ClassicOperation, CallToolResult> {
        let guard = self.mainnet_write_admission(consumer)?;
        let memo = operation_entry::memo_fact(memo);
        let base = IntentBaseFacts::new(
            self.security_profile(),
            source,
            guard.policy,
            fee_choice,
            memo.clone(),
        );
        let canonical = CanonicalBase {
            source: source.to_owned(),
            fee_choice,
            memo,
            policy_digest: base.policy_digest,
            signed_fee_cap: base.signed_fee_cap,
        };
        let entry = self.with_operation_recorder(|recorder| {
            operation_entry::lookup_canonical(recorder, &business_id, base, facts)
        })?;
        Self::entered(business_id, None, Some(canonical), entry)
    }

    /// Completes the canonical binding of `operation` with the full lasting
    /// `payload` and the preparation's governing `outcome`, whose decision the
    /// record keeps. A required approval gives the record the outcome's
    /// lifetime as its waiting interval. A call without an operation, an
    /// envelope preparation, and a binding already staged stay as they are.
    ///
    /// # Errors
    ///
    /// The intent constructor's refusals, as a tool result.
    pub(crate) fn stage_canonical(
        &self,
        operation: Option<&mut ClassicOperation>,
        payload: stellar_agent_core::approval::IntentPayload,
        outcome: &crate::tools::common::DispatchOutcome,
    ) -> Result<(), CallToolResult> {
        let Some(operation) = operation else {
            return Ok(());
        };
        let Some(canonical) = operation.canonical.take() else {
            return Ok(());
        };
        let profile = self.security_profile();
        let base = IntentBaseFacts {
            chain_id: profile.chain_id.caip2_str(),
            source: &canonical.source,
            policy_digest: canonical.policy_digest,
            signed_fee_cap: canonical.signed_fee_cap,
            profile_fee_cap: profile.classic_max_fee_per_op_stroops,
            fee_choice: canonical.fee_choice,
            memo: canonical.memo,
        };
        let intent =
            operation_entry::classic_intent(base, payload).map_err(|error| refusal(&error))?;
        operation.preparation = Some(Preparation::Canonical {
            intent: Box::new(intent),
            decision: outcome.audit_decision(),
            rule_ttl_ms: matches!(
                outcome,
                crate::tools::common::DispatchOutcome::RequireApproval(_)
            )
            .then(|| outcome.governing_ttl_ms()),
        });
        Ok(())
    }

    /// The preparation `entry` continues under `business_id`; a retained
    /// operation answers with its replay.
    fn entered(
        business_id: BusinessId,
        preparation: Option<Preparation>,
        canonical: Option<CanonicalBase>,
        entry: ClassicEntry,
    ) -> Result<ClassicOperation, CallToolResult> {
        let resume = match entry {
            ClassicEntry::Build => None,
            ClassicEntry::Resume(handle) => Some(handle),
            ClassicEntry::Replay(view) => return Err(replay_result(&view)),
        };
        Ok(ClassicOperation {
            business_id,
            preparation,
            canonical,
            resume,
        })
    }

    /// The envelope a classic preparation under `operation` returns.
    ///
    /// `candidate` is the stored envelope of a waiting record or the envelope
    /// the call just built. A stored envelope returns with the facts read from
    /// it, and a built one returns once the record that binds it is open. A
    /// record another call opened between the lookup and this open answers as
    /// the lookup would have. Without an operation `candidate` returns as it
    /// is.
    ///
    /// # Errors
    ///
    /// The call's whole answer as a tool result: the replay of a retained
    /// operation, `operation.business_id_conflict`, `operation.capacity`,
    /// the store's refusals, and an internal error for a canonical
    /// preparation that [`Self::stage_canonical`] has not staged.
    pub(crate) fn prepared_envelope(
        &self,
        operation: Option<&ClassicOperation>,
        tool: OperationTool,
        kind: OperationKind,
        candidate: String,
    ) -> Result<PreparedEnvelope, CallToolResult> {
        let Some(operation) = operation else {
            return Ok(PreparedEnvelope {
                xdr: candidate,
                stored: None,
                waiting_end: None,
                operation_id: None,
                handle: None,
            });
        };
        // An operation without its binding opens no record, so no envelope
        // returns for it.
        let Some(preparation) = operation.preparation.as_ref() else {
            return Err(refusal(&WalletError::Internal(
                InternalError::UnexpectedState {
                    detail: "a canonical preparation opens only once staged".to_owned(),
                },
            )));
        };
        let stored = |xdr: &str, handle: &OperationHandle| {
            operation_entry::envelope_facts(xdr)
                .map(|facts| PreparedEnvelope {
                    xdr: xdr.to_owned(),
                    stored: Some(facts),
                    waiting_end: Some(handle.waiting_expires_at_ms()),
                    operation_id: Some(*handle.id().as_bytes()),
                    handle: Some(handle.clone()),
                })
                .map_err(|error| refusal(&error))
        };
        if let Some(handle) = &operation.resume
            && handle.envelope_xdr() == Some(candidate.as_str())
        {
            return stored(&candidate, handle);
        }
        let entry = self.with_operation_recorder(|recorder| {
            preparation.open(
                recorder,
                operation.business_id.clone(),
                tool,
                kind,
                &candidate,
            )
        })?;
        match entry {
            OpenedEntry::Resume(handle) => match handle.envelope_xdr() {
                Some(opened) if opened != candidate => stored(opened, &handle),
                _ => Ok(PreparedEnvelope {
                    xdr: candidate,
                    stored: None,
                    waiting_end: Some(handle.waiting_expires_at_ms()),
                    operation_id: Some(*handle.id().as_bytes()),
                    handle: Some(handle),
                }),
            },
            OpenedEntry::Replay(view) => Err(replay_result(&view)),
        }
    }

    /// Looks up `business_id` before a classic commit of `envelope_xdr`
    /// verifies its approval, rebuilds its envelope or consumes its nonce.
    ///
    /// The read writes nothing. A retained operation answers with its stored
    /// state, so a commit retried after a lost reply does no new work. A
    /// tombstone answers so only for the identity the envelope carries as an
    /// operation of `kind` under `policy`, the commit's verified mainnet policy.
    /// A record that continues gives its operation id, which the approval gate
    /// compares with the approval's record. A window the read cannot read
    /// gives `Ok(None)`, and the commit's gates refuse it. Off mainnet there is
    /// no record and the call proceeds with `Ok(None)`.
    ///
    /// # Errors
    ///
    /// The call's whole answer as a tool result. It is the replay of a
    /// retained operation or `operation.business_id_mismatch` for an id other
    /// than the preparation's. It is `operation.business_id_conflict` for an id
    /// bound to another intent.
    pub(crate) fn classic_commit_lookup(
        &self,
        policy: Option<&VerifiedPolicy>,
        kind: OperationKind,
        business_id: Option<&BusinessId>,
        envelope_xdr: &str,
    ) -> Result<Option<OperationId>, CallToolResult> {
        let (Some(business_id), Some(policy)) = (
            business_id.filter(|_| self.context.chain_id.is_mainnet()),
            policy,
        ) else {
            return Ok(None);
        };
        match operation_entry::commit_preview(
            &self.window_store,
            self.security_profile(),
            business_id,
            envelope_xdr,
            &operation_entry::commit_identities(
                self.security_profile(),
                policy,
                kind,
                envelope_xdr,
            ),
        ) {
            Ok(CommitPreview::Continues(operation)) => Ok(Some(operation)),
            Ok(CommitPreview::Unread) => Ok(None),
            Ok(CommitPreview::Replay(view)) => Err(replay_result(&view)),
            Err(error) => Err(refusal(&error)),
        }
    }

    /// The record a classic commit of `envelope_xdr` under `business_id`
    /// continues; `None` for a call without an operation record. `policy` is
    /// the commit's verified mainnet policy, under which the envelope's
    /// identity as an operation of `kind` must match a tombstone under the id.
    ///
    /// # Errors
    ///
    /// The call's whole answer as a tool result. It is the replay of a
    /// retained operation or `operation.business_id_mismatch` for an id other
    /// than the preparation's. It is also `operation.business_id_conflict`
    /// for an id bound to another intent, or a refusal of the store.
    pub(crate) fn classic_commit_entry(
        &self,
        policy: Option<&VerifiedPolicy>,
        kind: OperationKind,
        business_id: Option<&BusinessId>,
        envelope_xdr: &str,
    ) -> Result<Option<OperationHandle>, CallToolResult> {
        let (Some(business_id), Some(policy)) = (
            business_id.filter(|_| self.context.chain_id.is_mainnet()),
            policy,
        ) else {
            return Ok(None);
        };
        let identities =
            operation_entry::commit_identities(self.security_profile(), policy, kind, envelope_xdr);
        let entry = self.with_operation_recorder(|recorder| {
            operation_entry::commit_classic(
                &self.window_store,
                recorder,
                self.security_profile(),
                business_id,
                envelope_xdr,
                &identities,
            )
        })?;
        match entry {
            CommitEntry::Proceed(handle) => Ok(Some(handle)),
            CommitEntry::Replay(view) => Err(replay_result(&view)),
        }
    }

    /// The route of a classic commit of `tool`, decided before its other
    /// checks.
    ///
    /// Under the mainnet `guard`, an id whose record holds a canonical intent
    /// takes the canonical route; the read takes no lock and writes nothing.
    /// Every other commit presenting `fields` takes the envelope route with
    /// them, unchanged. A commit that omits one of them answers with the fixed
    /// argument refusal of `tool`, except that on mainnet it first resolves
    /// its business id: a missing or malformed id and an id without a record
    /// refuse with their own codes, and a window that cannot be read with the
    /// refusal the envelope route's policy gate gives for it.
    pub(crate) fn commit_route<'a, 'g>(
        &self,
        tool: &str,
        guard: Option<&'a crate::server::MainnetWriteGuard<'g>>,
        chain_id: &str,
        business_id: Option<&str>,
        fields: EnvelopeFields<'a>,
    ) -> CommitRoute<'a, 'g> {
        use stellar_agent_network::policy_state::{OperationStatus, SlotKind, WindowStoreError};
        let status = OperationStatus::new(&self.window_store, self.security_profile());
        if let Some(guard) = guard
            && let Some(id) = business_id.and_then(|raw| BusinessId::parse(raw).ok())
            && status
                .view(&id)
                .is_ok_and(|view| view.is_some_and(|view| view.slot_kind == SlotKind::Canonical))
        {
            return CommitRoute::Canonical(guard, id);
        }
        if let EnvelopeFields {
            envelope_xdr: Some(envelope_xdr),
            nonce: Some(nonce),
            expires_at_unix_ms: Some(expires_at_unix_ms),
        } = fields
        {
            return CommitRoute::Envelope {
                envelope_xdr,
                nonce,
                expires_at_unix_ms,
            };
        }
        let omitted = || CommitRoute::Answer(crate::server::argument_refusal(tool));
        if guard.is_none() {
            return omitted();
        }
        let id = match self.entry_business_id(chain_id, business_id) {
            Ok(Some(id)) => id,
            Ok(None) => return omitted(),
            Err(result) => return CommitRoute::Answer(result),
        };
        match status.view(&id) {
            Ok(Some(_)) => omitted(),
            Ok(None) => CommitRoute::Answer(refusal(&operation_entry::operation_refusal(
                WindowStoreError::BusinessIdMismatch,
            ))),
            Err(error) => CommitRoute::Answer(crate::tools::common::window_refresh_refusal(&error)),
        }
    }

    /// The business id of a record holding a canonical intent, read without
    /// a lock; `None` for a malformed id, an id without a record, an
    /// envelope record and a window the read cannot read, so an envelope
    /// record is never looked up under the recorder.
    pub(crate) fn canonical_slot_id(&self, business_id: Option<&str>) -> Option<BusinessId> {
        use stellar_agent_network::policy_state::{OperationStatus, SlotKind};
        let id = business_id.and_then(|raw| BusinessId::parse(raw).ok())?;
        OperationStatus::new(&self.window_store, self.security_profile())
            .view(&id)
            .is_ok_and(|view| view.is_some_and(|view| view.slot_kind == SlotKind::Canonical))
            .then_some(id)
    }

    /// Admits a commit of the unsigned `envelope_xdr` for the canonical
    /// record under `business_id` only when that record binds the envelope,
    /// read without a lock. A preparation of the record binds the envelope it
    /// built for the stored intent, so an envelope that only other records
    /// bind, or none, belongs to another intent.
    ///
    /// # Errors
    ///
    /// `operation.business_id_conflict` for an envelope the record does not
    /// bind, and for a window the read cannot read.
    pub(crate) fn canonical_envelope(
        &self,
        business_id: &BusinessId,
        envelope_xdr: &str,
    ) -> Result<(), CallToolResult> {
        use stellar_agent_network::policy_state::{OperationStatus, WindowStoreError};
        let bound = OperationStatus::new(&self.window_store, self.security_profile())
            .commit_binding(
                business_id,
                &operation_entry::unsigned_envelope_sha256(envelope_xdr),
            )
            .is_ok_and(|binding| {
                binding
                    .owners
                    .iter()
                    .any(|owner| &owner.business_id == business_id)
            });
        if bound {
            Ok(())
        } else {
            Err(refusal(&operation_entry::operation_refusal(
                WindowStoreError::BusinessIdConflict,
            )))
        }
    }

    /// The canonical operation a mainnet commit under `business_id`
    /// continues, looked up under the recorder, with its stored intent
    /// validated under `policy`, the commit's verified mainnet policy.
    ///
    /// `matches` compares the commit's lasting arguments, of the account
    /// `source`, with the stored intent. A record that does no further work
    /// answers with its stored state when its retained intent matches; a
    /// compacted record keeps no intent and answers as it is.
    ///
    /// # Errors
    ///
    /// The call's whole answer as a tool result: the replay of a retained
    /// operation; `operation.business_id_mismatch` for an id whose record is
    /// gone; `operation.business_id_conflict` for lasting arguments other than
    /// the stored intent's or a stored intent that does not validate; and the
    /// store's refusals.
    pub(crate) fn canonical_commit_target(
        &self,
        policy: &VerifiedPolicy,
        business_id: BusinessId,
        source: &str,
        matches: impl FnOnce(&stellar_agent_core::approval::ClassicIntent) -> bool,
    ) -> Result<crate::tools::canonical_commit::CanonicalTarget, CallToolResult> {
        use stellar_agent_network::policy_state::{
            LookupOutcome, OperationStatus, WindowStoreError,
        };
        // A tombstone keeps no intent and never resumes, so it answers from
        // one read of the window without a recorder write.
        let tombstone = OperationStatus::new(&self.window_store, self.security_profile())
            .view(&business_id)
            .map_err(|error| refusal(&operation_entry::operation_refusal(error)))?
            .filter(|view| view.compacted);
        if let Some(view) = tombstone {
            return Err(replay_result(&view));
        }
        let (found, retained) = self.with_operation_recorder(|recorder| {
            let found = recorder
                .lookup(&business_id)
                .map_err(operation_entry::operation_refusal)?;
            let retained = match &found {
                Some(LookupOutcome::Replay(view)) => recorder
                    .retained_intent(view.operation_id)
                    .map_err(operation_entry::operation_refusal)?,
                _ => None,
            };
            Ok((found, retained))
        })?;
        let refused = |error| refusal(&operation_entry::operation_refusal(error));
        let handle = match found {
            None => return Err(refused(WindowStoreError::BusinessIdMismatch)),
            Some(LookupOutcome::Replay(view)) => {
                // A compacted record keeps no intent and answers as it is.
                let other = retained.is_some_and(|slot| {
                    !operation_entry::canonical_slot_intent(
                        &slot,
                        &operation_entry::CanonicalUse {
                            chain_id: self.security_profile().chain_id.caip2_str(),
                            source,
                            policy_digest: policy.digest(),
                        },
                    )
                    .is_ok_and(|intent| matches(&intent))
                });
                if other {
                    return Err(refused(WindowStoreError::BusinessIdConflict));
                }
                return Err(replay_result(&view));
            }
            Some(LookupOutcome::Resumable(handle)) => handle,
        };
        let intent = operation_entry::preparation_intent(&handle, self.security_profile(), policy)
            .map_err(|error| refusal(&error))?
            .filter(|intent| matches(intent))
            .ok_or_else(|| refused(WindowStoreError::BusinessIdConflict))?;
        Ok(crate::tools::canonical_commit::CanonicalTarget {
            business_id,
            handle,
            intent,
        })
    }

    /// Opens the x402 record of a payment under its business id, with the
    /// intent digest the x402 crate computes; `None` off mainnet, where no
    /// record exists.
    ///
    /// # Errors
    ///
    /// The call's whole answer as a tool result. It is a business-id
    /// refusal, the replay of a retained operation, or
    /// `operation.business_id_conflict` for an id bound to another intent.
    /// It is also `operation.capacity` or a refusal of the store.
    #[cfg(feature = "mainnet-write")]
    pub(crate) fn x402_entry(
        &self,
        chain_id: &str,
        raw: Option<&str>,
        tool: OperationTool,
        kind: OperationKind,
        intent_digest: [u8; 32],
        intent: stellar_agent_network::policy_state::X402Intent,
    ) -> Result<Option<OperationHandle>, CallToolResult> {
        let business_id = self.entry_business_id(chain_id, raw)?;
        let Some(id) = business_id.filter(|_| self.context.chain_id.is_mainnet()) else {
            return Ok(None);
        };
        let request = stellar_agent_network::policy_state::OpenRequest {
            business_id: id,
            tool,
            kind,
            intent: stellar_agent_network::policy_state::IntentSlot::X402 {
                intent_digest,
                intent,
            },
            envelope_xdr: None,
            prepared_decision: None,
            rule_ttl_ms: None,
        };
        let outcome = self.with_operation_recorder(|recorder| {
            recorder
                .open(&request)
                .map_err(operation_entry::operation_refusal)
        })?;
        use stellar_agent_network::policy_state::OpenOutcome;
        match outcome {
            OpenOutcome::New(handle) | OpenOutcome::Resumable(handle) => Ok(Some(handle)),
            OpenOutcome::Replay(view) => Err(replay_result(&view)),
            OpenOutcome::Conflict => Err(refusal(&operation_entry::operation_refusal(
                stellar_agent_network::policy_state::WindowStoreError::BusinessIdConflict,
            ))),
        }
    }
}

/// The operation steps of one authorized x402 payment.
///
/// The attempt is committed as `Sending` after the mint and before the
/// signature, and its exposure after the intent consumption and before the
/// signed re-simulation. A returned payload ends it as `PayloadReleased`; a
/// failure ends it as `SentOutcomeUnknown` after the exposure and as
/// `NotSent` before it.
#[cfg(feature = "mainnet-write")]
pub(crate) struct X402Steps<'s> {
    server: &'s WalletServer,
    handle: Option<OperationHandle>,
    attempt: std::sync::Mutex<Option<stellar_agent_network::OperationAttempt>>,
    exposed: std::sync::atomic::AtomicBool,
    refusal: std::sync::Mutex<Option<WalletError>>,
}

#[cfg(feature = "mainnet-write")]
impl std::fmt::Debug for X402Steps<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X402Steps")
            .field("handle", &self.handle)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "mainnet-write")]
impl<'s> X402Steps<'s> {
    /// The steps of a payment under `handle`; without a record every step
    /// does nothing.
    pub(crate) fn new(server: &'s WalletServer, handle: Option<OperationHandle>) -> Self {
        Self {
            server,
            handle,
            attempt: std::sync::Mutex::new(None),
            exposed: std::sync::atomic::AtomicBool::new(false),
            refusal: std::sync::Mutex::new(None),
        }
    }

    /// The link the intent authorization's mint carries.
    pub(crate) fn link(&self) -> Option<stellar_agent_network::policy_state::OperationLink> {
        self.handle.as_ref().map(operation_entry::next_attempt_link)
    }

    fn attempt(&self) -> Option<stellar_agent_network::OperationAttempt> {
        *self
            .attempt
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Keeps `error` for [`Self::refusal_result`] and returns the gate
    /// refusal the x402 crate passes through.
    fn refuse(&self, error: WalletError) -> stellar_agent_x402::X402Error {
        let detail = format!("operation record refused: {}", error.code());
        *self
            .refusal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(error);
        stellar_agent_x402::X402Error::TransmitGateRefused { detail }
    }

    /// The operation hooks of the payment.
    pub(crate) fn hooks(&self) -> stellar_agent_x402::exact::OperationHooks<'_> {
        stellar_agent_x402::exact::OperationHooks {
            before_sign: Box::new(move |_authorization| self.before_sign()),
            expose: Box::new(move |transmit| self.expose(transmit)),
        }
    }

    fn before_sign(
        &self,
    ) -> Result<Option<stellar_agent_network::OperationAttempt>, stellar_agent_x402::X402Error>
    {
        use stellar_agent_network::policy_state::{AttemptAuthorization, AttemptRequest};
        let Some(handle) = &self.handle else {
            return Ok(None);
        };
        let started = self
            .server
            .operation_step(|recorder| {
                recorder
                    .begin_attempt(
                        handle,
                        &AttemptRequest {
                            envelope: None,
                            authorization: AttemptAuthorization::Linked,
                            send_by_ms: u64::MAX,
                        },
                    )
                    .map_err(operation_entry::operation_refusal)
            })
            .map_err(|error| self.refuse(error))?;
        let attempt = stellar_agent_network::OperationAttempt {
            operation_id: handle.id(),
            attempt_index: started.attempt_index,
        };
        *self
            .attempt
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(attempt);
        Ok(Some(attempt))
    }

    fn expose(
        &self,
        transmit: &stellar_agent_x402::exact::AuthorizationToTransmit<'_>,
    ) -> Result<(), stellar_agent_x402::X402Error> {
        use stellar_agent_network::policy_state::ExposureIdentity;
        let (Some(attempt), Some(authorization_id)) =
            (transmit.operation, transmit.authorization_id)
        else {
            return Ok(());
        };
        let identity = ExposureIdentity::X402 {
            authorization_id,
            auth_entry_sha256: transmit.signed_entries_sha256,
            signature_expiration_ledger: transmit.signature_expiration_ledger,
        };
        self.server
            .operation_step(|recorder| {
                recorder
                    .expose(attempt.operation_id, attempt.attempt_index, &identity, None)
                    .map_err(operation_entry::operation_refusal)
            })
            .map_err(|error| self.refuse(error))?;
        self.exposed
            .store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    /// The refusal a step kept, as the call's result.
    pub(crate) fn refusal_result(&self) -> Option<CallToolResult> {
        self.refusal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .map(|error| refusal(&error))
    }

    /// Ends the attempt as `PayloadReleased` once the payload is returned.
    pub(crate) fn released(&self) {
        self.end(
            stellar_agent_network::policy_state::OperationState::PayloadReleased,
            None,
        );
    }

    /// Ends the attempt as `SentOutcomeUnknown` when the built payload is
    /// withheld: a built payload follows the committed exposure, and the
    /// signed entries already reached the endpoint in the re-simulation.
    pub(crate) fn withheld(&self) {
        self.end(
            stellar_agent_network::policy_state::OperationState::SentOutcomeUnknown,
            None,
        );
    }

    /// Ends the attempt after a failure with wire code `code`:
    /// `SentOutcomeUnknown` once the signed entries were exposed, `NotSent`
    /// before.
    pub(crate) fn failed(&self, code: &str) {
        use stellar_agent_network::policy_state::OperationState;
        if self.exposed.load(std::sync::atomic::Ordering::SeqCst) {
            self.end(OperationState::SentOutcomeUnknown, None);
        } else {
            self.end(OperationState::NotSent, Some(code));
        }
    }

    fn end(&self, to: stellar_agent_network::policy_state::OperationState, code: Option<&str>) {
        use stellar_agent_network::policy_state::{OperationResult, TransitionEvidence};
        let Some(attempt) = self.attempt() else {
            return;
        };
        let evidence = TransitionEvidence {
            result: code.map(|code| OperationResult {
                error_code: Some(code.to_owned()),
                ..OperationResult::default()
            }),
            send_never_started: code.is_some(),
            ..TransitionEvidence::default()
        };
        let ended = self.server.operation_step(|recorder| {
            recorder
                .transition(
                    attempt.operation_id,
                    Some(attempt.attempt_index),
                    to,
                    &evidence,
                )
                .map_err(operation_entry::operation_refusal)
        });
        if let Err(error) = ended {
            tracing::warn!(
                state = to.wire_name(),
                code = error.code(),
                "operation record: the x402 attempt's end was not recorded; it stays sending \
                 until recovery reads it"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test assertions")]

    use super::*;
    #[cfg(feature = "mainnet-write")]
    #[allow(clippy::expect_used, reason = "behavior assertions")]
    mod canonical_consent_tests {
        include!("canonical_consent_tests.rs");
    }

    #[cfg(feature = "mainnet-write")]
    impl WalletServer {
        /// Looks up `business_id` with the envelope lookup of the request's
        /// operation identity under the verified mainnet policy.
        pub(crate) fn classic_prepare_entry(
            &self,
            business_id: BusinessId,
            consumer: MainnetConsumer,
            source: &str,
            fee_choice: ClassicFeeChoice,
            memo: &stellar_xdr::Memo,
            facts: IdentityFacts,
        ) -> Result<ClassicOperation, CallToolResult> {
            let guard = self.mainnet_write_admission(consumer)?;
            let identity = operation_entry::operation_identity(
                IntentBaseFacts::new(
                    self.security_profile(),
                    source,
                    guard.policy,
                    fee_choice,
                    operation_entry::memo_fact(memo),
                ),
                facts,
            )
            .map_err(|error| refusal(&error))?;
            self.prepare_entry(business_id, Preparation::Envelope(identity))
        }

        /// Looks up `business_id` with `preparation`'s own lookup.
        pub(crate) fn prepare_entry(
            &self,
            business_id: BusinessId,
            preparation: Preparation,
        ) -> Result<ClassicOperation, CallToolResult> {
            let entry = self
                .with_operation_recorder(|recorder| preparation.lookup(recorder, &business_id))?;
            Self::entered(business_id, Some(preparation), None, entry)
        }
    }

    use stellar_agent_core::profile::receipt::{OperationDestination, PaymentDestinations};
    use stellar_agent_network::policy_state::{
        OperationId, OperationResult, OperationState, OperationView, SlotKind,
    };

    const G: &str = "GADQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOZPI";
    const M_MAX: &str = "MADQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQP77777777777754MA";

    #[test]
    fn producer_lock_uses_the_inbox_retry_budget() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("producer.lock");
        let held = producer_lock(&path).unwrap();
        let start = std::time::Instant::now();
        let result = producer_lock(&path);
        let elapsed = start.elapsed();
        assert!(matches!(
            result,
            Err(WalletError::Approval(ApprovalFailure::WriterLocked { .. }))
        ));
        assert!(
            elapsed >= DEFAULT_RETRY_BACKOFF * (DEFAULT_RETRY_ATTEMPTS - 1),
            "producer contention waits through every inbox retry backoff"
        );
        drop(held);
        assert!(
            producer_lock(&path).is_ok(),
            "a released producer lock can be acquired"
        );
    }

    /// A canonical preparation that reaches its open without the staged
    /// binding refuses with an internal error; no envelope returns and no
    /// record opens under its business id.
    #[cfg(feature = "mainnet-write")]
    #[test]
    #[serial_test::serial(keyring)]
    #[serial_test::serial]
    fn an_unstaged_canonical_preparation_fails_closed() {
        use crate::tools::common::tests::mainnet::{Fixture, wire};
        use stellar_agent_core::approval::IntentPayload;
        let f = Fixture::new(|raw| raw);
        let server = &f.server;
        let id = BusinessId::parse("canonical-unstaged").unwrap();
        let operation = server
            .canonical_prepare_entry(
                id.clone(),
                MainnetConsumer::McpCreateAccount,
                f.envelope.source(),
                ClassicFeeChoice::Explicit(500),
                &stellar_xdr::Memo::None,
                IdentityFacts::Intent(IntentPayload::CreateAccount {
                    destination: f.envelope.destination().into(),
                    starting_balance_stroops: 17,
                }),
            )
            .unwrap();
        let refused = server
            .prepared_envelope(
                Some(&operation),
                OperationTool::StellarCreateAccount,
                OperationKind::CreateAccount,
                "candidate".to_owned(),
            )
            .unwrap_err();
        assert_eq!(
            wire(&refused)["error"]["code"],
            "internal.unexpected_state",
            "{}",
            wire(&refused)
        );
        assert!(
            stellar_agent_network::policy_state::OperationStatus::new(
                &server.window_store,
                server.security_profile(),
            )
            .view(&id)
            .unwrap()
            .is_none(),
            "no record opens"
        );
    }

    #[cfg(feature = "mainnet-write")]
    #[test]
    #[serial_test::serial(keyring)]
    #[serial_test::serial]
    fn canonical_staging_keeps_the_winning_handle() {
        use crate::tools::common::tests::mainnet::Fixture;
        use stellar_agent_core::approval::{IntentPayload, MemoFact};
        let f = Fixture::new(|raw| raw);
        let server = &f.server;
        let intent = operation_entry::classic_intent(
            IntentBaseFacts::new(
                server.security_profile(),
                f.envelope.source(),
                server.current_mainnet_policy().unwrap(),
                ClassicFeeChoice::Explicit(500),
                MemoFact::None,
            ),
            IntentPayload::CreateAccount {
                destination: f.envelope.destination().into(),
                starting_balance_stroops: 17,
            },
        )
        .unwrap();
        let preparation = Preparation::Canonical {
            intent: Box::new(intent.clone()),
            decision: PolicyDecision::Allow,
            rule_ttl_ms: Some(300_000),
        };
        let id = BusinessId::parse("canonical-winner").unwrap();
        let first = server
            .prepare_entry(id.clone(), preparation.clone())
            .unwrap();
        let stale = server
            .prepare_entry(id.clone(), preparation.clone())
            .unwrap();
        let candidate = operation_entry::intent_envelope(
            &intent,
            server.context.network_passphrase(),
            2,
            100,
            stellar_agent_core::timefmt::now_unix_ms().unwrap() / 1000 + 120,
        )
        .unwrap();
        let built = server
            .prepared_envelope(
                Some(&first),
                OperationTool::StellarCreateAccount,
                OperationKind::CreateAccount,
                candidate.clone(),
            )
            .unwrap();
        let winner = built.handle.unwrap();
        assert_eq!(
            winner.intent().kind(),
            SlotKind::Canonical,
            "staged open selects Canonical"
        );
        let losing = operation_entry::intent_envelope(
            &intent,
            server.context.network_passphrase(),
            3,
            100,
            stellar_agent_core::timefmt::now_unix_ms().unwrap() / 1000 + 120,
        )
        .unwrap();
        let raced = server
            .prepared_envelope(
                Some(&stale),
                OperationTool::StellarCreateAccount,
                OperationKind::CreateAccount,
                losing,
            )
            .unwrap();
        assert_eq!(
            raced.handle.as_ref().map(OperationHandle::id),
            Some(winner.id()),
            "concurrent open keeps winning handle"
        );
        assert_eq!(
            raced.xdr, candidate,
            "concurrent open keeps winning envelope"
        );
        let resumed = server.prepare_entry(id, preparation).unwrap();
        let retained = server
            .prepared_envelope(
                Some(&resumed),
                OperationTool::StellarCreateAccount,
                OperationKind::CreateAccount,
                candidate.clone(),
            )
            .unwrap();
        assert_eq!(
            retained.handle.as_ref().map(OperationHandle::id),
            Some(winner.id()),
            "resume keeps winning handle"
        );
        let unrecorded = server
            .prepared_envelope(
                None,
                OperationTool::StellarCreateAccount,
                OperationKind::CreateAccount,
                candidate.clone(),
            )
            .unwrap();
        assert!(unrecorded.handle.is_none() && unrecorded.operation_id.is_none());
        let legacy = server
            .classic_prepare_entry(
                BusinessId::parse("legacy-winner").unwrap(),
                MainnetConsumer::McpCreateAccount,
                f.envelope.source(),
                ClassicFeeChoice::Explicit(500),
                &stellar_xdr::Memo::None,
                IdentityFacts::Intent(intent.payload().clone()),
            )
            .unwrap();
        let legacy = server
            .prepared_envelope(
                Some(&legacy),
                OperationTool::StellarCreateAccount,
                OperationKind::CreateAccount,
                candidate,
            )
            .unwrap();
        assert_eq!(
            legacy.handle.unwrap().intent().kind(),
            SlotKind::Envelope,
            "ordinary producer stays Envelope"
        );
        let claim = operation_entry::classic_intent(
            IntentBaseFacts::new(
                server.security_profile(),
                f.envelope.source(),
                server.current_mainnet_policy().unwrap(),
                ClassicFeeChoice::Explicit(500),
                MemoFact::None,
            ),
            IntentPayload::Claim {
                balance_id: format!("00000000{}", "09".repeat(32)),
                claimant: f.envelope.source().into(),
                asset: stellar_agent_core::approval::IntentAsset::Native,
                amount_stroops: 17,
            },
        )
        .unwrap();
        let id = BusinessId::parse("retained-claim").unwrap();
        let staged = server
            .prepare_entry(
                id.clone(),
                Preparation::Canonical {
                    intent: Box::new(claim.clone()),
                    decision: PolicyDecision::Allow,
                    rule_ttl_ms: Some(300_000),
                },
            )
            .unwrap();
        let xdr = operation_entry::intent_envelope(
            &claim,
            server.context.network_passphrase(),
            9,
            100,
            stellar_agent_core::timefmt::now_unix_ms().unwrap() / 1000 + 120,
        )
        .unwrap();
        server
            .prepared_envelope(
                Some(&staged),
                OperationTool::StellarClaim,
                OperationKind::Claim,
                xdr,
            )
            .unwrap();
        let partial = server.with_operation_recorder(|recorder| {
            operation_entry::lookup_canonical(
                recorder,
                &id,
                IntentBaseFacts::new(
                    server.security_profile(),
                    f.envelope.source(),
                    server.current_mainnet_policy().unwrap(),
                    ClassicFeeChoice::Explicit(500),
                    MemoFact::None,
                ),
                IdentityFacts::Claim {
                    balance_id: format!("00000000{}", "09".repeat(32)),
                    claimant: f.envelope.source().into(),
                },
            )
        });
        assert!(
            matches!(partial, Ok(ClassicEntry::Resume(h)) if h.intent().intent_digest() == *claim.digest().as_bytes()),
            "MCP partial claim retains full digest without an RPC client"
        );
    }

    #[cfg(feature = "mainnet-write")]
    #[test]
    #[serial_test::serial(keyring)]
    #[serial_test::serial]
    fn canonical_prepare_crashes_and_races_converge() {
        use crate::tools::common::tests::mainnet::Fixture;
        use stellar_agent_core::approval::{IntentPayload, MemoFact};
        let f = Fixture::new(|raw| raw);
        let server = &f.server;
        let intent = operation_entry::classic_intent(
            IntentBaseFacts::new(
                server.security_profile(),
                f.envelope.source(),
                server.current_mainnet_policy().unwrap(),
                ClassicFeeChoice::Explicit(500),
                MemoFact::None,
            ),
            IntentPayload::CreateAccount {
                destination: f.envelope.destination().into(),
                starting_balance_stroops: 17,
            },
        )
        .unwrap();
        let preparation = Preparation::Canonical {
            intent: Box::new(intent.clone()),
            decision: PolicyDecision::RequireApproval,
            rule_ttl_ms: Some(300_000),
        };
        let operation = server
            .prepare_entry(
                BusinessId::parse("canonical-producer").unwrap(),
                preparation,
            )
            .unwrap();
        let xdr = operation_entry::intent_envelope(
            &intent,
            server.context.network_passphrase(),
            2,
            100,
            stellar_agent_core::timefmt::now_unix_ms().unwrap() / 1000 + 60,
        )
        .unwrap();
        let handle = server
            .prepared_envelope(
                Some(&operation),
                OperationTool::StellarCreateAccount,
                OperationKind::CreateAccount,
                xdr.clone(),
            )
            .unwrap()
            .handle
            .unwrap();
        let directory = server.resolve_approval_dir().unwrap();
        let path = directory.join(format!("{}.toml", server.profile_name_for_approval()));
        let make = || {
            PendingApproval::new_payment_pending(
                xdr.clone(),
                xdr.as_bytes(),
                f.envelope.destination().into(),
                17,
                "XLM".into(),
                None,
                100,
                2,
                "1000".into(),
                300_000,
            )
            .unwrap()
        };
        let orphan = make();
        let mut unrelated = make();
        if let ApprovalKind::PaymentSimulated {
            envelope_sha256_hex,
            ..
        } = &mut unrelated.kind
        {
            *envelope_sha256_hex = "ff".repeat(32);
        }
        {
            let mut inbox = open_inbox(&path).unwrap();
            inbox
                .insert(orphan.clone(), orphan.created_at_unix_ms)
                .unwrap();
            inbox
                .insert(unrelated.clone(), unrelated.created_at_unix_ms)
                .unwrap();
        }
        let result = server.classic_pending_approval(
            Some(&handle),
            ApprovedKind::Payment,
            PolicyDecision::RequireApproval,
            Staged {
                build: |stored: Option<&stellar_agent_core::approval::ClassicIntent>| {
                    assert_eq!(
                        stored,
                        Some(&intent),
                        "producer receives validated stored intent"
                    );
                    let mut entry = make();
                    entry.expires_at_unix_ms = entry.created_at_unix_ms + 120_000;
                    operation_entry::stage_pending(&mut entry, stored, 300_000).unwrap();
                    Ok(entry)
                },
                insert: |entry: PendingApproval| {
                    open_inbox(&path)
                        .unwrap()
                        .insert(entry.clone(), entry.created_at_unix_ms)
                        .unwrap();
                    Ok(entry)
                },
            },
        );
        assert!(
            result.is_ok(),
            "producer records the signed shortened interval"
        );
        let result = result.unwrap();
        let inbox = open_inbox(&path).unwrap();
        assert!(
            inbox.get(&orphan.approval_nonce).is_none(),
            "canonical retry removes only the retained-envelope orphan"
        );
        assert!(
            inbox.get(&unrelated.approval_nonce).is_some(),
            "different envelope survives"
        );
        assert!(
            inbox.get(&result.approval_nonce).is_some(),
            "linked winner survives"
        );
        drop(inbox);
        let record = ApprovalStatus::new(&server.window_store, server.security_profile())
            .find_by_nonce(&result.approval_nonce)
            .unwrap()
            .unwrap()
            .record;
        assert_eq!(
            record.subject,
            *intent.digest().as_bytes(),
            "producer record binds intent"
        );
        assert_eq!(record.rule_ttl_ms, 120_000, "producer uses signed interval");
        assert_eq!(record.waiting_expires_at_ms, result.expires_at_unix_ms);
        let repeated = server
            .classic_pending_approval(
                Some(&handle),
                ApprovedKind::Payment,
                PolicyDecision::RequireApproval,
                Staged {
                    build: |_: Option<&stellar_agent_core::approval::ClassicIntent>| -> Result<
                        PendingApproval,
                        String,
                    > {
                        unreachable!("retry must reuse the linked entry")
                    },
                    insert: |_: PendingApproval| -> Result<PendingApproval, String> {
                        unreachable!("retry must reuse the linked entry")
                    },
                },
            )
            .unwrap();
        assert_eq!(
            repeated.approval_nonce, result.approval_nonce,
            "restart adopts durable winner"
        );
    }

    #[test]
    fn producer_lock_acquires_when_the_holder_releases_between_attempts() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("producer.lock");
        let held = producer_lock(&path).unwrap();
        let release = std::thread::spawn(move || {
            std::thread::sleep(DEFAULT_RETRY_BACKOFF + DEFAULT_RETRY_BACKOFF / 2);
            drop(held);
        });
        let result = producer_lock(&path);
        release.join().unwrap();
        assert!(
            result.is_ok(),
            "a retry acquires the lock released during the retry window"
        );
    }

    fn data_of(destinations: PaymentDestinations, compacted: bool) -> Value {
        let view = OperationView {
            operation_id: OperationId::from_bytes([0x5a; 16]),
            business_id: BusinessId::parse("order-7").unwrap(),
            state: OperationState::Sending,
            tool: None,
            kind: Some(OperationKind::Pay),
            slot_kind: SlotKind::Envelope,
            intent_digest: [1; 32],
            attempts: 1,
            result: Some(OperationResult::default()),
            created_at_ms: None,
            closed_at_ms: None,
            waiting_expires_at_ms: None,
            execution_expires_at_ms: None,
            compacted,
            history_incomplete: false,
            destinations,
        };
        let result = replay_result(&view);
        let text = &result.content[0].as_text().unwrap().text;
        serde_json::from_str::<Value>(text).unwrap()["data"].clone()
    }

    /// The MCP replay of a pay record carries the complete destination or
    /// the per-operation list; a tombstone carries neither member.
    #[test]
    fn a_pay_replay_carries_its_destination() {
        let single = data_of(PaymentDestinations::Single(M_MAX.to_owned()), false);
        assert_eq!(single["destination"], M_MAX, "{single}");
        assert!(single.get("destinations").is_none(), "{single}");
        assert_eq!(single["next"], "wait", "{single}");

        let listed = data_of(
            PaymentDestinations::PerOperation(vec![
                OperationDestination {
                    operation: 0,
                    destination: G.to_owned(),
                },
                OperationDestination {
                    operation: 2,
                    destination: M_MAX.to_owned(),
                },
            ]),
            false,
        );
        assert_eq!(
            listed["destinations"],
            serde_json::json!([
                { "operation": 0, "destination": G },
                { "operation": 2, "destination": M_MAX },
            ]),
            "{listed}"
        );
        assert!(listed.get("destination").is_none(), "{listed}");

        let tombstone = data_of(PaymentDestinations::None, true);
        assert!(tombstone.get("destination").is_none(), "{tombstone}");
        assert!(tombstone.get("destinations").is_none(), "{tombstone}");
    }
}
