//! Presence-gated consent for one decoded mainnet transaction.
//!
//! [`confirm_mainnet_write`] renders the authoritative summary of the
//! stored intent or envelope, parks its pending entry, releases the pending store and awaits
//! the verified WebAuthn presence of an approval credential in the
//! owner-signed policy. It then reopens the store and records the version 5 or 6
//! consent; the core attester checks the parked snapshot, the current policy
//! and both challenge deadlines again under the store lock. No terminal input
//! is consent.

use super::business_entry::approval_step;
use super::consent::{OperatorRowSink, acquire_operator_row_sink, consent_outbox};
use super::mainnet_presence::acquire_mainnet_presence;
use std::io::Write;
use std::path::Path;
use stellar_agent_core::audit_log::{EvidenceReservation, PolicyDecision};
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::{
    approval::{
        ApprovalContext, ApprovalKind, AttestationBinding, ClassicIntent, ConsentAudit,
        DEFAULT_RETRY_ATTEMPTS, DEFAULT_RETRY_BACKOFF, MainnetApprovalAuthority, PendingApproval,
        PendingApprovalStore, VerifiedMainnetPresence,
        attest::{attest_mainnet_confirmation_admitted_with_row, record_error},
        error::ApprovalError,
        load_attestation_key, open_with_retry,
        presence_policy::PolicyAdmission,
        process_uid_for_attestation,
        store::MAINNET_POLICY_AUTHORITY_TTL_SECONDS,
        subject::approval_subject_classic,
        witness::{
            ApprovalExpectation, ApprovalWitness, ApprovedKind, verify_approval_admitted,
            verify_durable_approval, verify_durable_intent_approval,
        },
    },
    envelope_decode::decode_authoritative_args,
    error::{
        ApprovalFailure, InternalError, ProtocolError, SubmissionError, ValidationError,
        WalletError,
    },
    mainnet::{
        decision::{MainnetDecision, MainnetRefusal},
        verified_policy::VerifiedPolicy,
    },
    policy::{
        Decision, PolicyError,
        v1::value::{ValueClass, derive_value_class},
    },
    profile::{owner_key::OwnerKeyContext, receipt::ReceiptStore},
};
use stellar_agent_network::mainnet::authority::{AuthorityRefusal, MainnetAuthority};
use stellar_agent_network::operation_entry::{
    ConsentAdmission, approval_requires_prepared, commit_consent, consent_completion,
    operation_refusal, pending_approval_facts, persisted_attestation,
};
use stellar_agent_network::policy_state::approvals::{
    consent_evidence_time_floor, delivery_enforced,
};
use stellar_agent_network::policy_state::{
    ApprovalRecorder, ApprovalStatus, ConsentRow, OperationHandle, OperationState,
    PendingApprovalFacts, PersistedWindowStore,
};
use stellar_agent_network::{
    MainnetWriteContext,
    mainnet::{MainnetConsumer, resolve::classic_consumer_tools},
    operational::OperationalReport,
};
use stellar_xdr::{ReadXdr as _, TransactionEnvelope};

pub(crate) enum ConfirmDecision {
    Allow,
    RequireApproval { ttl_ms: u64 },
}
impl ConfirmDecision {
    fn ttl_ms(self) -> u64 {
        match self {
            Self::Allow => MAINNET_POLICY_AUTHORITY_TTL_SECONDS * 1000,
            Self::RequireApproval { ttl_ms } => ttl_ms,
        }
    }
}

/// The last line of the rendered summary: what records consent to it.
pub(crate) const CONSENT_LINE: &str =
    "Review this transaction in the local browser and approve with a pinned passkey.";
pub(crate) const SIGNED_CONSENT_LINE: &str =
    "Review this transaction at the signed approval origin and approve with a policy passkey.";

pub(crate) struct MainnetWriteSummary {
    envelope: String,
    consumer: MainnetConsumer,
    policy_tool: &'static str,
    kind: ApprovedKind,
    args: serde_json::Value,
    value: ValueClass,
    sequence: i64,
    fee: u32,
    fee_cap: u32,
    memo: String,
    /// The endpoint's latest ledger as the operational check observed it.
    /// The summary shows it; the pending entry, the digest and the
    /// attestation do not include it.
    ledger: Option<OperationalReport>,
}

/// `approval.wrong_kind`: the consumer has no approval kind this
/// confirmation writes.
fn wrong_kind(detail: &str) -> WalletError {
    WalletError::Approval(ApprovalFailure::WrongKind {
        detail: detail.to_owned(),
    })
}
/// `protocol.xdr_codec_failed`: the envelope or a value decoded from it is
/// unusable, the code every CLI verb gives an undecodable envelope.
#[expect(
    clippy::needless_pass_by_value,
    reason = "Result::map_err supplies owned errors"
)]
fn envelope_error(detail: impl ToString) -> WalletError {
    WalletError::Protocol(ProtocolError::XdrCodecFailed {
        detail: detail.to_string(),
    })
}
#[expect(
    clippy::needless_pass_by_value,
    reason = "Result::map_err supplies owned errors"
)]
fn store_error(error: ApprovalError) -> WalletError {
    record_error(&error)
}

impl MainnetWriteSummary {
    /// Summarizes a classic envelope for confirmation. A contract transfer
    /// never reaches it: the payment verb refuses a contract recipient
    /// before confirmation, and the classic decoder refuses its envelope.
    pub(crate) fn from_envelope(
        envelope_xdr: &str,
        consumer: MainnetConsumer,
        fee_cap: u32,
    ) -> Result<Self, WalletError> {
        let tools = match consumer {
            MainnetConsumer::CliPay
            | MainnetConsumer::CliCreateAccount
            | MainnetConsumer::CliTrustline
            | MainnetConsumer::CliClaim => classic_consumer_tools(consumer),
            _ => None,
        }
        .ok_or_else(|| wrong_kind("mainnet confirmation requires a classic CLI consumer"))?;
        let args =
            decode_authoritative_args(envelope_xdr, tools.decoder_tool).map_err(envelope_error)?;
        let TransactionEnvelope::Tx(tx) = TransactionEnvelope::from_xdr_base64(
            envelope_xdr,
            stellar_agent_xdr_limits::untrusted_decode_limits(envelope_xdr.len()),
        )
        .map_err(envelope_error)?
        else {
            return Err(envelope_error(
                "mainnet confirmation requires a version 1 transaction envelope",
            ));
        };
        let policy_tool = tools.policy_tool;
        let value = derive_value_class(policy_tool, &args);
        let classic_kind = match tools.approved_kind {
            ApprovedKind::Payment => {
                stellar_agent_core::envelope_decode::ClassicTransactionKind::Payment
            }
            ApprovedKind::Trustline => {
                stellar_agent_core::envelope_decode::ClassicTransactionKind::Trustline
            }
            ApprovedKind::Claim => {
                stellar_agent_core::envelope_decode::ClassicTransactionKind::Claim
            }
            _ => {
                return Err(wrong_kind(
                    "mainnet confirmation requires a classic CLI consumer",
                ));
            }
        };
        let memo = stellar_agent_core::envelope_decode::classic_summary(envelope_xdr, classic_kind)
            .map_err(envelope_error)?
            .memo
            .display();
        Ok(Self {
            envelope: envelope_xdr.to_owned(),
            consumer,
            policy_tool,
            kind: tools.approved_kind,
            args,
            value,
            sequence: tx.tx.seq_num.0,
            fee: tx.tx.fee,
            fee_cap,
            memo,
            ledger: None,
        })
    }

    /// The summary with the ledger the endpoint's operational check
    /// observed, which the rendered summary names after the fee lines.
    pub(crate) fn with_ledger(mut self, report: OperationalReport) -> Self {
        self.ledger = Some(report);
        self
    }

    fn render(
        &self,
        context: &MainnetWriteContext,
        output: &mut impl Write,
    ) -> std::io::Result<()> {
        let esc = super::render::escape_for_terminal;
        writeln!(
            output,
            "Profile: {}\nChain: {}\nEndpoint: {}\nSigner: {}",
            esc(context.profile_name()),
            esc(context.chain().caip2_str()),
            esc(context.authority()),
            esc(self.args["source"].as_str().unwrap_or(""))
        )?;
        if let ValueClass::Value(effects) = &self.value {
            let unknown = if self.kind == ApprovedKind::Claim {
                "not known to the wallet before the claim"
            } else {
                "not applicable"
            };
            for leg in effects.legs() {
                writeln!(
                    output,
                    "Action: {:?}\nAsset: {}\nAmount: {}\nDestination: {}",
                    leg.kind,
                    leg.asset
                        .as_deref()
                        .map_or_else(|| unknown.to_owned(), super::render::escape_for_terminal),
                    leg.amount
                        .map_or_else(|| unknown.to_owned(), |amount| amount.to_string()),
                    esc(leg.destination.as_deref().unwrap_or(""))
                )?;
            }
        }
        if self.kind == ApprovedKind::Claim {
            writeln!(
                output,
                "Balance ID: {}",
                esc(&self.string("balance_id_strkey"))
            )?;
        }
        writeln!(output, "Memo: {}", esc(&self.memo))?;
        writeln!(
            output,
            "Fee: {} stroops\nFee cap: {} stroops per operation",
            self.fee, self.fee_cap
        )?;
        if let Some(ledger) = &self.ledger {
            writeln!(
                output,
                "Ledger {}, closed {} s ago",
                ledger.latest_ledger, ledger.close_lag_seconds
            )?;
        }
        writeln!(output, "{CONSENT_LINE}")
    }
    fn string(&self, key: &str) -> String {
        self.args[key].as_str().unwrap_or("").to_owned()
    }
    fn amount(&self, key: &str) -> Result<i64, WalletError> {
        self.string(key).parse().map_err(envelope_error)
    }
    fn pending(&self, uid: String, ttl: u64) -> Result<PendingApproval, WalletError> {
        let text = self.envelope.clone();
        let bytes = self.envelope.as_bytes();
        match self.consumer {
            MainnetConsumer::CliPay | MainnetConsumer::CliCreateAccount => {
                PendingApproval::new_payment_pending(
                    text,
                    bytes,
                    self.string("destination"),
                    self.amount(if self.consumer == MainnetConsumer::CliPay {
                        "amount_stroops"
                    } else {
                        "starting_balance_stroops"
                    })?,
                    if self.consumer == MainnetConsumer::CliPay {
                        self.string("asset")
                    } else {
                        "XLM".into()
                    },
                    self.args["memo"].as_str().map(str::to_owned),
                    self.fee,
                    self.sequence,
                    uid,
                    ttl,
                )
            }
            MainnetConsumer::CliTrustline => PendingApproval::new_trustline_pending(
                text,
                bytes,
                self.string("source"),
                self.string("asset_code"),
                self.string("asset_issuer"),
                Some(self.amount("limit_stroops")?),
                self.fee,
                self.sequence,
                uid,
                ttl,
            ),
            MainnetConsumer::CliClaim => PendingApproval::new_claim_pending_unvalued(
                text,
                bytes,
                self.string("balance_id_hex72"),
                self.string("balance_id_strkey"),
                self.string("source"),
                self.fee,
                self.sequence,
                uid,
                ttl,
            ),
            _ => return Err(wrong_kind("unsupported confirmation consumer")),
        }
        .map_err(store_error)
    }
}

/// Selects the authority the governing decision grants.
/// An approval rule runs the passkey ceremony and stores its witness in the
/// caller's `witness` slot.
///
/// # Errors
///
/// Ceremony refusals retain their gate errors. Factory errors remain internal.
#[allow(
    clippy::result_large_err,
    clippy::too_many_arguments,
    reason = "the shared authority refusal preserves typed gate errors; the ceremony takes each input explicitly"
)]
pub(crate) async fn cli_mainnet_authority<'w>(
    decision: &MainnetDecision,
    confirmation: ConfirmDecision,
    summary: &MainnetWriteSummary,
    context: &MainnetWriteContext,
    policy: &VerifiedPolicy,
    store_path: &Path,
    operation: Option<&OperationHandle>,
    prepared: PolicyDecision,
    witness: &'w mut Option<ApprovalWitness>,
) -> Result<MainnetAuthority<'w>, AuthorityRefusal<WalletError>> {
    match decision.decision() {
        Decision::RequireApproval(_) => {
            let w = confirm_mainnet_write(
                summary,
                confirmation,
                context,
                policy,
                store_path,
                operation,
                prepared,
                decision,
            )
            .await
            .map_err(AuthorityRefusal::Gate)?;
            let slot = witness.insert(w);
            MainnetAuthority::from_decision(decision, Some(&*slot))
                .map_err(AuthorityRefusal::Internal)
        }
        _ => MainnetAuthority::from_decision(decision, None).map_err(AuthorityRefusal::Internal),
    }
}

/// Converts a typed authority refusal at the CLI boundary.
pub(crate) fn render_authority_refusal(
    verb: &str,
    refusal: AuthorityRefusal<WalletError>,
) -> Envelope<()> {
    match refusal {
        AuthorityRefusal::Gate(e) => Envelope::<()>::err(&e),
        AuthorityRefusal::Refusal(MainnetRefusal::Denied { reason, .. }) => {
            Envelope::<()>::err_raw(
                reason.wire_code(),
                format!("{verb} operation denied by operator policy"),
            )
        }
        AuthorityRefusal::Refusal(MainnetRefusal::Engine(
            e @ (PolicyError::AccountingOverflow | PolicyError::AccountingInvalid),
        )) => Envelope::<()>::err_raw(e.wire_code(), format!("{e}")),
        AuthorityRefusal::Refusal(MainnetRefusal::Engine(e)) => {
            Envelope::<()>::err_raw("policy.engine_required", format!("{e}"))
        }
        AuthorityRefusal::Refusal(MainnetRefusal::Clock(e)) => {
            crate::commands::policy_engine::clock_refusal(&e)
        }
        AuthorityRefusal::Internal(e) => {
            Envelope::<()>::err(&WalletError::Internal(InternalError::UnexpectedState {
                detail: e.to_string(),
            }))
        }
        AuthorityRefusal::ApprovalRequired { .. } => {
            Envelope::<()>::err(&WalletError::Internal(InternalError::UnexpectedState {
                detail: "the CLI authority wrapper requires a completed approval".to_owned(),
            }))
        }
    }
}

/// Records the operator's presence-gated consent to the mainnet write that
/// `summary` decodes, and returns its witness under `policy`.
///
/// The summary goes to stderr for orientation. The pending entry is parked in
/// the store at `store_path` and the store is released before the presence
/// wait, so other handles can use it meanwhile.
///
/// Under `operation`, the durable approval record of the operation governs.
/// A record that links an unattested entry runs the ceremony on that entry,
/// and one that links an attested entry completes its consent without a
/// ceremony. Without a record, the entries a crash left for the operation go,
/// the new entry is parked, and the record opens with `prepared` before the
/// presence wait. Every refusal after the open keeps entry and record, and the
/// witness returns only after the record's consent commits and the committed
/// record verifies the presented proof again, as [`verify_committed`] states.
/// A canonical intent consent verifies under `governing`, the fresh decision.
///
/// A kind the shared capability integrates runs in a different order: the
/// record opens with the held writer, its evidence is reserved, and only then
/// is the entry inserted and the summary shown. A contended writer reacquires
/// an existing record's slot through the keyed outbox instead. Attestation and
/// proof verification load the policy under the held admission, which drops
/// with the inbox and writer before the publication commit.
///
/// Without `operation`, a refusal after the entry was parked removes it while
/// it is still the unattested record parked here.
///
/// # Errors
///
/// `internal.unexpected_state` for an approval rule without `operation`, or
/// an operation outside `Prepared` without a record; for an integrated kind,
/// `audit.outbox_evidence_unusable` for an unready scope, uninitialized
/// evidence or an unresolved migration pin, `approval.evidence_capacity` for
/// a full scope, and `approval.attestation_invalid` for a linked entry whose
/// signed facts differ from the record;
/// `approval.presence_unavailable` when the summary cannot be shown; the
/// summary's, the attestation key's and the consent sink's refusals before
/// anything is parked; the store refusals of the record's read, open and
/// consent; the presence refusals of [`acquire_mainnet_presence`]; and the
/// attester's, the store's and the witness's refusals; under `operation`
/// also the refusals of [`verify_committed`].
#[allow(
    clippy::too_many_arguments,
    reason = "the ceremony takes each input explicitly"
)]
pub(crate) async fn confirm_mainnet_write(
    summary: &MainnetWriteSummary,
    decision: ConfirmDecision,
    context: &MainnetWriteContext,
    policy: &VerifiedPolicy,
    store_path: &Path,
    operation: Option<&OperationHandle>,
    prepared: PolicyDecision,
    governing: &MainnetDecision,
) -> Result<ApprovalWitness, WalletError> {
    if matches!(decision, ConfirmDecision::RequireApproval { .. }) && operation.is_none() {
        return Err(WalletError::Internal(InternalError::UnexpectedState {
            detail: "a mainnet approval requires its operation record".to_owned(),
        }));
    }
    let profile = context.profile();
    let name = context.profile_name();
    let authority = MainnetApprovalAuthority::for_profile(name)?;
    let intent = operation
        .map(|handle| {
            stellar_agent_network::operation_entry::preparation_intent(handle, profile, policy)
        })
        .transpose()?
        .flatten();
    let check = operation.map(|handle| CommitCheck {
        operation: handle,
        expected: ApprovalExpectation {
            kind: summary.kind,
            subject: approval_subject_classic(&summary.envelope),
        },
        intent: intent.as_ref().map(|intent| (intent, governing)),
    });
    let mut rendered = Vec::new();
    if let Some(intent) = intent.as_ref() {
        super::intent_summary::write(intent, &mut rendered)
            .and_then(|()| writeln!(&mut rendered, "{CONSENT_LINE}"))
    } else {
        summary.render(context, &mut rendered)
    }
    .map_err(|_| WalletError::Approval(ApprovalFailure::PresenceUnavailable))?;
    if crate::commands::profile::policy_check::has_signed_origin(name, profile) {
        rendered = String::from_utf8(rendered)
            .map_err(|_| WalletError::Approval(ApprovalFailure::PresenceUnavailable))?
            .replace(CONSENT_LINE, SIGNED_CONSENT_LINE)
            .into_bytes();
    }
    let integrated = profile.chain_id.is_mainnet() && delivery_enforced(name, summary.kind);
    if !integrated {
        show_summary(&rendered)?;
    }
    let uid = process_uid_for_attestation().map_err(store_error)?;
    let ttl_ms = decision.ttl_ms();
    let mut entry = summary.pending(uid, ttl_ms)?;
    stellar_agent_network::operation_entry::stage_pending(&mut entry, intent.as_ref(), ttl_ms)?;
    if intent.is_some()
        && let ApprovalKind::PaymentSimulated { summary_memo, .. } = &mut entry.kind
    {
        // This legacy ASCII text field cannot represent typed or Unicode memos.
        // Canonical views read the authenticated intent and retained XDR.
        *summary_memo = None;
    }
    // The key and the sink are checked before the entry is parked, so a
    // profile that cannot record consent parks nothing; both are acquired
    // again after the wait.
    load_attestation_key(
        &profile.attestation_key_id,
        &OwnerKeyContext::for_profile(name, profile),
    )?;
    drop(acquire_operator_row_sink(profile, name)?);
    let mut reservation = None;
    let entry = match &check {
        None => {
            open_store(store_path)?
                .insert(entry.clone(), entry.created_at_unix_ms)
                .map_err(store_error)?;
            entry
        }
        Some(check) => {
            let handle = check.operation;
            let facts = pending_approval_facts(
                &entry,
                handle,
                summary.kind,
                approval_subject_classic(&summary.envelope),
                entry
                    .expires_at_unix_ms
                    .checked_sub(entry.created_at_unix_ms)
                    .ok_or_else(|| {
                        wrong_kind("the signed approval interval ends before it starts")
                    })?,
            );
            let start = if integrated {
                let (start, admitted) =
                    start_integrated(context, store_path, handle, entry, &facts, prepared)?;
                reservation = Some(admitted);
                start
            } else {
                start_durable(context, store_path, handle, entry, &facts, prepared)?
            };
            match start {
                DurableStart::Ceremony(entry) => *entry,
                DurableStart::Recover(nonce) => {
                    let admission = authority.admit()?;
                    return commit_durable(
                        open_store(store_path)?,
                        context,
                        policy,
                        &nonce,
                        ConsentRow::Recovered,
                        admission,
                        integrated,
                        check,
                    );
                }
            }
        }
    };
    if integrated {
        show_summary(&rendered)?;
    }
    let approval_context = ApprovalContext::from_profile(name, profile);
    // Boxed so callers' futures do not carry the presence ceremony's state.
    let result = match Box::pin(acquire_mainnet_presence(
        &entry,
        &approval_context,
        &authority,
        store_path,
    ))
    .await
    {
        Ok(presence) => persist_confirmation(
            summary,
            context,
            policy,
            store_path,
            &entry,
            presence,
            check.as_ref(),
            reservation,
        ),
        Err(error) => Err(error),
    };
    if result.is_err() && operation.is_none() {
        discard_parked(store_path, &entry);
    }
    result
}

/// How a ceremony under an operation proceeds after reading its record.
enum DurableStart {
    /// Run the ceremony on this entry, which the record names.
    Ceremony(Box<PendingApproval>),
    /// The record names this attested entry: complete its consent.
    Recover(String),
}

/// Opens the winner with the held writer, then reserves before any inbox
/// insertion. A missing winner entry refuses unless this call owns its facts.
fn start_integrated(
    context: &MainnetWriteContext,
    store_path: &Path,
    handle: &OperationHandle,
    entry: PendingApproval,
    facts: &PendingApprovalFacts,
    prepared: PolicyDecision,
) -> Result<(DurableStart, EvidenceReservation), WalletError> {
    let profile = context.profile();
    let name = context.profile_name();
    let window = PersistedWindowStore::for_profile(name);
    let status = ApprovalStatus::new(&window, profile);
    let outbox = consent_outbox(profile, name)?;
    let present = |record: &stellar_agent_network::policy_state::WireApproval,
                   reservation: &EvidenceReservation| {
        let mut pending = open_store(store_path)?;
        let linked = match pending.get(&record.nonce) {
            Some(linked) => linked.clone(),
            None if record.facts() == *facts => {
                remove_orphans(&mut pending, &status, handle)?;
                pending
                    .insert(entry.clone(), entry.created_at_unix_ms)
                    .map_err(store_error)?;
                entry
            }
            None => {
                return Err(WalletError::Approval(ApprovalFailure::NotFound {
                    detail: "the operation's approval entry is gone; prepare the operation again"
                        .to_owned(),
                }));
            }
        };
        // The entry's subject kind selects the subject, as the approver does.
        let subject = if linked.subject_kind
            == stellar_agent_core::approval::subject::SubjectKind::IntentDigest
        {
            handle.intent().intent_digest()
        } else {
            stellar_agent_core::approval::mainnet_consent_subject(
                &linked,
                &AttestationBinding::new(name, profile.chain_id.caip2_str()),
            )?
        };
        if pending_approval_facts(
            &linked,
            handle,
            record.kind,
            record.subject,
            record.rule_ttl_ms,
        ) != record.facts()
            || subject != record.subject
        {
            return Err(WalletError::Approval(ApprovalFailure::AttestationInvalid {
                detail: "the approval does not match the signed inbox facts".to_owned(),
            }));
        }
        let start = if linked.attestation_blob_b64.is_some() {
            DurableStart::Recover(linked.approval_nonce)
        } else {
            DurableStart::Ceremony(Box::new(linked))
        };
        Ok((start, reservation.clone()))
    };
    match acquire_operator_row_sink(profile, name)? {
        OperatorRowSink::Writer(writer) => {
            let mut writer = writer.lock().map_err(|_| {
                WalletError::from(ValidationError::AuditWriterOpenFailed {
                    profile: name.to_owned(),
                })
            })?;
            ConsentAdmission {
                store: &window,
                profile,
                writer: &mut writer,
                outbox: &outbox,
            }
            .admit(
                handle.id(),
                facts,
                |writer, facts| {
                    if handle.state() != OperationState::Prepared {
                        return Err(approval_requires_prepared());
                    }
                    ApprovalRecorder::new(
                        &window,
                        profile,
                        writer,
                        uuid::Uuid::new_v4().to_string(),
                    )
                    .open_pending(handle.id(), facts, prepared)
                    .map_err(operation_refusal)
                },
                present,
            )
        }
        OperatorRowSink::Outbox(outbox) => {
            let record = status
                .find_by_operation(handle.id())
                .map_err(operation_refusal)?
                .ok_or_else(|| {
                    stellar_agent_core::audit_log::audit_writer_refusal(
                        name,
                        &stellar_agent_core::audit_log::WriterError::FileLocked,
                    )
                })?
                .record;
            let reservation = ConsentAdmission::reacquire(
                &window,
                profile,
                record.operation_id,
                &record.facts(),
                &outbox,
            )?;
            present(&record, &reservation)
        }
    }
}

/// Reads the durable record of `handle`'s operation and, without one, parks
/// `entry` and opens the record with `facts` and `prepared`.
///
/// A refused open removes the entry unless a read by operation shows a
/// record naming it, so a record never names a removed entry.
fn start_durable(
    context: &MainnetWriteContext,
    store_path: &Path,
    handle: &OperationHandle,
    entry: PendingApproval,
    facts: &PendingApprovalFacts,
    prepared: PolicyDecision,
) -> Result<DurableStart, WalletError> {
    drop(open_store(store_path)?);
    let _producer = stellar_agent_network::operation_entry::approval_producer_lock(
        &store_path.with_extension("producer.lock"),
    )?;
    let window = PersistedWindowStore::for_profile(context.profile_name());
    let status = ApprovalStatus::new(&window, context.profile());
    if let Some(view) = status
        .find_by_operation(handle.id())
        .map_err(operation_refusal)?
    {
        return linked_durable_start(store_path, &view.record.nonce);
    }
    if handle.state() != OperationState::Prepared {
        return Err(approval_requires_prepared());
    }
    {
        let mut store = open_store(store_path)?;
        remove_orphans(&mut store, &status, handle)?;
        store
            .insert(entry.clone(), entry.created_at_unix_ms)
            .map_err(store_error)?;
    }
    let opened = approval_step(context, |recorder| {
        recorder
            .open_pending(handle.id(), facts, prepared)
            .map_err(operation_refusal)
    });
    if let Err(error) = opened {
        let linked = status.find_by_operation(handle.id());
        if matches!(&linked, Ok(view) if view.as_ref().is_none_or(|v| v.record.nonce != entry.approval_nonce))
        {
            discard_parked(store_path, &entry);
        }
        if let Ok(Some(view)) = linked
            && view.record.nonce != entry.approval_nonce
        {
            return linked_durable_start(store_path, &view.record.nonce);
        }
        return Err(error);
    }
    Ok(DurableStart::Ceremony(Box::new(entry)))
}

fn linked_durable_start(store_path: &Path, nonce: &str) -> Result<DurableStart, WalletError> {
    let linked = open_store(store_path)?.get(nonce).cloned().ok_or_else(|| {
        WalletError::Approval(ApprovalFailure::NotFound {
            detail: "the operation's approval entry is gone; prepare the operation again"
                .to_owned(),
        })
    })?;
    Ok(if linked.attestation_blob_b64.is_some() {
        DurableStart::Recover(linked.approval_nonce)
    } else {
        DurableStart::Ceremony(Box::new(linked))
    })
}

/// Removes the unattested live value entries of `handle`'s envelope that no
/// durable record names: the entries a crash between their insert and the
/// record's open leaves.
fn remove_orphans(
    store: &mut PendingApprovalStore,
    status: &ApprovalStatus<'_>,
    handle: &OperationHandle,
) -> Result<(), WalletError> {
    let Some(envelope) = handle.envelope_xdr().map(approval_subject_classic) else {
        return Ok(());
    };
    let envelope = stellar_agent_core::hex::encode(&envelope);
    for view in store.snapshot(clock_now()?) {
        let Some(stored) = store.get(&view.approval_nonce) else {
            continue;
        };
        let (ApprovalKind::PaymentSimulated {
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
        }) = &stored.kind
        else {
            continue;
        };
        if view.expired
            || stored.attestation_blob_b64.is_some()
            || *envelope_sha256_hex != envelope
            || status
                .find_by_nonce(&view.approval_nonce)
                .map_err(operation_refusal)?
                .is_some()
        {
            continue;
        }
        store.remove(&view.approval_nonce).map_err(store_error)?;
    }
    Ok(())
}

/// What a committed consent must approve, taken from the request and its
/// admitted operation, never from the durable record.
struct CommitCheck<'a> {
    /// The operation this command admitted.
    operation: &'a OperationHandle,
    /// The requested kind and envelope subject.
    expected: ApprovalExpectation,
    /// The operation's canonical intent and the fresh decision governing it.
    intent: Option<(&'a ClassicIntent, &'a MainnetDecision)>,
}

/// Captures the attestation of `nonce` in `pending`, verifies the attested
/// entry against its durable record, releases the inbox, commits the consent
/// and returns the witness of [`verify_committed`]. `row` states where the
/// consent row went; `published` selects the verified publication handoff of
/// an integrated consent.
#[allow(
    clippy::too_many_arguments,
    reason = "completion retains its policy admission and delivery choice"
)]
fn commit_durable(
    pending: PendingApprovalStore,
    context: &MainnetWriteContext,
    policy: &VerifiedPolicy,
    nonce: &str,
    row: ConsentRow,
    admission: PolicyAdmission,
    published: bool,
    check: &CommitCheck<'_>,
) -> Result<ApprovalWitness, WalletError> {
    let profile = context.profile();
    let window = PersistedWindowStore::for_profile(context.profile_name());
    let presented = persisted_attestation(&pending, nonce)?;
    let completion = if published {
        super::consent::publication_completion(
            pending,
            profile,
            context.profile_name(),
            nonce,
            policy,
            admission,
        )?
    } else {
        let completion = consent_completion(
            &pending,
            &window,
            profile,
            context.profile_name(),
            nonce,
            policy,
            row,
            &admission,
        )?;
        drop(pending);
        drop(admission);
        completion
    };
    commit_consent(&window, profile, &completion)?;
    #[cfg(all(test, feature = "mainnet-write"))]
    commit_test::run(context.profile_name(), nonce);
    verify_committed(context, policy, nonce, &presented, check)
}

/// Verifies `presented`, the attestation captured for `nonce` before the
/// inbox was released, against the committed durable record, and returns the
/// witness that grants authority. The inbox is not read, so collecting or
/// locking it after the commit changes nothing.
///
/// The verification time is the wall clock, raised to the consent evidence
/// floor when the requested kind enforces delivery.
///
/// # Errors
///
/// In the order the check runs: `submission.record_unavailable` when the
/// receipt store cannot be read, and `approval.consumed` when a submission
/// receipt names the nonce, both before any durable read; the store
/// refusals of the record's read; `approval.clock_error` when the wall clock
/// cannot be read; `audit.*` when the evidence floor cannot be read; the
/// refusals of [`verify_durable_approval`] or
/// [`verify_durable_intent_approval`], including `approval.not_found`,
/// `approval.revoked`, `approval.expired` and `approval.attestation_invalid`;
/// and `approval.consumed` when the record belongs to another operation.
fn verify_committed(
    context: &MainnetWriteContext,
    policy: &VerifiedPolicy,
    nonce: &str,
    presented: &[u8; 32],
    check: &CommitCheck<'_>,
) -> Result<ApprovalWitness, WalletError> {
    let profile = context.profile();
    let name = context.profile_name();
    let receipt = ReceiptStore::open(name)
        .and_then(|receipts| receipts.find_by_approval_nonce(nonce))
        .map_err(|error| {
            WalletError::Submission(SubmissionError::ReceiptStoreUnreadable {
                detail: error.to_string(),
            })
        })?;
    if receipt.is_some() {
        return Err(WalletError::Approval(ApprovalFailure::Consumed {
            detail: "this approval was already spent on a submission".to_owned(),
        }));
    }
    let window = PersistedWindowStore::for_profile(name);
    let facts = ApprovalStatus::new(&window, profile)
        .facts_by_nonce(nonce)
        .map_err(operation_refusal)?;
    let mut now = clock_now()?;
    if delivery_enforced(name, check.expected.kind) {
        now = now.max(consent_evidence_time_floor(profile, name)?);
    }
    let witness = match check.intent {
        Some((intent, decision)) => verify_durable_intent_approval(
            facts.as_ref(),
            presented,
            profile,
            name,
            intent,
            decision,
            policy,
            now,
        ),
        None => verify_durable_approval(
            facts.as_ref(),
            presented,
            profile,
            name,
            &check.expected,
            policy,
            now,
        ),
    }?;
    if facts.map(|facts| facts.record().operation_id) != Some(*check.operation.id().as_bytes()) {
        return Err(WalletError::Approval(ApprovalFailure::Consumed {
            detail: "this approval belongs to another operation".to_owned(),
        }));
    }
    Ok(witness)
}

/// Runs a test's action between the consent commit and [`verify_committed`].
#[cfg(all(test, feature = "mainnet-write"))]
pub(crate) mod commit_test {
    use std::cell::RefCell;
    type Hook = Box<dyn FnOnce(&str)>;
    thread_local! { static HOOK: RefCell<Option<(String, Hook)>> = const { RefCell::new(None) }; }
    /// Removes the action when dropped.
    pub(crate) struct Guard;
    impl Drop for Guard {
        fn drop(&mut self) {
            HOOK.with_borrow_mut(|hook| *hook = None);
        }
    }
    /// Runs `hook` with the nonce after the next commit of profile `name`.
    pub(crate) fn after_commit(name: &str, hook: impl FnOnce(&str) + 'static) -> Guard {
        HOOK.with_borrow_mut(|slot| *slot = Some((name.to_owned(), Box::new(hook))));
        Guard
    }
    pub(super) fn run(name: &str, nonce: &str) {
        let hook = HOOK.with_borrow_mut(|slot| {
            if slot.as_ref().is_some_and(|(owner, _)| owner == name) {
                slot.take().map(|(_, hook)| hook)
            } else {
                None
            }
        });
        if let Some(hook) = hook {
            hook(nonce);
        }
    }
}

/// The wall clock in Unix milliseconds, refused as `approval.clock_error`.
fn clock_now() -> Result<u64, WalletError> {
    stellar_agent_core::timefmt::now_unix_ms().map_err(|error| {
        WalletError::Approval(ApprovalFailure::ClockError {
            detail: error.to_string(),
        })
    })
}

/// Writes the rendered summary to stderr.
#[cfg(not(test))]
fn show_summary(rendered: &[u8]) -> Result<(), WalletError> {
    let mut stderr = std::io::stderr();
    stderr
        .write_all(rendered)
        .and_then(|()| stderr.flush())
        .map_err(|_| WalletError::Approval(ApprovalFailure::PresenceUnavailable))
}

#[cfg(test)]
thread_local! {
    /// The summaries the confirmation showed on this thread, oldest first.
    static SHOWN_SUMMARIES: std::cell::RefCell<Vec<String>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Records the rendered summary on this thread in place of stderr.
#[cfg(test)]
#[expect(
    clippy::unnecessary_wraps,
    reason = "the signature of the stderr implementation"
)]
fn show_summary(rendered: &[u8]) -> Result<(), WalletError> {
    SHOWN_SUMMARIES.with(|shown| {
        shown
            .borrow_mut()
            .push(String::from_utf8_lossy(rendered).into_owned());
    });
    Ok(())
}

/// The summaries the confirmation showed on this thread, oldest first.
#[cfg(all(test, feature = "mainnet-write"))]
pub(crate) fn shown_summaries() -> Vec<String> {
    SHOWN_SUMMARIES.with(|shown| shown.borrow().clone())
}

/// Forgets the summaries shown on this thread.
#[cfg(all(test, feature = "mainnet-write"))]
pub(crate) fn clear_shown_summaries() {
    SHOWN_SUMMARIES.with(|shown| shown.borrow_mut().clear());
}

fn open_store(store_path: &Path) -> Result<PendingApprovalStore, WalletError> {
    open_with_retry(store_path, DEFAULT_RETRY_ATTEMPTS, DEFAULT_RETRY_BACKOFF)
        .map_err(|error| crate::commands::approve::approval_store_open_error(&error))
}

/// Removes the entry this confirmation parked while the store still holds it
/// unattested with the parked lifetime; a record another handle attested or
/// replaced stays.
fn discard_parked(store_path: &Path, entry: &PendingApproval) {
    let Ok(mut store) = open_store(store_path) else {
        return;
    };
    let parked = store.get(&entry.approval_nonce).is_some_and(|stored| {
        stored.attestation_blob_b64.is_none()
            && stored.created_at_unix_ms == entry.created_at_unix_ms
            && stored.expires_at_unix_ms == entry.expires_at_unix_ms
    });
    if parked && let Err(error) = store.remove(&entry.approval_nonce) {
        tracing::debug!(code = %record_error(&error).code(), "parked mainnet entry not removed");
    }
}

/// Attests `entry` under `presence` and returns its witness. A confirmation
/// with a `durable` check then commits the consent to the operation's record,
/// retaining the queued row's reference, and returns the witness only after
/// that commit and the check.
#[allow(
    clippy::too_many_arguments,
    reason = "the ceremony's inputs and its durable choice are each explicit"
)]
fn persist_confirmation(
    summary: &MainnetWriteSummary,
    context: &MainnetWriteContext,
    policy: &VerifiedPolicy,
    store_path: &Path,
    entry: &PendingApproval,
    presence: VerifiedMainnetPresence,
    durable: Option<&CommitCheck<'_>>,
    reservation: Option<EvidenceReservation>,
) -> Result<ApprovalWitness, WalletError> {
    let profile = context.profile();
    let name = context.profile_name();
    let published = reservation.is_some();
    let admission = MainnetApprovalAuthority::for_profile(name)?.admit()?;
    let mut pending = open_store(store_path)?;
    let key = load_attestation_key(
        &profile.attestation_key_id,
        &OwnerKeyContext::for_profile(name, profile),
    )?;
    let sink = acquire_operator_row_sink(profile, name)?;
    let binding = AttestationBinding::new(name, context.chain().caip2_str());
    let attest = |pending: &mut PendingApprovalStore, audit, presence| {
        attest_mainnet_confirmation_admitted_with_row(
            pending,
            entry,
            &key,
            &binding,
            audit,
            summary.policy_tool,
            policy,
            presence,
            &admission,
        )
    };
    let row = match sink {
        OperatorRowSink::Writer(writer) => {
            let mut guard = writer.lock().map_err(|_| {
                WalletError::from(ValidationError::AuditWriterOpenFailed {
                    profile: name.to_owned(),
                })
            })?;
            attest(&mut pending, ConsentAudit::Writer(&mut guard), presence)?;
            ConsentRow::Written
        }
        OperatorRowSink::Outbox(outbox) if durable.is_some() => {
            let outbox = match reservation {
                Some(reservation) => outbox.with_evidence_reservation(reservation),
                None => outbox,
            };
            attest(&mut pending, ConsentAudit::Outbox(&outbox), presence)?
                .map(ConsentRow::Queued)
                .ok_or_else(|| {
                    WalletError::Internal(InternalError::UnexpectedState {
                        detail: "the queued consent row has no reference".to_owned(),
                    })
                })?
        }
        OperatorRowSink::Outbox(outbox) => {
            attest(&mut pending, ConsentAudit::Outbox(&outbox), presence)?;
            ConsentRow::Written
        }
    };
    if let Some(check) = durable {
        return commit_durable(
            pending,
            context,
            policy,
            &entry.approval_nonce,
            row,
            admission,
            published,
            check,
        );
    }
    let attestation = persisted_attestation(&pending, &entry.approval_nonce)?;
    let now = clock_now()?;
    verify_approval_admitted(
        &pending,
        profile,
        name,
        &entry.approval_nonce,
        &attestation,
        &ApprovalExpectation {
            kind: summary.kind,
            subject: approval_subject_classic(&summary.envelope),
        },
        policy,
        now,
        &admission,
    )
}

#[cfg(test)]
pub(crate) mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, reason = "test assertions")]
    #[cfg(feature = "mainnet-write")]
    #[allow(clippy::expect_used, reason = "behavior assertions")]
    pub(crate) mod canonical_consent_tests {
        include!("canonical_consent_tests.rs");
    }
    #[cfg(feature = "mainnet-write")]
    pub(crate) mod committed;
    #[cfg(feature = "mainnet-write")]
    mod publication;
    use super::*;
    #[cfg(feature = "mainnet-write")]
    use crate::common::mainnet_presence::driver;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    #[cfg(feature = "mainnet-write")]
    use stellar_agent_core::approval::mainnet_fixtures::MainnetConsentFixture;
    #[test]
    fn confirm_ttl_follows_decision() {
        assert_eq!(ConfirmDecision::Allow.ttl_ms(), 600_000);
        assert_eq!(
            ConfirmDecision::RequireApproval { ttl_ms: 17_000 }.ttl_ms(),
            17_000
        );
    }
    #[test]
    #[serial_test::serial]
    fn summary_renders_envelope_legs() {
        use stellar_agent_test_support::SignedTestEnvelope;
        use stellar_xdr::{Hash, Limits, Memo, WriteXdr as _};
        #[cfg(feature = "mainnet-write")]
        let (_dir, context, _) = confirmation_fixture("confirm-memos");
        let built = SignedTestEnvelope::builder([8; 32])
            .unsigned()
            .amount_stroops(17)
            .build();
        for (memo, rendered) in [
            (Memo::None, "none".to_owned()),
            (
                Memo::Text(b"order".to_vec().try_into().unwrap()),
                "text \"order\"".into(),
            ),
            (
                Memo::Text("café\u{202e}".as_bytes().to_vec().try_into().unwrap()),
                "text \"café\u{202e}\"".into(),
            ),
            (Memo::Id(7), "id 7".into()),
            (
                Memo::Hash(Hash([1; 32])),
                format!("hash {}", "01".repeat(32)),
            ),
            (
                Memo::Return(Hash([2; 32])),
                format!("return {}", "02".repeat(32)),
            ),
        ] {
            let TransactionEnvelope::Tx(mut tx) =
                TransactionEnvelope::from_xdr_base64(built.envelope_xdr(), Limits::none()).unwrap()
            else {
                unreachable!()
            };
            tx.tx.memo = memo;
            let summary = MainnetWriteSummary::from_envelope(
                &TransactionEnvelope::Tx(tx)
                    .to_xdr_base64(Limits::none())
                    .unwrap(),
                MainnetConsumer::CliPay,
                500,
            )
            .unwrap();
            assert_eq!(summary.memo, rendered);
            #[cfg(feature = "mainnet-write")]
            {
                let mut output = Vec::new();
                summary.render(&context, &mut output).unwrap();
                assert!(String::from_utf8(output).unwrap().contains(&format!(
                    "Memo: {}",
                    crate::common::render::escape_for_terminal(&rendered)
                )));
            }
            assert_eq!(summary.fee_cap, 500);
            let ValueClass::Value(value) = &summary.value else {
                panic!("value legs missing")
            };
            assert_eq!(value.legs()[0].amount, Some(17));
            assert_eq!(
                value.legs()[0].destination.as_deref(),
                Some(built.destination())
            );
            let pending = summary.pending("1000".into(), 600_000).unwrap();
            assert_eq!(
                pending.expires_at_unix_ms - pending.created_at_unix_ms,
                600_000
            );
        }
    }

    #[test]
    #[cfg(feature = "mainnet-write")]
    #[serial_test::serial]
    fn summary_renders_every_classic_consumer() {
        use stellar_xdr::*;
        let (_dir, context, envelope) = confirmation_fixture("confirm-summary");
        let TransactionEnvelope::Tx(original) =
            TransactionEnvelope::from_xdr_base64(&envelope, Limits::none()).unwrap()
        else {
            unreachable!()
        };
        let OperationBody::Payment(payment) = &original.tx.operations[0].body else {
            unreachable!()
        };
        let destination = match &payment.destination {
            MuxedAccount::Ed25519(key) => AccountId(PublicKey::PublicKeyTypeEd25519(key.clone())),
            _ => unreachable!(),
        };
        let issuer = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([7; 32])));
        let credit = AlphaNum4 {
            asset_code: AssetCode4(*b"USD\0"),
            issuer,
        };
        let cases = [
            (
                MainnetConsumer::CliPay,
                OperationBody::PathPaymentStrictReceive(PathPaymentStrictReceiveOp {
                    send_asset: Asset::Native,
                    send_max: 23,
                    destination: payment.destination.clone(),
                    dest_asset: Asset::CreditAlphanum4(credit.clone()),
                    dest_amount: 19,
                    path: vec![].try_into().unwrap(),
                }),
                vec![
                    "Action: Payment",
                    "Amount: 23",
                    "Action: PathPaymentReceive",
                    "Amount: 19",
                ],
            ),
            (
                MainnetConsumer::CliCreateAccount,
                OperationBody::CreateAccount(CreateAccountOp {
                    destination,
                    starting_balance: 29,
                }),
                vec!["Action: AccountCreation", "Amount: 29", "Asset: native"],
            ),
            (
                MainnetConsumer::CliTrustline,
                OperationBody::ChangeTrust(ChangeTrustOp {
                    line: ChangeTrustAsset::CreditAlphanum4(credit),
                    limit: 31,
                }),
                vec!["Action: Trustline", "Asset: USD:"],
            ),
            (
                MainnetConsumer::CliClaim,
                OperationBody::ClaimClaimableBalance(ClaimClaimableBalanceOp {
                    balance_id: ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash([4; 32])),
                }),
                vec![
                    "Action: Claim",
                    "not known to the wallet before the claim",
                    "Balance ID: B",
                ],
            ),
        ];
        for (consumer, body, expected) in cases {
            let mut tx = original.clone();
            tx.tx.operations = vec![Operation {
                source_account: None,
                body,
            }]
            .try_into()
            .unwrap();
            let encoded = TransactionEnvelope::Tx(tx)
                .to_xdr_base64(Limits::none())
                .unwrap();
            let summary = MainnetWriteSummary::from_envelope(&encoded, consumer, 500).unwrap();
            let mut output = Vec::new();
            summary.render(&context, &mut output).unwrap();
            let output = String::from_utf8(output).unwrap();
            for expected in expected {
                assert!(output.contains(expected), "{output}");
            }
            for decision in [
                ConfirmDecision::Allow,
                ConfirmDecision::RequireApproval { ttl_ms: 300_000 },
            ] {
                let ttl = decision.ttl_ms();
                let entry = summary.pending("1000".into(), ttl).unwrap();
                assert_eq!(entry.expires_at_unix_ms - entry.created_at_unix_ms, ttl);
            }
            assert!(output.contains(context.profile_name()));
            assert!(output.contains(context.authority()));
            assert!(output.contains("stellar:mainnet"));
            assert!(output.contains(&summary.string("source")));
            assert!(output.contains("Fee: 100 stroops"));
            assert!(output.ends_with(&format!("{CONSENT_LINE}\n")), "{output}");
            assert!(!output.contains("Type the profile name"), "{output}");
        }
    }

    /// The ledger the operational check observed renders as one line after
    /// the fee lines and before the consent line; a summary without it
    /// renders no ledger line.
    #[test]
    #[cfg(feature = "mainnet-write")]
    #[serial_test::serial]
    fn summary_names_the_ledger_after_the_fee_lines() {
        let (_dir, context, envelope) = confirmation_fixture("confirm-ledger");
        let render = |summary: &MainnetWriteSummary| {
            let mut output = Vec::new();
            summary.render(&context, &mut output).unwrap();
            String::from_utf8(output).unwrap()
        };
        let plain =
            MainnetWriteSummary::from_envelope(&envelope, MainnetConsumer::CliPay, 500).unwrap();
        assert!(!render(&plain).contains("Ledger "), "{}", render(&plain));

        let summary = plain.with_ledger(OperationalReport {
            latest_ledger: 2000,
            close_time_unix: 1_800_000_000,
            close_lag_seconds: 4,
        });
        let output = render(&summary);
        assert!(
            output.ends_with(&format!(
                "Fee cap: 500 stroops per operation\nLedger 2000, closed 4 s ago\n{CONSENT_LINE}\n"
            )),
            "{output}"
        );
    }

    /// A trustline envelope with `asset_code` and a text memo of `memo`
    /// bytes, built from the confirmation fixture's envelope.
    #[cfg(feature = "mainnet-write")]
    fn trustline_envelope(envelope: &str, asset_code: [u8; 4], memo: &[u8]) -> String {
        use stellar_xdr::*;
        let TransactionEnvelope::Tx(mut tx) =
            TransactionEnvelope::from_xdr_base64(envelope, Limits::none()).unwrap()
        else {
            unreachable!()
        };
        tx.tx.memo = Memo::Text(memo.to_vec().try_into().unwrap());
        tx.tx.operations = vec![Operation {
            source_account: None,
            body: OperationBody::ChangeTrust(ChangeTrustOp {
                line: ChangeTrustAsset::CreditAlphanum4(AlphaNum4 {
                    asset_code: AssetCode4(asset_code),
                    issuer: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([7; 32]))),
                }),
                limit: 31,
            }),
        }]
        .try_into()
        .unwrap();
        TransactionEnvelope::Tx(tx)
            .to_xdr_base64(Limits::none())
            .unwrap()
    }

    /// An asset code holding control bytes cannot be shown faithfully, so the
    /// confirmation refuses the envelope before it renders anything, and the
    /// refusal carries none of the raw bytes.
    #[test]
    #[cfg(feature = "mainnet-write")]
    #[serial_test::serial]
    fn summary_refuses_an_asset_code_it_cannot_show() {
        let (_dir, _context, envelope) = confirmation_fixture("confirm-asset");
        let encoded = trustline_envelope(&envelope, [b'U', 0x1b, b'[', 0x07], b"order");
        let Err(error) =
            MainnetWriteSummary::from_envelope(&encoded, MainnetConsumer::CliTrustline, 500)
        else {
            panic!("an asset code with control bytes must be refused");
        };
        assert_eq!(error.code(), "protocol.xdr_codec_failed");
        let message = error.message();
        assert!(message.contains("asset code"), "{message}");
        assert!(!message.contains('\u{1b}'), "{message:?}");
        assert!(!message.contains('\u{7}'), "{message:?}");
    }

    /// A value that decodes is rendered with every control character as a
    /// visible escape: the memo's cursor and bell bytes reach the terminal
    /// only as `\u{1b}` and `\u{7}`.
    #[test]
    #[cfg(feature = "mainnet-write")]
    #[serial_test::serial]
    fn summary_escapes_control_characters_it_shows() {
        let (_dir, context, envelope) = confirmation_fixture("confirm-memo-escape");
        let encoded = trustline_envelope(&envelope, *b"USD\0", b"U\x1b[2K\x07");
        let summary =
            MainnetWriteSummary::from_envelope(&encoded, MainnetConsumer::CliTrustline, 500)
                .unwrap();
        let mut output = Vec::new();
        summary.render(&context, &mut output).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(
            output.contains("Memo: text \"U\\u{1b}[2K\\u{7}\""),
            "{output}"
        );
        assert!(!output.contains('\u{1b}'), "{output:?}");
        assert!(!output.contains('\u{7}'), "{output:?}");
    }

    /// The consent fixture of the confirmation tests, opted out of every
    /// kind's enforcement.
    #[cfg(feature = "mainnet-write")]
    pub(crate) type ConfirmationFixture =
        crate::common::unenforced_fixture::Unenforced<MainnetConsentFixture>;

    #[cfg(feature = "mainnet-write")]
    pub(crate) fn confirmation_fixture(
        name: &str,
    ) -> (ConfirmationFixture, MainnetWriteContext, String) {
        confirmation_fixture_with(name, |_| {})
    }
    /// An enabled mainnet profile whose owner-signed policy admits the
    /// test-support fixture credential, edited by `edit` before it is saved,
    /// and the write context built from it.
    #[cfg(feature = "mainnet-write")]
    fn confirmation_fixture_with(
        name: &str,
        edit: impl FnOnce(&mut stellar_agent_core::profile::schema::Profile),
    ) -> (ConfirmationFixture, MainnetWriteContext, String) {
        use stellar_agent_core::profile::name::ResolvedProfileName;
        // The served source account is at sequence 1, so its next
        // transaction carries sequence 2.
        let envelope = stellar_agent_test_support::SignedTestEnvelope::builder([8; 32])
            .unsigned()
            .sequence(2)
            .amount_stroops(17)
            .build();
        let source = envelope.source().to_owned();
        let fixture = MainnetConsentFixture::with_profile(name, |profile| {
            profile.mcp_signer_default.account = source;
            edit(profile);
        });
        let chain_key = &fixture.profile().audit_log_hash_chain_key_id;
        stellar_agent_network::keyring::rotate_keyring_secret_32(
            &chain_key.service,
            &chain_key.account,
        )
        .unwrap();
        let context = stellar_agent_network::NetworkContext::mainnet_write(
            fixture.profile(),
            &ResolvedProfileName::from_flag(name),
            &fixture.home().join("profiles"),
            stellar_agent_network::MainnetEndpointFlags::default(),
        )
        .unwrap();
        let fixture = ConfirmationFixture::new(fixture, context.profile_name());
        (fixture, context, envelope.envelope_xdr().to_owned())
    }

    /// Runs the confirmation of a payment summary of `envelope` under the
    /// fixture's current policy.
    #[cfg(feature = "mainnet-write")]
    async fn confirm(
        fixture: &MainnetConsentFixture,
        context: &MainnetWriteContext,
        summary: &MainnetWriteSummary,
    ) -> Result<ApprovalWitness, WalletError> {
        confirm_mainnet_write(
            summary,
            ConfirmDecision::Allow,
            context,
            &fixture.current_policy(),
            &fixture.store_path(),
            None,
            PolicyDecision::Allow,
            &governing(context, &fixture.current_policy(), 600_000),
        )
        .await
    }

    /// A fresh classic RequireApproval decision of `ttl_ms` under `policy`.
    #[cfg(feature = "mainnet-write")]
    pub(crate) fn governing(
        context: &MainnetWriteContext,
        policy: &VerifiedPolicy,
        ttl_ms: u64,
    ) -> MainnetDecision {
        MainnetDecision::for_test(
            Decision::RequireApproval(stellar_agent_core::policy::ApprovalRequest::new(
                "fixture".to_owned(),
                u32::try_from(ttl_ms / 1000).unwrap(),
            )),
            None,
            policy.digest(),
            policy.sequence(),
            7,
            context.profile_name(),
            context.chain().caip2_str(),
            1_900_000_000_000,
            ttl_ms,
            stellar_agent_core::mainnet::decision::AuthorityScope::Classic,
        )
    }

    /// The audit sink of fixture operation opens, which keeps no rows.
    #[cfg(feature = "mainnet-write")]
    struct NoRows;

    #[cfg(feature = "mainnet-write")]
    impl stellar_agent_network::policy_state::OperationAudit for NoRows {
        fn append(
            &mut self,
            _entry: stellar_agent_core::audit_log::AuditEntry,
        ) -> Result<(), String> {
            Ok(())
        }
    }

    /// A `Prepared` operation under `business_id` whose slot binds `envelope`.
    #[cfg(feature = "mainnet-write")]
    pub(crate) fn prepared_operation(
        context: &MainnetWriteContext,
        business_id: &str,
        envelope: &str,
    ) -> OperationHandle {
        use stellar_agent_network::operation_entry::{envelope_max_time, envelope_slot};
        use stellar_agent_network::policy_state::{
            BusinessId, OpenOutcome, OpenRequest, OperationKind, OperationRecorder, OperationTool,
        };
        let store = PersistedWindowStore::for_profile(context.profile_name());
        let opened = OperationRecorder::new(&store, context.profile(), &mut NoRows, "fixture")
            .open(&OpenRequest {
                business_id: BusinessId::parse(business_id).unwrap(),
                tool: OperationTool::CliPay,
                kind: OperationKind::Pay,
                intent: envelope_slot(&[7; 32], envelope, envelope_max_time(envelope).unwrap()),
                envelope_xdr: Some(envelope.to_owned()),
                prepared_decision: None,
                rule_ttl_ms: None,
            })
            .unwrap();
        let OpenOutcome::New(handle) = opened else {
            panic!("a new operation")
        };
        handle
    }

    /// Authority keeps the governing facts and borrows the caller's consent slot.
    #[cfg(feature = "mainnet-write")]
    #[tokio::test(flavor = "current_thread")]
    #[serial_test::serial]
    async fn cli_mainnet_authority_follows_the_decision() {
        use stellar_agent_core::mainnet::decision::AuthorityScope;
        use stellar_agent_core::policy::ApprovalRequest;
        let (fixture, context, envelope) = confirmation_fixture("authority-wrapper");
        clear_shown_summaries();
        let _presence = driver::install(driver::fixture_credential());
        let summary =
            MainnetWriteSummary::from_envelope(&envelope, MainnetConsumer::CliPay, 500).unwrap();
        let policy = fixture.current_policy();
        let decision = MainnetDecision::for_test(
            Decision::Allow,
            None,
            policy.digest(),
            policy.sequence(),
            7,
            context.profile_name(),
            context.chain().caip2_str(),
            1_900_000_000_000,
            600_000,
            AuthorityScope::Classic,
        );
        let mut witness = None;
        let authority = cli_mainnet_authority(
            &decision,
            ConfirmDecision::Allow,
            &summary,
            &context,
            &policy,
            &fixture.store_path(),
            None,
            PolicyDecision::Allow,
            &mut witness,
        )
        .await
        .unwrap();
        let MainnetAuthority::Policy(authority) = authority else {
            panic!("Allow requires policy authority")
        };
        assert_eq!(authority.policy_digest(), decision.policy_digest());
        assert_eq!(authority.policy_sequence(), decision.policy_sequence());
        assert_eq!(authority.rule_index(), decision.rule_index());
        assert_eq!(authority.profile(), decision.profile());
        assert_eq!(authority.chain_id(), decision.chain_id());
        assert_eq!(authority.evaluated_at_ms(), decision.evaluated_at_ms());
        assert_eq!(
            authority.governing_until_ms(),
            decision.evaluated_at_ms() + decision.governing_ttl_ms()
        );
        assert_eq!(authority.scope(), decision.scope());
        assert!(witness.is_none());
        assert!(driver::ceremonies().is_empty());
        assert!(shown_summaries().is_empty());
        assert_eq!(pending_store(&fixture).len(), 0);
        assert_eq!(consent_rows(&context), 0);

        let decision = MainnetDecision::for_test(
            Decision::RequireApproval(ApprovalRequest::new("fixture".to_owned(), 300)),
            None,
            policy.digest(),
            policy.sequence(),
            7,
            context.profile_name(),
            context.chain().caip2_str(),
            1_900_000_000_000,
            300_000,
            AuthorityScope::Classic,
        );
        let approved = prepared_operation(&context, "authority-approval", &envelope);
        let authority = cli_mainnet_authority(
            &decision,
            ConfirmDecision::RequireApproval { ttl_ms: 300_000 },
            &summary,
            &context,
            &policy,
            &fixture.store_path(),
            Some(&approved),
            PolicyDecision::RequireApproval,
            &mut witness,
        )
        .await
        .unwrap();
        let MainnetAuthority::Approval(borrowed) = authority else {
            panic!("approval authority")
        };
        let address = std::ptr::from_ref(borrowed.witness());
        assert_eq!(
            borrowed.witness().expires_at_ms() - borrowed.witness().created_at_ms(),
            300_000
        );
        assert_eq!(address, std::ptr::from_ref(witness.as_ref().unwrap()));
        assert_eq!(driver::ceremonies().len(), 1);
        assert_eq!(shown_summaries().len(), 1);
        assert_eq!(pending_store(&fixture).len(), 1);
        assert_eq!(consent_rows(&context), 1);

        let _browser = driver::install(Box::new(|_| {
            Err(WalletError::Approval(
                ApprovalFailure::PresenceBrowserRequired,
            ))
        }));
        let mut slot = None;
        let refused = prepared_operation(&context, "authority-refused", &envelope);
        let refusal = cli_mainnet_authority(
            &decision,
            ConfirmDecision::RequireApproval { ttl_ms: 300_000 },
            &summary,
            &context,
            &policy,
            &fixture.store_path(),
            Some(&refused),
            PolicyDecision::RequireApproval,
            &mut slot,
        )
        .await
        .unwrap_err();
        assert!(matches!(
            refusal,
            AuthorityRefusal::Gate(WalletError::Approval(
                ApprovalFailure::PresenceBrowserRequired
            ))
        ));
        assert!(slot.is_none());
    }

    /// Every typed refusal has one stable JSON envelope at the CLI boundary.
    #[test]
    fn render_authority_refusal_matches_todays_cli_output() {
        use stellar_agent_core::{
            policy::{DenyReason, PolicyError},
            wallet::WalletLifecycleError,
        };
        use stellar_agent_network::mainnet::authority::AuthorityError;
        let cases = [
            (
                AuthorityRefusal::Gate(WalletError::Approval(
                    ApprovalFailure::PresenceBrowserRequired,
                )),
                "approval.presence_browser_required",
                "Mainnet consent requires a local browser with WebAuthn user verification; no approval is recorded.",
            ),
            (
                AuthorityRefusal::Refusal(MainnetRefusal::Denied {
                    rule_index: Some(2),
                    reason: DenyReason::ExplicitRuleDeny,
                }),
                "policy.deny.explicit_rule_deny",
                "pay operation denied by operator policy",
            ),
            (
                AuthorityRefusal::Refusal(MainnetRefusal::Engine(PolicyError::Internal {
                    detail: "fixture".to_owned(),
                })),
                "policy.engine_required",
                "policy internal error: fixture",
            ),
            (
                AuthorityRefusal::Refusal(MainnetRefusal::Engine(PolicyError::AccountingOverflow)),
                "policy.accounting_overflow",
                "the policy accounting sum overflows",
            ),
            (
                AuthorityRefusal::Refusal(MainnetRefusal::Engine(PolicyError::AccountingInvalid)),
                "policy.accounting_invalid",
                "a policy accounting amount or fee is invalid",
            ),
            (
                AuthorityRefusal::Refusal(MainnetRefusal::Clock(
                    WalletLifecycleError::ClockError {
                        detail: "policy clock unavailable (test injection)".to_owned(),
                        source: None,
                    },
                )),
                "wallet.clock_error",
                "system clock error: wallet clock error: policy clock unavailable (test injection)",
            ),
            (
                AuthorityRefusal::Internal(AuthorityError::Internal {
                    detail: "fixture".to_owned(),
                }),
                "internal.unexpected_state",
                "unexpected internal state: mainnet authority internal error: fixture",
            ),
            (
                AuthorityRefusal::ApprovalRequired {
                    expectation: ApprovalExpectation {
                        kind: ApprovedKind::Payment,
                        subject: [3; 32],
                    },
                },
                "internal.unexpected_state",
                "unexpected internal state: the CLI authority wrapper requires a completed approval",
            ),
        ];
        for (refusal, code, message) in cases {
            let mut envelope = render_authority_refusal("pay", refusal);
            envelope.request_id = "guard".to_owned();
            assert_eq!(
                serde_json::to_string(&envelope).unwrap(),
                format!(
                    "{{\"ok\":false,\"error\":{{\"code\":\"{code}\",\"message\":\"{message}\"}},\"request_id\":\"guard\"}}"
                )
            );
        }
    }

    /// The pending store of the fixture profile.
    #[cfg(feature = "mainnet-write")]
    fn pending_store(fixture: &MainnetConsentFixture) -> PendingApprovalStore {
        PendingApprovalStore::open(fixture.store_path()).unwrap()
    }

    /// A verified assertion of the policy's credential records one version 5
    /// consent with its receipt and one consent row naming the mainnet
    /// confirmation and the pay tool.
    #[cfg(feature = "mainnet-write")]
    #[tokio::test]
    #[serial_test::serial]
    async fn confirm_accepts() {
        let (fixture, context, envelope) = confirmation_fixture("confirm-accepts");
        let _presence = driver::install(driver::fixture_credential());
        let summary =
            MainnetWriteSummary::from_envelope(&envelope, MainnetConsumer::CliPay, 500).unwrap();
        let witness = confirm(&fixture, &context, &summary).await.unwrap();
        assert_eq!(witness.subject(), approval_subject_classic(&envelope));
        assert_eq!(witness.expires_at_ms() - witness.created_at_ms(), 600_000);
        assert_eq!(driver::ceremonies().len(), 1);
        let pending = pending_store(&fixture);
        assert_eq!(pending.len(), 1);
        let entry = pending.get(witness.nonce()).unwrap();
        assert!(entry.attestation_blob_b64.is_some());
        assert!(entry.mainnet_presence.is_some());
        let rows: Vec<serde_json::Value> =
            std::fs::read_to_string(&context.profile().audit_log_path)
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .filter(|row: &serde_json::Value| row["kind"] == "approval_attested")
                .collect();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["origin"], "cli-mainnet-confirm");
        assert_eq!(rows[0]["gated_tool"], "stellar_pay");
    }
    #[cfg(feature = "mainnet-write")]
    #[tokio::test]
    #[serial_test::serial]
    async fn confirm_accepts_claim_with_unknown_value() {
        use stellar_xdr::{
            ClaimClaimableBalanceOp, ClaimableBalanceId, Hash, Limits, Operation, OperationBody,
            WriteXdr as _,
        };
        let (fixture, context, envelope) = confirmation_fixture("confirm-claim");
        let _presence = driver::install(driver::fixture_credential());
        clear_shown_summaries();
        let TransactionEnvelope::Tx(mut tx) =
            TransactionEnvelope::from_xdr_base64(&envelope, Limits::none()).unwrap()
        else {
            unreachable!()
        };
        tx.tx.operations = vec![Operation {
            source_account: None,
            body: OperationBody::ClaimClaimableBalance(ClaimClaimableBalanceOp {
                balance_id: ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash([3; 32])),
            }),
        }]
        .try_into()
        .unwrap();
        let envelope = TransactionEnvelope::Tx(tx)
            .to_xdr_base64(Limits::none())
            .unwrap();
        let summary =
            MainnetWriteSummary::from_envelope(&envelope, MainnetConsumer::CliClaim, 500).unwrap();
        let witness = confirm(&fixture, &context, &summary).await.unwrap();
        assert_eq!(witness.kind(), ApprovedKind::Claim);
        let pending = pending_store(&fixture);
        let stellar_agent_core::approval::ApprovalKind::ClaimSimulated {
            summary_asset,
            summary_amount_stroops,
            summary_balance_id_hex72: balance_id_hex72,
            summary_source: source,
            summary_simulated_fee_stroops: simulated_fee_stroops,
            summary_simulated_seq_num: simulated_seq_num,
            ..
        } = &pending.get(witness.nonce()).unwrap().kind
        else {
            panic!("claim required")
        };
        assert_eq!(summary_asset, &None);
        assert_eq!(summary_amount_stroops, &None);
        assert_eq!(balance_id_hex72, &format!("00000000{}", "03".repeat(32)));
        assert_eq!(source, &summary.string("source"));
        assert_eq!(*simulated_fee_stroops, summary.fee);
        assert_eq!(*simulated_seq_num, summary.sequence);
        let shown = shown_summaries();
        assert_eq!(shown.len(), 1);
        assert_eq!(
            shown[0]
                .matches("not known to the wallet before the claim")
                .count(),
            2
        );
        let audit = std::fs::read_to_string(&context.profile().audit_log_path).unwrap();
        assert!(audit.contains("stellar_claim"));
        assert!(audit.contains("cli-mainnet-confirm"));
    }
    #[cfg(all(feature = "mainnet-write", feature = "test-helpers"))]
    #[tokio::test]
    #[serial_test::serial]
    async fn failed_consent_leaves_no_attestation() {
        let (fixture, context, envelope) = confirmation_fixture("confirm-failure");
        let _presence = driver::install(driver::fixture_credential());
        let _server =
            stellar_agent_core::audit_log::writer::AuditWriterRegistry::get_or_open_keyed(
                "confirm-server",
                &context.profile().audit_log_path,
                stellar_agent_network::keyring::keyed_audit_access(
                    context.profile(),
                    context.profile_name(),
                    stellar_agent_core::audit_log::BindingCheck::Enforce,
                )
                .unwrap(),
            )
            .unwrap();
        let outbox = stellar_agent_core::audit_log::AuditOutbox::for_log(
            &context.profile().audit_log_path,
            stellar_agent_network::keyring::KeyringTipAnchorStore::shared(
                &context.profile().audit_log_hash_chain_key_id,
                &context.profile().audit_log_path,
            ),
        );
        stellar_agent_core::audit_log::outbox::test_seam::arm_partial_write(outbox.path(), 5);
        let summary =
            MainnetWriteSummary::from_envelope(&envelope, MainnetConsumer::CliPay, 500).unwrap();
        let result = confirm(&fixture, &context, &summary).await;
        stellar_agent_core::audit_log::outbox::test_seam::disarm(outbox.path());
        assert_eq!(result.unwrap_err().code(), "audit.chain_key_unavailable");
        assert_eq!(driver::ceremonies().len(), 1);
        let text = std::fs::read_to_string(fixture.store_path()).unwrap();
        assert!(!text.contains("attestation_blob_b64"));
        assert_eq!(pending_store(&fixture).len(), 0, "the parked entry is gone");
    }
    #[cfg(feature = "mainnet-write")]
    #[tokio::test]
    #[serial_test::serial]
    async fn confirmed_claim_witness_resolves() {
        claim_authority_resolves("confirm-claim-resolve", true, |_| {}).await;
    }

    #[cfg(feature = "mainnet-write")]
    #[tokio::test]
    #[serial_test::serial]
    async fn allow_claim_resolves_without_confirmation() {
        claim_authority_resolves("allow-claim-resolve", false, |_| {}).await;
    }

    /// The state [`claim_authority_resolves`] reaches after its mint.
    #[cfg(feature = "mainnet-write")]
    pub(crate) struct Minted<'a> {
        pub(crate) fixture: &'a MainnetConsentFixture,
        pub(crate) context: &'a MainnetWriteContext,
        pub(crate) policy: &'a VerifiedPolicy,
        pub(crate) operation: &'a OperationHandle,
        pub(crate) envelope: &'a str,
        pub(crate) witness: Option<&'a ApprovalWitness>,
    }

    /// Resolves a claim authority of profile `profile_name` under an approval
    /// rule or `Allow`, mints it, and then runs `after_mint` on the minted
    /// state.
    #[cfg(feature = "mainnet-write")]
    pub(crate) async fn claim_authority_resolves(
        profile_name: &str,
        approval_required: bool,
        after_mint: fn(Minted<'_>),
    ) {
        use sha2::Digest as _;
        use stellar_agent_core::approval::mainnet_fixtures::ENABLEMENT_NONCE;
        use stellar_agent_core::cross_check::{CrossCheckValue, ThresholdSet};
        use stellar_agent_core::{
            mainnet::enablement::verify_enablement,
            profile::{
                name::ProfileNameSource, schema::signer_identity_entry_ref,
                signer_identity::SignerIdentityRecord,
            },
        };
        use stellar_agent_network::{
            cross_check::{
                AccountObservation, ClaimWitnessInputs, ClaimableBalanceObservation,
                CrossCheckOutcome, obtain_classic_witness_bound,
            },
            keyring,
            mainnet::{
                audit_readiness::audit_readiness,
                resolve::{TxSignRequest, resolve_tx_sign},
            },
            policy_state::PersistedWindowStore,
        };
        use stellar_agent_test_support::{
            EchoIdResponder, SignedTestEnvelope, signed_envelope::get_network_result,
        };
        use stellar_xdr::*;
        let (fixture, context, encoded) = confirmation_fixture_with(profile_name, |profile| {
            use stellar_agent_core::profile::schema::{PrimaryProviderRecord, ProviderRecord};
            let providers = profile.providers.get_or_insert_with(Default::default);
            providers.primary = Some(PrimaryProviderRecord::new("primary", "rpc.example.invalid"));
            providers.oracle = Some(ProviderRecord::new(
                "oracle",
                "oracle.example.invalid",
                true,
            ));
            profile.oracle_provider_url = Some("https://oracle.example.invalid".parse().unwrap());
        });
        clear_shown_summaries();
        let _presence = driver::install(driver::fixture_credential());
        let TransactionEnvelope::Tx(mut tx) =
            TransactionEnvelope::from_xdr_base64(&encoded, Limits::none()).unwrap()
        else {
            unreachable!()
        };
        tx.tx.operations = vec![Operation {
            source_account: None,
            body: OperationBody::ClaimClaimableBalance(ClaimClaimableBalanceOp {
                balance_id: ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash([3; 32])),
            }),
        }]
        .try_into()
        .unwrap();
        tx.tx.cond = Preconditions::Time(TimeBounds {
            min_time: TimePoint(0),
            max_time: TimePoint(
                stellar_agent_network::mainnet::clock::now_ms().unwrap() / 1000 + 120,
            ),
        });
        let encoded = TransactionEnvelope::Tx(tx)
            .to_xdr_base64(Limits::none())
            .unwrap();
        let summary =
            MainnetWriteSummary::from_envelope(&encoded, MainnetConsumer::CliClaim, 500).unwrap();
        let profile = context.profile().clone();
        let name = context.profile_name().to_owned();
        let name = name.as_str();
        let nonce_digest =
            stellar_agent_core::hex::encode(&sha2::Sha256::digest(ENABLEMENT_NONCE.as_bytes()));
        let raw = include_str!("../../../stellar-agent-core/tests/fixtures/policy-v2.toml")
            .replace("operator", name)
            .replace("stellar_pay", "stellar_claim")
            .replace(
                "    { kind = \"asset_allowlist\", assets = [\"native\"] },\n",
                "",
            )
            .replace(&"0".repeat(64), &nonce_digest)
            .replace("ttl_secs = 3600", "ttl_secs = 300")
            .replace("reason = \"review\"", "")
            .replace(
                "sequence = 7",
                &format!("sequence = {}", fixture.sequence() + 1),
            );
        let raw = if approval_required {
            raw
        } else {
            raw.replace("decision = \"require_approval\"", "decision = \"allow\"")
                .replace("ttl_secs = 300", "")
        };
        fixture.write_signed(&raw);
        let policy = fixture.current_policy();
        let decision = MainnetDecision::for_test(
            if approval_required {
                Decision::RequireApproval(stellar_agent_core::policy::ApprovalRequest::new(
                    "fixture".to_owned(),
                    300,
                ))
            } else {
                Decision::Allow
            },
            None,
            policy.digest(),
            policy.sequence(),
            0,
            name,
            context.chain().caip2_str(),
            stellar_agent_core::timefmt::now_unix_ms().unwrap(),
            if approval_required { 300_000 } else { 600_000 },
            stellar_agent_core::mainnet::decision::AuthorityScope::Classic,
        );
        let mut slot = None;
        let operation = prepared_operation(&context, "claim-authority", &encoded);
        let authority = cli_mainnet_authority(
            &decision,
            ConfirmDecision::RequireApproval { ttl_ms: 300_000 },
            &summary,
            &context,
            &policy,
            &fixture.store_path(),
            Some(&operation),
            PolicyDecision::RequireApproval,
            &mut slot,
        )
        .await
        .unwrap();
        if !approval_required {
            assert!(matches!(authority, MainnetAuthority::Policy(_)));
            assert!(shown_summaries().is_empty());
            assert!(driver::ceremonies().is_empty());
            assert_eq!(pending_store(&fixture).len(), 0);
            assert_eq!(consent_rows(&context), 0);
        }
        let public = ed25519_dalek::SigningKey::from_bytes(&[8; 32])
            .verifying_key()
            .to_bytes();
        let identity = signer_identity_entry_ref(&profile.mcp_signer_default);
        keyring_core::Entry::new(&identity.service, &identity.account)
            .unwrap()
            .set_password(
                &SignerIdentityRecord::signed_for_test(
                    public,
                    name,
                    &profile,
                    &ed25519_dalek::SigningKey::from_bytes(&[11; 32]),
                )
                .render()
                .unwrap(),
            )
            .unwrap();
        let source = SignedTestEnvelope::builder([8; 32]).unsigned().build();
        let enablement = verify_enablement(
            &policy,
            name,
            ProfileNameSource::Flag,
            &profile,
            &fixture.home().join("profiles"),
            &|_| Ok(ENABLEMENT_NONCE.to_owned()),
        )
        .unwrap();
        let signer = keyring::enrolled_signer(
            name,
            &fixture.home().join("profiles"),
            &profile,
            keyring::EnrolledRole::Agent,
            &public,
            &policy.owner(),
        )
        .unwrap();
        let mut servers = Vec::new();
        for _ in 0..2 {
            let server = wiremock::MockServer::start().await;
            for (method, response) in [
                (
                    "getNetwork",
                    get_network_result(context.network_passphrase()),
                ),
                ("getLedgerEntries", source.ledger_entries_result()),
            ] {
                wiremock::Mock::given(wiremock::matchers::body_partial_json(
                    serde_json::json!({"method": method}),
                ))
                .respond_with(EchoIdResponder::new(response))
                .mount(&server)
                .await;
            }
            servers.push(server);
        }
        let (primary, oracle) = (&servers[0], &servers[1]);
        let context = context.with_test_transport_routes(&[
            ("rpc.example.invalid", &primary.uri()),
            ("oracle.example.invalid", &oracle.uri()),
        ]);
        let client = context.primary_client().unwrap();
        let view = stellar_agent_network::account::fetch_account(&client, source.source(), &[])
            .await
            .unwrap();
        let outcome = obtain_classic_witness_bound(
            context.profile(),
            &context.network_context(),
            CrossCheckValue::Unvalued,
            ClaimWitnessInputs {
                source: AccountObservation::from_view(&view).unwrap(),
                trustline: None,
                balance: Some(ClaimableBalanceObservation {
                    balance_id: [3; 32],
                    entry: None,
                }),
            },
            &encoded,
            &ThresholdSet::from_profile_and_signed(
                context.profile(),
                policy.mainnet().unwrap().cross_check_thresholds.as_ref(),
            ),
            "stellar_claim",
        )
        .await
        .unwrap();
        let CrossCheckOutcome::Passed(witness) = outcome else {
            panic!("a bound claim witness is required on mainnet")
        };
        assert_eq!(witness.authority(), "https://oracle.example.invalid");
        assert!(!oracle.received_requests().await.unwrap().is_empty());
        let store = PersistedWindowStore::for_profile(name);
        let request = |witness| TxSignRequest {
            context: &context,
            consumer: MainnetConsumer::CliClaim,
            unsigned_envelope_xdr: &encoded,
            client: &client,
            probe_deadline: std::time::Duration::from_secs(2),
            witness,
            signer: &signer,
            policy: &policy,
            enablement: &enablement,
            authority: &authority,
            audit: audit_readiness(context.profile(), context.profile_name()).unwrap(),
            store: &store,
            operation: Some(stellar_agent_network::operation_entry::next_attempt_link(
                &operation,
            )),
            restriction: None,
            sac_payment_context: None,
        };
        assert_eq!(
            resolve_tx_sign(request(None))
                .await
                .map(|_| ())
                .unwrap_err(),
            stellar_agent_network::mainnet::MainnetAuthorizationError::Refused(
                stellar_agent_network::mainnet::MainnetPrecondition::WitnessRequired
            )
        );
        let auth = resolve_tx_sign(request(Some(&witness))).await.unwrap();
        auth.check_consumer(MainnetConsumer::CliClaim).unwrap();
        let path = stellar_agent_core::profile::schema::default_policy_window_state_path_for(name);
        let bytes = std::fs::read(path).unwrap();
        let body: serde_json::Value = serde_json::from_slice(
            &bytes[crate::common::mainnet_write_fixture::WINDOW_HMAC_TAG_BYTES..],
        )
        .unwrap();
        let rows = body["authorizations"].as_array().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].get("policy_authority").is_some(),
            !approval_required
        );
        assert_eq!(
            store
                .open_authorizations(
                    context.profile(),
                    stellar_agent_core::timefmt::now_unix_ms().unwrap()
                )
                .unwrap()
                .len(),
            1
        );
        after_mint(Minted {
            fixture: &fixture,
            context: &context,
            policy: &policy,
            operation: &operation,
            envelope: &encoded,
            witness: slot.as_ref(),
        });
    }

    /// The `approval_attested` rows of the profile's audit log.
    #[cfg(feature = "mainnet-write")]
    fn consent_rows(context: &MainnetWriteContext) -> usize {
        std::fs::read_to_string(&context.profile().audit_log_path)
            .unwrap_or_default()
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .filter(|row| row["kind"] == "approval_attested")
            .count()
    }

    /// Drives the confirmation with `presence` as the browser side and
    /// returns the refusal code after asserting that nothing was recorded
    /// and the parked entry is gone.
    #[cfg(feature = "mainnet-write")]
    async fn refused_confirmation(name: &str, presence: driver::Driver) -> String {
        let (fixture, context, envelope) = confirmation_fixture(name);
        let _presence = driver::install(presence);
        let summary =
            MainnetWriteSummary::from_envelope(&envelope, MainnetConsumer::CliPay, 500).unwrap();
        let code = confirm(&fixture, &context, &summary)
            .await
            .unwrap_err()
            .code()
            .to_owned();
        assert_eq!(pending_store(&fixture).len(), 0);
        assert_eq!(consent_rows(&context), 0);
        let stored = std::fs::read_to_string(fixture.store_path()).unwrap_or_default();
        assert!(!stored.contains("attestation_blob_b64"), "{stored}");
        code
    }

    /// A browser refusal records nothing for either reported terminal state.
    #[cfg(feature = "mainnet-write")]
    #[tokio::test]
    #[serial_test::serial]
    async fn confirm_browser_refusal_records_nothing_for_each_terminal_state() {
        for (index, streams) in [(true, true), (false, false)].into_iter().enumerate() {
            let _tty = super::super::tty::tests::test_tty(streams.0, streams.1);
            let checks = super::super::tty::tests::TEST_TTY_CHECKS.get();
            assert_eq!(
                refused_confirmation(
                    &format!("confirm-browser-{index}"),
                    Box::new(|_| Err(WalletError::Approval(
                        ApprovalFailure::PresenceBrowserRequired
                    )))
                )
                .await,
                "approval.presence_browser_required",
                "{streams:?}"
            );
            assert_eq!(super::super::tty::tests::TEST_TTY_CHECKS.get(), checks);
        }
    }

    /// A missing browser, a canceled ceremony, an assertion over another
    /// challenge, one without user verification and one of a credential
    /// the signed policy does not list all refuse with nothing recorded.
    #[cfg(feature = "mainnet-write")]
    #[tokio::test]
    #[serial_test::serial]
    async fn confirm_refuses_a_failed_or_invalid_presence() {
        use stellar_agent_test_support::webauthn::{
            FLAG_UP, FLAG_UV, TestAuthenticator, fixture_authenticator,
        };
        let refusing = |failure: fn() -> ApprovalFailure| -> driver::Driver {
            Box::new(move |_| Err(WalletError::Approval(failure())))
        };
        let cases: Vec<(driver::Driver, &str)> = vec![
            (
                refusing(|| ApprovalFailure::PresenceBrowserRequired),
                "approval.presence_browser_required",
            ),
            (
                refusing(|| ApprovalFailure::PresenceCanceled),
                "approval.presence_canceled",
            ),
            (
                driver::over_another_challenge(driver::fixture_credential()),
                "approval.presence_invalid",
            ),
            (
                driver::credential(fixture_authenticator(), FLAG_UP),
                "approval.presence_invalid",
            ),
            (
                driver::credential(
                    TestAuthenticator::from_seed([0x33; 32], vec![0x44; 16]),
                    FLAG_UP | FLAG_UV,
                ),
                "approval.presence_invalid",
            ),
        ];
        for (index, (presence, expected)) in cases.into_iter().enumerate() {
            assert_eq!(
                refused_confirmation(&format!("confirm-refused-{index}"), presence).await,
                expected,
                "case {index}"
            );
        }
    }

    /// The store is released during the ceremony: another handle opens it,
    /// sees the parked unattested entry, and the confirmation still
    /// completes afterwards.
    #[cfg(feature = "mainnet-write")]
    #[tokio::test]
    #[serial_test::serial]
    async fn confirm_releases_the_store_during_the_ceremony() {
        let (fixture, context, envelope) = confirmation_fixture("confirm-released");
        let store_path = fixture.store_path();
        let seen = std::rc::Rc::new(std::cell::Cell::new(false));
        let observed = std::rc::Rc::clone(&seen);
        let mut answer = driver::fixture_credential();
        let _presence = driver::install(Box::new(move |ceremony| {
            let other = PendingApprovalStore::open(store_path.clone()).unwrap();
            let parked = other.get(&ceremony.nonce).unwrap();
            assert!(parked.attestation_blob_b64.is_none());
            observed.set(true);
            drop(other);
            answer(ceremony)
        }));
        let summary =
            MainnetWriteSummary::from_envelope(&envelope, MainnetConsumer::CliPay, 500).unwrap();
        confirm(&fixture, &context, &summary).await.unwrap();
        assert!(seen.get(), "the ceremony ran with the store released");
        assert_eq!(consent_rows(&context), 1);
    }

    /// A policy signed at a higher sequence during the ceremony refuses the
    /// consent, although the same credential signed: the challenge bound
    /// the earlier policy.
    #[cfg(feature = "mainnet-write")]
    #[tokio::test]
    #[serial_test::serial]
    async fn confirm_refuses_a_policy_changed_during_the_ceremony() {
        let (fixture, context, envelope) = confirmation_fixture("confirm-policy-changed");
        let policy = fixture.current_policy();
        let policy_path = fixture.policy_path();
        let original = std::fs::read_to_string(&policy_path).unwrap();
        fixture.write_signed(&fixture.policy_body(
            fixture.sequence() + 1,
            &[&stellar_agent_test_support::webauthn::fixture_authenticator()],
        ));
        let higher = std::fs::read_to_string(&policy_path).unwrap();
        std::fs::write(&policy_path, &original).unwrap();
        let mut answer = driver::fixture_credential();
        let _presence = driver::install(Box::new(move |ceremony| {
            std::fs::write(&policy_path, &higher).unwrap();
            answer(ceremony)
        }));
        let summary =
            MainnetWriteSummary::from_envelope(&envelope, MainnetConsumer::CliPay, 500).unwrap();
        let error = confirm_mainnet_write(
            &summary,
            ConfirmDecision::Allow,
            &context,
            &policy,
            &fixture.store_path(),
            None,
            PolicyDecision::Allow,
            &governing(&context, &policy, 600_000),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), "approval.presence_policy_unavailable");
        assert_eq!(consent_rows(&context), 0);
        assert_eq!(pending_store(&fixture).len(), 0);
    }

    #[cfg(feature = "mainnet-write")]
    #[tokio::test]
    #[serial_test::serial]
    async fn confirm_without_the_attestation_key_records_nothing() {
        let (fixture, context, envelope) = confirmation_fixture("confirm-no-key");
        let _presence = driver::install(driver::fixture_credential());
        let key = &context.profile().attestation_key_id;
        keyring_core::Entry::new(&key.service, &key.account)
            .unwrap()
            .delete_credential()
            .unwrap();
        let summary =
            MainnetWriteSummary::from_envelope(&envelope, MainnetConsumer::CliPay, 500).unwrap();
        confirm(&fixture, &context, &summary).await.unwrap_err();
        assert!(driver::ceremonies().is_empty(), "no ceremony starts");
        assert_eq!(pending_store(&fixture).len(), 0);
        assert_eq!(consent_rows(&context), 0);
    }

    #[cfg(feature = "mainnet-write")]
    #[tokio::test]
    #[serial_test::serial]
    async fn confirm_without_a_consent_sink_records_nothing() {
        let (fixture, context, envelope) = confirmation_fixture("confirm-no-sink");
        let _presence = driver::install(driver::fixture_credential());
        let chain_key = &context.profile().audit_log_hash_chain_key_id;
        keyring_core::Entry::new(&chain_key.service, &chain_key.account)
            .unwrap()
            .delete_credential()
            .unwrap();
        let summary =
            MainnetWriteSummary::from_envelope(&envelope, MainnetConsumer::CliPay, 500).unwrap();
        let error = confirm(&fixture, &context, &summary).await.unwrap_err();
        assert_eq!(error.code(), "audit.chain_key_unavailable");
        assert!(driver::ceremonies().is_empty(), "no ceremony starts");
        assert_eq!(pending_store(&fixture).len(), 0);
        assert_eq!(consent_rows(&context), 0);
        let stored = std::fs::read_to_string(fixture.store_path()).unwrap_or_default();
        assert!(!stored.contains("attestation_blob_b64"), "{stored}");
    }

    #[test]
    fn summary_refusals_carry_their_codes() {
        use stellar_agent_test_support::SignedTestEnvelope;
        use stellar_xdr::{
            Limits, TransactionV0, TransactionV0Envelope, TransactionV0Ext, Uint256, WriteXdr as _,
        };
        let built = SignedTestEnvelope::builder([8; 32])
            .unsigned()
            .amount_stroops(17)
            .build();
        let code = |envelope: &str, consumer| {
            MainnetWriteSummary::from_envelope(envelope, consumer, 500)
                .err()
                .unwrap()
                .code()
                .to_owned()
        };
        for consumer in [
            MainnetConsumer::McpPay,
            MainnetConsumer::McpClaim,
            MainnetConsumer::X402Create,
        ] {
            assert_eq!(
                code(built.envelope_xdr(), consumer),
                "approval.wrong_kind",
                "{consumer:?}"
            );
        }
        assert_eq!(
            code("AAAA", MainnetConsumer::CliPay),
            "protocol.xdr_codec_failed"
        );
        let TransactionEnvelope::Tx(tx) =
            TransactionEnvelope::from_xdr_base64(built.envelope_xdr(), Limits::none()).unwrap()
        else {
            unreachable!()
        };
        let stellar_xdr::MuxedAccount::Ed25519(source) = tx.tx.source_account.clone() else {
            unreachable!()
        };
        let v0 = TransactionEnvelope::TxV0(TransactionV0Envelope {
            tx: TransactionV0 {
                source_account_ed25519: Uint256(source.0),
                fee: tx.tx.fee,
                seq_num: tx.tx.seq_num.clone(),
                time_bounds: None,
                memo: tx.tx.memo.clone(),
                operations: tx.tx.operations.clone(),
                ext: TransactionV0Ext::V0,
            },
            signatures: vec![].try_into().unwrap(),
        })
        .to_xdr_base64(Limits::none())
        .unwrap();
        assert_eq!(
            code(&v0, MainnetConsumer::CliPay),
            "protocol.xdr_codec_failed"
        );
        let summary =
            MainnetWriteSummary::from_envelope(built.envelope_xdr(), MainnetConsumer::CliPay, 500)
                .unwrap();
        assert_eq!(
            summary.amount("memo").unwrap_err().code(),
            "protocol.xdr_codec_failed"
        );
    }

    #[test]
    fn persisted_attestation_refusals_carry_their_code() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = PendingApprovalStore::open(dir.path().join("pending.toml")).unwrap();
        assert_eq!(
            persisted_attestation(&store, "absent").unwrap_err().code(),
            "approval.attestation_invalid"
        );
        let built = stellar_agent_test_support::SignedTestEnvelope::builder([8; 32])
            .unsigned()
            .amount_stroops(17)
            .build();
        let summary =
            MainnetWriteSummary::from_envelope(built.envelope_xdr(), MainnetConsumer::CliPay, 500)
                .unwrap();
        let entry = summary.pending("1000".into(), 600_000).unwrap();
        let five = URL_SAFE_NO_PAD.encode([5; 32]);
        let mut stored_with = |blob: Option<&str>| {
            let mut stored = entry.clone();
            stored.attestation_blob_b64 = blob.map(str::to_owned);
            store.remove(&entry.approval_nonce).unwrap();
            store.insert(stored, entry.created_at_unix_ms).unwrap();
            persisted_attestation(&store, &entry.approval_nonce)
        };
        for blob in [None, Some("not base64url!"), Some("AAAA")] {
            assert_eq!(
                stored_with(blob).unwrap_err().code(),
                "approval.attestation_invalid",
                "{blob:?}"
            );
        }
        assert_eq!(stored_with(Some(&five)).unwrap(), [5; 32]);
    }

    /// The durable ceremony of a payment summary of `envelope` under
    /// `handle` and an approval rule of `ttl_ms`.
    #[cfg(feature = "mainnet-write")]
    async fn durable(
        fixture: &MainnetConsentFixture,
        context: &MainnetWriteContext,
        envelope: &str,
        handle: &OperationHandle,
        ttl_ms: u64,
    ) -> Result<ApprovalWitness, WalletError> {
        let summary =
            MainnetWriteSummary::from_envelope(envelope, MainnetConsumer::CliPay, 500).unwrap();
        confirm_mainnet_write(
            &summary,
            ConfirmDecision::RequireApproval { ttl_ms },
            context,
            &fixture.current_policy(),
            &fixture.store_path(),
            Some(handle),
            PolicyDecision::RequireApproval,
            &governing(context, &fixture.current_policy(), ttl_ms),
        )
        .await
    }

    /// The authenticated record linked to `handle`'s operation.
    #[cfg(feature = "mainnet-write")]
    fn durable_record(
        context: &MainnetWriteContext,
        handle: &OperationHandle,
    ) -> Option<stellar_agent_network::policy_state::WireApproval> {
        let store = PersistedWindowStore::for_profile(context.profile_name());
        ApprovalStatus::new(&store, context.profile())
            .find_by_operation(handle.id())
            .unwrap()
            .map(|view| view.record)
    }

    /// The stored window record of `handle`'s operation.
    #[cfg(feature = "mainnet-write")]
    fn stored_operation(
        context: &MainnetWriteContext,
        handle: &OperationHandle,
    ) -> serde_json::Value {
        let path = stellar_agent_core::profile::schema::default_policy_window_state_path_for(
            context.profile_name(),
        );
        let bytes = std::fs::read(path).unwrap();
        let body: serde_json::Value = serde_json::from_slice(
            &bytes[crate::common::mainnet_write_fixture::WINDOW_HMAC_TAG_BYTES..],
        )
        .unwrap();
        let id = serde_json::to_value(handle.id()).unwrap();
        body["operations"]["records"]
            .as_array()
            .unwrap()
            .iter()
            .find(|record| record["id"] == id)
            .unwrap()
            .clone()
    }

    /// The inbox entries of the fixture profile.
    #[cfg(feature = "mainnet-write")]
    fn inbox(fixture: &MainnetConsentFixture) -> Vec<PendingApproval> {
        let store = pending_store(fixture);
        store
            .snapshot(0)
            .iter()
            .map(|view| store.get(&view.approval_nonce).unwrap().clone())
            .collect()
    }

    #[cfg(feature = "mainnet-write")]
    #[test]
    #[serial_test::serial]
    fn canonical_prepare_removes_only_unlinked_orphans() {
        use stellar_agent_core::approval::{IntentAsset, IntentPayload, MemoFact};
        use stellar_agent_network::operation_entry::{
            IntentBaseFacts, OpenedEntry, Preparation, classic_intent, stage_pending,
        };
        let (fixture, context, envelope) = confirmation_fixture("canonical-orphans");
        let summary =
            MainnetWriteSummary::from_envelope(&envelope, MainnetConsumer::CliPay, 500).unwrap();
        let policy = fixture.current_policy();
        let intent = classic_intent(
            IntentBaseFacts::new(
                context.profile(),
                summary.args["source"].as_str().unwrap(),
                &policy,
                stellar_agent_network::fees::ClassicFeeChoice::Explicit(500),
                MemoFact::None,
            ),
            IntentPayload::Pay {
                destination: summary.args["destination"].as_str().unwrap().into(),
                asset: IntentAsset::Native,
                amount_stroops: 17,
            },
        )
        .unwrap();
        let window = PersistedWindowStore::for_profile(context.profile_name());
        let OpenedEntry::Resume(handle) = Preparation::Canonical {
            intent: Box::new(intent.clone()),
            decision: PolicyDecision::RequireApproval,
            rule_ttl_ms: Some(300_000),
        }
        .open(
            &mut stellar_agent_network::policy_state::OperationRecorder::new(
                &window,
                context.profile(),
                &mut NoRows,
                "open",
            ),
            stellar_agent_network::policy_state::BusinessId::parse("canonical-orphans").unwrap(),
            stellar_agent_network::policy_state::OperationTool::CliPay,
            stellar_agent_network::policy_state::OperationKind::Pay,
            &envelope,
        )
        .unwrap() else {
            unreachable!()
        };
        let orphan = summary.pending("1000".into(), 300_000).unwrap();
        let mut other = summary.pending("1000".into(), 300_000).unwrap();
        if let ApprovalKind::PaymentSimulated {
            envelope_sha256_hex,
            ..
        } = &mut other.kind
        {
            *envelope_sha256_hex = "ff".repeat(32);
        }
        let mut pending = pending_store(&fixture);
        pending
            .insert(orphan.clone(), orphan.created_at_unix_ms)
            .unwrap();
        pending
            .insert(other.clone(), other.created_at_unix_ms)
            .unwrap();
        drop(pending);
        let mut entry = summary.pending("1000".into(), 300_000).unwrap();
        stage_pending(&mut entry, Some(&intent), 300_000).unwrap();
        let facts = pending_approval_facts(
            &entry,
            &handle,
            summary.kind,
            approval_subject_classic(&envelope),
            300_000,
        );
        assert!(matches!(
            start_durable(
                &context,
                &fixture.store_path(),
                &handle,
                entry.clone(),
                &facts,
                PolicyDecision::RequireApproval
            )
            .unwrap(),
            DurableStart::Ceremony(_)
        ));
        let pending = pending_store(&fixture);
        assert!(
            pending.get(&orphan.approval_nonce).is_none(),
            "CLI removes canonical retained-envelope orphan"
        );
        assert!(
            pending.get(&other.approval_nonce).is_some(),
            "CLI keeps different operation entry"
        );
        assert!(
            pending.get(&entry.approval_nonce).is_some(),
            "CLI keeps linked entry"
        );
        drop(pending);
        let DurableStart::Ceremony(repeated) = start_durable(
            &context,
            &fixture.store_path(),
            &handle,
            summary.pending("1000".into(), 300_000).unwrap(),
            &facts,
            PolicyDecision::RequireApproval,
        )
        .unwrap() else {
            unreachable!()
        };
        assert_eq!(
            repeated.approval_nonce, entry.approval_nonce,
            "CLI retry keeps durable winner"
        );
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(fixture.store_path().with_extension("producer.lock"))
            .unwrap();
        let _held = stellar_agent_core::file_lock::HeldFileLock::try_lock(file).unwrap();
        assert!(
            matches!(start_durable(&context, &fixture.store_path(), &handle, entry, &facts, PolicyDecision::RequireApproval),
            Err(error) if error.code() == "approval.writer_locked"),
            "CLI producer lock excludes a competing preparation"
        );
    }

    /// A ceremony under an operation opens one record whose facts are the
    /// entry's kind, subject, nonce and signed clocks, the operation's intent
    /// digest and identity, and moves the operation to `AwaitingApproval`.
    #[cfg(feature = "mainnet-write")]
    #[tokio::test]
    #[serial_test::serial]
    async fn ceremony_opens_one_durable_record() {
        let (fixture, context, envelope) = confirmation_fixture("durable-open");
        let _presence = driver::install(driver::fixture_credential());
        let handle = prepared_operation(&context, "durable-open", &envelope);
        let witness = durable(&fixture, &context, &envelope, &handle, 300_000)
            .await
            .unwrap();
        let record = durable_record(&context, &handle).unwrap();
        let entries = inbox(&fixture);
        assert_eq!(entries.len(), 1);
        assert_eq!(record.nonce, witness.nonce());
        assert_eq!(record.nonce, entries[0].approval_nonce);
        assert_eq!(record.kind, ApprovedKind::Payment);
        assert_eq!(
            record.subject_kind,
            stellar_agent_core::approval::subject::SubjectKind::EnvelopeText
        );
        assert_eq!(record.subject, approval_subject_classic(&envelope));
        assert_eq!(record.intent_digest, handle.intent().intent_digest());
        assert_eq!(record.operation_id, handle.id());
        assert_eq!(
            stored_operation(&context, &handle)["state"],
            "awaiting_approval"
        );
        assert_eq!(driver::ceremonies().len(), 1);
        assert_eq!(consent_rows(&context), 1);
    }

    /// The record keeps the entry's signed creation and waiting times under
    /// rule lifetimes shorter and longer than the 600-second default, and the
    /// open commit stores the prepare decision and the entry's waiting expiry
    /// on the operation.
    #[cfg(feature = "mainnet-write")]
    #[tokio::test]
    #[serial_test::serial]
    async fn producer_clocks_keep_signed_times_under_distinct_lifetimes() {
        for ttl in [300_000, 3_600_000] {
            let name = format!("durable-clocks-{ttl}");
            let (fixture, context, envelope) = confirmation_fixture(&name);
            let _presence = driver::install(driver::fixture_credential());
            let handle = prepared_operation(&context, "durable-clocks", &envelope);
            let before = stored_operation(&context, &handle);
            assert!(before["prepared_decision"].is_null());
            durable(&fixture, &context, &envelope, &handle, ttl)
                .await
                .unwrap();
            let entry = inbox(&fixture).remove(0);
            let record = durable_record(&context, &handle).unwrap();
            assert_eq!(record.created_at_ms, entry.created_at_unix_ms);
            assert_eq!(record.waiting_expires_at_ms, entry.expires_at_unix_ms);
            assert_eq!(record.waiting_expires_at_ms - record.created_at_ms, ttl);
            assert_eq!(record.rule_ttl_ms, ttl);
            let consent = record.consent.unwrap();
            assert_eq!(
                consent.execution_expires_at_ms,
                consent.consent_at_ms + ttl.min(900_000)
            );
            let operation = stored_operation(&context, &handle);
            assert_eq!(operation["prepared_decision"], "require_approval");
            assert_eq!(
                operation["waiting_expires_at_ms"],
                serde_json::json!(entry.expires_at_unix_ms)
            );
        }
    }

    /// An envelope whose `max_time` ends before the entry's waiting expiry
    /// caps the operation's waiting window at the envelope's end.
    #[cfg(feature = "mainnet-write")]
    #[tokio::test]
    #[serial_test::serial]
    async fn open_sets_the_waiting_expiry_to_the_earlier_end() {
        let (fixture, context, _) = confirmation_fixture("durable-cap");
        let _presence = driver::install(driver::fixture_credential());
        let max_time = stellar_agent_core::timefmt::now_unix_ms().unwrap() / 1_000 + 1_200;
        let built = stellar_agent_test_support::SignedTestEnvelope::builder([8; 32])
            .unsigned()
            .sequence(2)
            .amount_stroops(17)
            .time_bounds(0, max_time)
            .build();
        let envelope = built.envelope_xdr().to_owned();
        let handle = prepared_operation(&context, "durable-cap", &envelope);
        durable(&fixture, &context, &envelope, &handle, 3_600_000)
            .await
            .unwrap();
        let entry = inbox(&fixture).remove(0);
        let waiting = stored_operation(&context, &handle)["waiting_expires_at_ms"]
            .as_u64()
            .unwrap();
        assert_eq!(waiting, max_time * 1_000);
        assert!(waiting < entry.expires_at_unix_ms);
    }

    /// The durable consent is the attested entry's: its blob, receipt and
    /// process identifier, with the directly written row named.
    #[cfg(feature = "mainnet-write")]
    #[tokio::test]
    #[serial_test::serial]
    async fn ceremony_records_consent_from_the_attested_entry() {
        let (fixture, context, envelope) = confirmation_fixture("durable-consent");
        let _presence = driver::install(driver::fixture_credential());
        let handle = prepared_operation(&context, "durable-consent", &envelope);
        durable(&fixture, &context, &envelope, &handle, 300_000)
            .await
            .unwrap();
        let entry = inbox(&fixture).remove(0);
        let receipt = entry.mainnet_presence.clone().unwrap();
        let consent = durable_record(&context, &handle).unwrap().consent.unwrap();
        assert_eq!(consent.consent_at_ms, receipt.verified_at_unix_ms());
        assert_eq!(
            consent.payload,
            Some(stellar_agent_network::policy_state::ConsentPayload::new(
                persisted_attestation(&pending_store(&fixture), &entry.approval_nonce).unwrap(),
                receipt,
                entry.process_uid.clone(),
                ConsentRow::Written,
            ))
        );
    }

    /// With another process holding the audit writer from the presence wait
    /// on, the consent row queues and the record retains its reference; the
    /// durable commit needs no writer.
    #[cfg(all(feature = "mainnet-write", feature = "test-helpers"))]
    #[tokio::test]
    #[serial_test::serial]
    async fn queued_consent_stores_its_reference() {
        let (fixture, context, envelope) = confirmation_fixture("durable-queued");
        let held = std::rc::Rc::new(std::cell::RefCell::new(None));
        let mut answer = driver::fixture_credential();
        let profile = context.profile().clone();
        let name = context.profile_name().to_owned();
        let slot = std::rc::Rc::clone(&held);
        let _presence = driver::install(Box::new(move |ceremony| {
            use stellar_agent_core::audit_log::writer::AuditWriterRegistry;
            // The open released this process's writer; another process takes
            // it during the presence wait.
            AuditWriterRegistry::remove_for_test(&name);
            *slot.borrow_mut() = Some(
                AuditWriterRegistry::get_or_open_keyed(
                    "durable-server",
                    &profile.audit_log_path,
                    stellar_agent_network::keyring::keyed_audit_access(
                        &profile,
                        &name,
                        stellar_agent_core::audit_log::BindingCheck::Enforce,
                    )
                    .unwrap(),
                )
                .unwrap(),
            );
            answer(ceremony)
        }));
        let handle = prepared_operation(&context, "durable-queued", &envelope);
        durable(&fixture, &context, &envelope, &handle, 300_000)
            .await
            .unwrap();
        assert!(held.borrow().is_some());
        let payload = durable_record(&context, &handle)
            .unwrap()
            .consent
            .unwrap()
            .payload
            .unwrap();
        assert!(payload.outbox_row.is_some());
        assert_eq!(payload.row_provenance, None);
        assert_eq!(consent_rows(&context), 0, "the row waits in the outbox");
    }

    /// An approval rule without an operation refuses before anything is
    /// shown or parked.
    #[cfg(feature = "mainnet-write")]
    #[tokio::test]
    #[serial_test::serial]
    async fn mainnet_producer_without_a_handle_refuses() {
        let (fixture, context, envelope) = confirmation_fixture("durable-no-handle");
        clear_shown_summaries();
        let _presence = driver::install(driver::fixture_credential());
        let summary =
            MainnetWriteSummary::from_envelope(&envelope, MainnetConsumer::CliPay, 500).unwrap();
        let error = confirm_mainnet_write(
            &summary,
            ConfirmDecision::RequireApproval { ttl_ms: 300_000 },
            &context,
            &fixture.current_policy(),
            &fixture.store_path(),
            None,
            PolicyDecision::RequireApproval,
            &governing(&context, &fixture.current_policy(), 300_000),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), "internal.unexpected_state");
        assert_eq!(
            error.to_string(),
            "unexpected internal state: a mainnet approval requires its operation record"
        );
        assert!(shown_summaries().is_empty());
        assert!(driver::ceremonies().is_empty());
        assert!(inbox(&fixture).is_empty());
    }

    /// A refused open removes the entry when no record names it. An error
    /// after the generation commit keeps entry and record, and the rerun
    /// completes on the same nonce.
    #[cfg(feature = "mainnet-write")]
    #[tokio::test]
    #[serial_test::serial]
    async fn open_error_cleanup_follows_the_read_by_operation() {
        use stellar_agent_network::policy_state::store::commit_faults::{
            COMMIT_FAULT_AFTER_COUNTER, COMMIT_FAULT_AFTER_PREPARED, arm_accounting_fault,
        };
        let (fixture, context, envelope) = confirmation_fixture("durable-open-error");
        let _presence = driver::install(driver::fixture_credential());
        let before = prepared_operation(&context, "before-commit", &envelope);
        let armed = arm_accounting_fault(COMMIT_FAULT_AFTER_PREPARED);
        durable(&fixture, &context, &envelope, &before, 300_000)
            .await
            .unwrap_err();
        drop(armed);
        assert!(inbox(&fixture).is_empty());
        assert_eq!(durable_record(&context, &before), None);
        assert!(driver::ceremonies().is_empty());

        let after = prepared_operation(&context, "after-commit", &envelope);
        let armed = arm_accounting_fault(COMMIT_FAULT_AFTER_COUNTER);
        durable(&fixture, &context, &envelope, &after, 300_000)
            .await
            .unwrap_err();
        drop(armed);
        let entries = inbox(&fixture);
        assert_eq!(entries.len(), 1);
        let record = durable_record(&context, &after).unwrap();
        assert_eq!(record.nonce, entries[0].approval_nonce);
        assert!(driver::ceremonies().is_empty());
        let witness = durable(&fixture, &context, &envelope, &after, 300_000)
            .await
            .unwrap();
        assert_eq!(witness.nonce(), record.nonce);
        assert_eq!(inbox(&fixture).len(), 1);
        assert_eq!(driver::ceremonies().len(), 1);
    }

    /// A refused open reaches the CLI boundary with the store's code and
    /// text.
    #[cfg(feature = "mainnet-write")]
    #[tokio::test]
    #[serial_test::serial]
    async fn open_errors_keep_store_codes() {
        use stellar_agent_core::mainnet::decision::AuthorityScope;
        use stellar_agent_core::policy::ApprovalRequest;
        use stellar_agent_network::policy_state::store::commit_faults::{
            COMMIT_FAULT_AFTER_PREPARED, arm_accounting_fault,
        };
        let (fixture, context, envelope) = confirmation_fixture("durable-codes");
        let _presence = driver::install(driver::fixture_credential());
        let summary =
            MainnetWriteSummary::from_envelope(&envelope, MainnetConsumer::CliPay, 500).unwrap();
        let policy = fixture.current_policy();
        let decision = MainnetDecision::for_test(
            Decision::RequireApproval(ApprovalRequest::new("fixture".to_owned(), 300)),
            None,
            policy.digest(),
            policy.sequence(),
            7,
            context.profile_name(),
            context.chain().caip2_str(),
            1_900_000_000_000,
            300_000,
            AuthorityScope::Classic,
        );
        let handle = prepared_operation(&context, "durable-codes", &envelope);
        let mut slot = None;
        let armed = arm_accounting_fault(COMMIT_FAULT_AFTER_PREPARED);
        let refusal = cli_mainnet_authority(
            &decision,
            ConfirmDecision::RequireApproval { ttl_ms: 300_000 },
            &summary,
            &context,
            &policy,
            &fixture.store_path(),
            Some(&handle),
            PolicyDecision::RequireApproval,
            &mut slot,
        )
        .await
        .unwrap_err();
        drop(armed);
        let rendered = serde_json::to_value(render_authority_refusal("pay", refusal)).unwrap();
        assert_eq!(rendered["error"]["code"], "submission.record_unavailable");
        assert_eq!(
            rendered["error"]["message"],
            "the submission could not be durably recorded, so nothing was sent: \
             the operation record could not be read or written: \
             policy window-state store I/O error: Interrupted"
        );
    }

    /// A browser refusal after the open keeps entry and record, and the
    /// retry runs the ceremony on the same entry with no insert and no open.
    #[cfg(feature = "mainnet-write")]
    #[tokio::test]
    #[serial_test::serial]
    async fn presence_failure_after_open_keeps_entry_and_record() {
        let (fixture, context, envelope) = confirmation_fixture("durable-presence");
        let handle = prepared_operation(&context, "durable-presence", &envelope);
        let browser = driver::install(Box::new(|_| {
            Err(WalletError::Approval(
                ApprovalFailure::PresenceBrowserRequired,
            ))
        }));
        let error = durable(&fixture, &context, &envelope, &handle, 300_000)
            .await
            .unwrap_err();
        drop(browser);
        assert_eq!(error.code(), "approval.presence_browser_required");
        let entries = inbox(&fixture);
        assert_eq!(entries.len(), 1);
        assert!(entries[0].attestation_blob_b64.is_none());
        let record = durable_record(&context, &handle).unwrap();
        assert_eq!(record.nonce, entries[0].approval_nonce);
        assert_eq!(record.consent, None);

        let _presence = driver::install(driver::fixture_credential());
        let witness = durable(&fixture, &context, &envelope, &handle, 300_000)
            .await
            .unwrap();
        assert_eq!(witness.nonce(), record.nonce);
        assert_eq!(inbox(&fixture).len(), 1);
        assert_eq!(driver::ceremonies().len(), 1);
        let record = durable_record(&context, &handle).unwrap();
        assert!(record.consent.is_some());
        assert_eq!(record.created_at_ms, entries[0].created_at_unix_ms);
    }

    /// Runs a durable ceremony whose consent commit stops after its prepared
    /// image, which leaves an attested entry and a record without consent.
    #[cfg(feature = "mainnet-write")]
    async fn crash_after_attestation(
        fixture: &MainnetConsentFixture,
        context: &MainnetWriteContext,
        envelope: &str,
        handle: &OperationHandle,
    ) -> WalletError {
        use stellar_agent_network::policy_state::store::commit_faults::{
            COMMIT_FAULT_AFTER_PREPARED, arm_accounting_fault, observe_commit,
        };
        let mut commits = 0;
        let observed = observe_commit(move |point| {
            if point == COMMIT_FAULT_AFTER_PREPARED {
                commits += 1;
                if commits == 2 {
                    std::mem::forget(arm_accounting_fault(point));
                }
            }
        });
        let error = durable(fixture, context, envelope, handle, 300_000)
            .await
            .unwrap_err();
        drop(observed);
        error
    }

    /// A consent commit that fails returns no witness: the entry is attested
    /// and the record holds no consent.
    #[cfg(feature = "mainnet-write")]
    #[tokio::test]
    #[serial_test::serial]
    async fn ceremony_witness_follows_the_durable_commit() {
        let (fixture, context, envelope) = confirmation_fixture("durable-commit");
        let _presence = driver::install(driver::fixture_credential());
        let handle = prepared_operation(&context, "durable-commit", &envelope);
        let error = crash_after_attestation(&fixture, &context, &envelope, &handle).await;
        assert_eq!(error.code(), "submission.record_unavailable");
        assert!(inbox(&fixture)[0].attestation_blob_b64.is_some());
        assert_eq!(durable_record(&context, &handle).unwrap().consent, None);
        assert_eq!(consent_rows(&context), 1);
    }

    /// After an attestation without durable consent, the rerun records the
    /// original receipt as recovered consent with no ceremony and no row. A
    /// rerun after the consent returns the witness and writes nothing.
    #[cfg(feature = "mainnet-write")]
    #[tokio::test]
    #[serial_test::serial]
    async fn ceremony_rerun_recovers_without_a_second_ceremony() {
        let (fixture, context, envelope) = confirmation_fixture("durable-recover");
        let _presence = driver::install(driver::fixture_credential());
        let handle = prepared_operation(&context, "durable-recover", &envelope);
        crash_after_attestation(&fixture, &context, &envelope, &handle).await;
        let entry = inbox(&fixture).remove(0);
        let witness = durable(&fixture, &context, &envelope, &handle, 300_000)
            .await
            .unwrap();
        assert_eq!(witness.nonce(), entry.approval_nonce);
        assert_eq!(driver::ceremonies().len(), 1);
        assert_eq!(consent_rows(&context), 1);
        let consent = durable_record(&context, &handle).unwrap().consent.unwrap();
        let receipt = entry.mainnet_presence.unwrap();
        assert_eq!(consent.consent_at_ms, receipt.verified_at_unix_ms());
        let payload = consent.payload.unwrap();
        assert_eq!(payload.receipt, receipt);
        assert_eq!(
            payload.row_provenance,
            Some(stellar_agent_network::policy_state::RowProvenance::Recovered)
        );
        let window = std::fs::read(
            stellar_agent_core::profile::schema::default_policy_window_state_path_for(
                context.profile_name(),
            ),
        )
        .unwrap();
        let again = durable(&fixture, &context, &envelope, &handle, 300_000)
            .await
            .unwrap();
        assert_eq!(again.nonce(), entry.approval_nonce);
        assert_eq!(driver::ceremonies().len(), 1);
        assert_eq!(
            std::fs::read(
                stellar_agent_core::profile::schema::default_policy_window_state_path_for(
                    context.profile_name(),
                ),
            )
            .unwrap(),
            window
        );
    }

    /// Polls `future` and returns `Err` when one of its polls panics.
    #[cfg(feature = "mainnet-write")]
    async fn until_crash<F: std::future::Future>(future: F) -> Result<F::Output, ()> {
        let mut future = std::pin::pin!(future);
        std::future::poll_fn(|cx| {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                future.as_mut().poll(cx)
            })) {
                Ok(std::task::Poll::Ready(output)) => std::task::Poll::Ready(Ok(output)),
                Ok(std::task::Poll::Pending) => std::task::Poll::Pending,
                Err(_) => std::task::Poll::Ready(Err(())),
            }
        })
        .await
    }

    /// The nonce prefixes of the consent rows in the profile's audit log.
    #[cfg(feature = "mainnet-write")]
    fn consent_row_nonces(context: &MainnetWriteContext) -> Vec<String> {
        std::fs::read_to_string(&context.profile().audit_log_path)
            .unwrap_or_default()
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .filter(|row| row["kind"] == "approval_attested")
            .map(|row| row["nonce_prefix"].as_str().unwrap().to_owned())
            .collect()
    }

    /// A ceremony that stops after its consent row and before the inbox
    /// attestation leaves a linked unattested entry. The rerun runs a fresh
    /// ceremony on that entry: two rows for one nonce, one entry, and one
    /// record that holds the second receipt's consent.
    #[cfg(feature = "mainnet-write")]
    #[tokio::test]
    #[serial_test::serial]
    async fn ceremony_rerun_after_a_row_only_crash_writes_a_second_row() {
        use stellar_agent_core::approval::attest::consent_test_seam;
        let (fixture, context, envelope) = confirmation_fixture("durable-row-only");
        let _presence = driver::install(driver::fixture_credential());
        let handle = prepared_operation(&context, "durable-row-only", &envelope);
        consent_test_seam::on_written(&fixture.store_path(), || {
            panic!("test crash: after the consent row")
        });
        let crashed = until_crash(durable(&fixture, &context, &envelope, &handle, 300_000)).await;
        assert!(crashed.is_err(), "the ceremony stops at the seam");
        // A restarted process opens the audit log afresh.
        stellar_agent_core::audit_log::writer::AuditWriterRegistry::remove_for_test(
            context.profile_name(),
        );
        let entries = inbox(&fixture);
        assert_eq!(entries.len(), 1);
        assert!(entries[0].attestation_blob_b64.is_none());
        let nonce = entries[0].approval_nonce.clone();
        let record = durable_record(&context, &handle).unwrap();
        assert_eq!(record.nonce, nonce);
        assert_eq!(record.consent, None);
        assert_eq!(consent_row_nonces(&context).len(), 1);

        let witness = durable(&fixture, &context, &envelope, &handle, 300_000)
            .await
            .unwrap();
        assert_eq!(witness.nonce(), nonce);
        assert_eq!(driver::ceremonies().len(), 2);
        let rows = consent_row_nonces(&context);
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|prefix| nonce.starts_with(prefix.as_str())));
        let entries = inbox(&fixture);
        assert_eq!(entries.len(), 1);
        let receipt = entries[0].mainnet_presence.clone().unwrap();
        let record = durable_record(&context, &handle).unwrap();
        assert_eq!(record.nonce, nonce);
        assert!(record.consent.is_some(), "the rerun records consent");
        let consent = record.consent.unwrap();
        assert_eq!(consent.consent_at_ms, receipt.verified_at_unix_ms());
        assert_eq!(consent.payload.unwrap().receipt, receipt);
        let window = std::fs::read(
            stellar_agent_core::profile::schema::default_policy_window_state_path_for(
                context.profile_name(),
            ),
        )
        .unwrap();
        let body: serde_json::Value = serde_json::from_slice(
            &window[crate::common::mainnet_write_fixture::WINDOW_HMAC_TAG_BYTES..],
        )
        .unwrap();
        assert_eq!(body["approvals"]["records"].as_array().unwrap().len(), 1);
    }

    /// Without a record, the ceremony first removes the unattested live
    /// entry of its envelope that a crash left, and keeps other entries.
    #[cfg(feature = "mainnet-write")]
    #[tokio::test]
    #[serial_test::serial]
    async fn rerun_removes_the_orphan_and_keeps_one_nonce() {
        let (fixture, context, envelope) = confirmation_fixture("durable-orphan");
        let _presence = driver::install(driver::fixture_credential());
        let other = stellar_agent_test_support::SignedTestEnvelope::builder([8; 32])
            .unsigned()
            .sequence(3)
            .amount_stroops(17)
            .build();
        for parked in [envelope.as_str(), other.envelope_xdr()] {
            let entry = MainnetWriteSummary::from_envelope(parked, MainnetConsumer::CliPay, 500)
                .unwrap()
                .pending("1000".into(), 300_000)
                .unwrap();
            pending_store(&fixture)
                .insert(entry.clone(), entry.created_at_unix_ms)
                .unwrap();
        }
        let handle = prepared_operation(&context, "durable-orphan", &envelope);
        let witness = durable(&fixture, &context, &envelope, &handle, 300_000)
            .await
            .unwrap();
        let entries = inbox(&fixture);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].approval_nonce, witness.nonce());
        let ApprovalKind::PaymentSimulated {
            envelope_xdr_b64, ..
        } = &entries[0].kind
        else {
            panic!("payment")
        };
        assert_eq!(envelope_xdr_b64, other.envelope_xdr());
    }

    /// A handle outside `Prepared` without a record refuses with
    /// the open's code before the inbox changes.
    #[cfg(feature = "mainnet-write")]
    #[tokio::test]
    #[serial_test::serial]
    async fn resumed_handle_without_a_record_refuses() {
        use stellar_agent_network::policy_state::{
            BusinessId, LookupOutcome, OperationRecorder, TransitionEvidence,
        };
        let (fixture, context, envelope) = confirmation_fixture("durable-resumed");
        let _presence = driver::install(driver::fixture_credential());
        let orphan = MainnetWriteSummary::from_envelope(&envelope, MainnetConsumer::CliPay, 500)
            .unwrap()
            .pending("1000".into(), 300_000)
            .unwrap();
        pending_store(&fixture)
            .insert(orphan.clone(), orphan.created_at_unix_ms)
            .unwrap();
        let prepared = prepared_operation(&context, "durable-resumed", &envelope);
        let store = PersistedWindowStore::for_profile(context.profile_name());
        let mut rows = NoRows;
        let mut recorder = OperationRecorder::new(&store, context.profile(), &mut rows, "fixture");
        recorder
            .transition(
                prepared.id(),
                None,
                OperationState::AwaitingApproval,
                &TransitionEvidence::default(),
            )
            .unwrap();
        let Some(LookupOutcome::Resumable(handle)) = recorder
            .lookup(&BusinessId::parse("durable-resumed").unwrap())
            .unwrap()
        else {
            panic!("a resumable operation")
        };
        assert_eq!(handle.state(), OperationState::AwaitingApproval);
        let error = durable(&fixture, &context, &envelope, &handle, 300_000)
            .await
            .unwrap_err();
        assert_eq!(error.code(), "internal.unexpected_state");
        assert_eq!(
            error.to_string(),
            "unexpected internal state: the approval requires a matching prepared operation"
        );
        let entries = inbox(&fixture);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].approval_nonce, orphan.approval_nonce);
        assert!(driver::ceremonies().is_empty());
    }

    /// Proof-free `Allow` under an operation runs no ceremony and opens no
    /// record.
    #[cfg(feature = "mainnet-write")]
    #[tokio::test]
    #[serial_test::serial]
    async fn allow_opens_no_durable_record() {
        use stellar_agent_core::mainnet::decision::AuthorityScope;
        let (fixture, context, envelope) = confirmation_fixture("durable-allow");
        let _presence = driver::install(driver::fixture_credential());
        let summary =
            MainnetWriteSummary::from_envelope(&envelope, MainnetConsumer::CliPay, 500).unwrap();
        let policy = fixture.current_policy();
        let decision = MainnetDecision::for_test(
            Decision::Allow,
            None,
            policy.digest(),
            policy.sequence(),
            7,
            context.profile_name(),
            context.chain().caip2_str(),
            1_900_000_000_000,
            600_000,
            AuthorityScope::Classic,
        );
        let handle = prepared_operation(&context, "durable-allow", &envelope);
        let mut slot = None;
        let authority = cli_mainnet_authority(
            &decision,
            ConfirmDecision::Allow,
            &summary,
            &context,
            &policy,
            &fixture.store_path(),
            Some(&handle),
            PolicyDecision::Allow,
            &mut slot,
        )
        .await
        .unwrap();
        assert!(matches!(authority, MainnetAuthority::Policy(_)));
        assert_eq!(durable_record(&context, &handle), None);
        let operation = stored_operation(&context, &handle);
        assert_eq!(operation["state"], "prepared");
        assert!(operation["prepared_decision"].is_null());
        assert!(driver::ceremonies().is_empty());
        assert!(inbox(&fixture).is_empty());
    }

    /// Inside each window commit of the ceremony, the open and the consent,
    /// another handle opens the inbox store without waiting.
    #[cfg(feature = "mainnet-write")]
    #[tokio::test]
    #[serial_test::serial]
    async fn producers_hold_no_inbox_lock_across_a_window_commit() {
        use stellar_agent_network::policy_state::store::commit_faults::{
            COMMIT_FAULT_AFTER_PREPARED, observe_commit,
        };
        let (fixture, context, envelope) = confirmation_fixture("durable-locks");
        let _presence = driver::install(driver::fixture_credential());
        let handle = prepared_operation(&context, "durable-locks", &envelope);
        let opened = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let seen = std::rc::Rc::clone(&opened);
        let path = fixture.store_path();
        let observed = observe_commit(move |point| {
            if point == COMMIT_FAULT_AFTER_PREPARED {
                seen.borrow_mut()
                    .push(PendingApprovalStore::open(path.clone()).is_ok());
            }
        });
        durable(&fixture, &context, &envelope, &handle, 300_000)
            .await
            .unwrap();
        drop(observed);
        assert_eq!(*opened.borrow(), vec![true, true]);
    }
}
