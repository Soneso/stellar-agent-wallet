//! Building the durable-submission recorder, reconciling what stands open, and
//! reporting what the submit layer refused.
//!
//! Every value verb that broadcasts records its submission before the
//! transaction is sent, and settles that record against what the network
//! answers. The construction is identical across the verbs, so it lives here
//! once, alongside the reconciliation pass each verb runs before its policy
//! gate and the mapping that turns the three unresolved-submission refusals
//! into a response an operator or an agent can act on.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use stellar_agent_core::approval::witness::ApprovalWitness;
use stellar_agent_core::audit_log::schema::ValueLegRecord;
use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::{NetworkError, SubmissionError, WalletError};
use stellar_agent_core::policy::v1::{ValueClass, ValueEffects};
use stellar_agent_core::policy::{McpToolRegistration, ToolDescriptor, ToolValueKind};
use stellar_agent_core::profile::receipt::ReceiptStore;
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_network::cross_check::CrossCheckWitness;
use stellar_agent_network::mainnet::audit_readiness::AuditReadiness;
use stellar_agent_network::mainnet::authorization::MainnetTxSignAuthorization;
use stellar_agent_network::mainnet::consumed::AuthorizationConsumed;
use stellar_agent_network::policy_state::{PersistedWindowStore, RECONCILE_BUDGET};
use stellar_agent_network::{
    ApprovalTombstone, AuditWriterHandle, MainnetSubmitGrant, MainnetWriteContext, NetworkContext,
    StellarRpcClient, SubmissionIntent, SubmissionOutcome, SubmissionRecorder,
    WalletSubmissionRecorder, envelope_hash_hex,
};

use crate::common::profile_access::ProfileOrigin;

/// Observes retained intents before the caller constructs its policy engine.
pub(crate) async fn observe_intents(profile: &Profile, profile_name: &str) {
    PersistedWindowStore::for_profile(profile_name)
        .observe_before_policy(profile)
        .await;
}

/// Observes and replaces the state of an existing policy engine.
///
/// # Errors
/// Refuses a state clear or verified refresh failure.
pub(crate) async fn observe_and_refresh_intents(
    profile: &Profile,
    profile_name: &str,
    engine: &dyn stellar_agent_core::policy::PolicyEngine,
) -> Result<(), stellar_agent_network::policy_state::WindowStoreError> {
    let Some(state) = engine.window_state_store() else {
        return Ok(());
    };
    let window = PersistedWindowStore::for_profile(profile_name);
    window.observe_before_policy(profile).await;
    state.clear().map_err(|error| {
        stellar_agent_network::policy_state::WindowStoreError::Invalid {
            detail: error.to_string(),
        }
    })?;
    window.load_into(profile_name, profile, state)
}

/// The verb this binary names as the way to reconcile a submission whose
/// outcome is not known.
pub(crate) const RECONCILE_VERB: &str = "stellar-agent tx status";

/// Everything a value verb knows about the submission it is about to make.
pub(crate) struct SubmitRecord<'a> {
    /// The profile the submission is made under.
    pub profile: &'a Profile,
    /// The operator's resolved profile name.
    pub profile_name: String,
    /// The verb whose policy engine is rebuilt to size the action, as it
    /// appears in `policy.toml` diagnostics.
    pub verb: &'static str,
    /// The registered tool name, as it appears in the audit log.
    pub tool: &'static str,
    /// The policy decision that admitted this submission.
    pub policy_decision: stellar_agent_core::audit_log::PolicyDecision,
    /// CAIP-2 chain identifier for the audit rows.
    pub chain_id: &'a str,
    /// The authenticated value effects the policy gate sizes.
    /// Without effects, `unvalued` supplies checked count sizing when present.
    pub effects: Option<&'a ValueEffects>,
    /// The reason a contract call has no measurable value effects.
    pub unvalued: Option<stellar_agent_core::policy::v1::OpaqueReason>,
    /// The audit writer the origin-aware pre-flight acquired. `None` only on a
    /// synthesized zero-configuration profile, which has no audit log to write
    /// to.
    pub audit: Option<Arc<Mutex<AuditWriter>>>,
    /// The caller's clock in unix milliseconds.
    pub now_ms: u64,
}

/// Builds the recorder for one submission.
///
/// The window entries come from the policy engine's own accounting for this
/// action, rebuilt from the profile the same way the gate's engine was: the
/// SAME derivation the gate evaluated and the audit rows carry.
///
/// # Errors
///
/// Returns `submission.record_unavailable` when the receipt store cannot be
/// opened, the policy engine cannot be rebuilt, or it cannot account for the
/// action. All three refuse the submission: a send the wallet cannot record is
/// one it cannot reconcile, cap, or audit afterwards.
pub(crate) fn build_recorder(
    record: SubmitRecord<'_>,
) -> Result<WalletSubmissionRecorder<'_>, WalletError> {
    let receipts = ReceiptStore::open(&record.profile_name).map_err(|e| {
        record_unavailable(format!(
            "the submission receipt store could not be opened: {e}"
        ))
    })?;

    let legs: Vec<ValueLegRecord> = record
        .effects
        .map(|e| e.legs().iter().map(Into::into).collect())
        .unwrap_or_default();

    let engine = || {
        crate::commands::policy_engine::build_v1_policy_engine(
            record.verb,
            &record.profile.policy.engine,
            record.profile,
            &record.profile_name,
        )
        .map_err(|error| {
            record_unavailable(format!("the policy engine cannot be rebuilt: {error}"))
        })
    };
    let sizing = match (record.effects, record.unvalued) {
        (Some(effects), _) => Some(engine()?.record_confirmed_checked(
            &descriptor_for(record.tool, record.chain_id, ToolValueKind::MovesValue),
            record.profile,
            &ValueClass::Value(effects.clone()),
        )),
        (None, Some(reason)) => Some(engine()?.size_unvalued_call(
            &descriptor_for(record.tool, record.chain_id, ToolValueKind::OpaqueSign),
            record.profile,
            reason,
            record.now_ms,
        )),
        (None, None) => None,
    }
    .map(|outcome| {
        match outcome.map_err(|error| {
            record_unavailable(format!(
                "the policy engine cannot account for this action: {error}"
            ))
        })? {
            stellar_agent_core::policy::v1::SizingOutcome::Sized(sizing) => Ok(sizing),
            stellar_agent_core::policy::v1::SizingOutcome::Refused(reason) => {
                Err(WalletError::PolicyDenied {
                    reason: Box::new(reason),
                })
            }
            _ => Err(record_unavailable("unsupported sizing outcome".to_owned())),
        }
    })
    .transpose()?;
    let window_entries = sizing
        .as_ref()
        .map(|sizing| sizing.entries().to_vec())
        .unwrap_or_default();

    let recorder = WalletSubmissionRecorder::new(
        record.profile,
        record.profile_name.clone(),
        record.tool,
        Some(record.chain_id.to_owned()),
        record.policy_decision,
        legs,
        window_entries,
        receipts,
        PersistedWindowStore::for_profile(&record.profile_name),
        record.audit,
        None,
        uuid::Uuid::new_v4().to_string(),
        record.now_ms,
    );
    Ok(match sizing {
        Some(sizing) => recorder.with_signing_sizing(sizing),
        None => recorder,
    })
}

/// Builds checked count admission from the profile's policy engine.
pub(crate) fn no_value_admission(
    profile: &Profile,
    profile_name: &str,
    tool: &'static str,
    chain_id: &str,
    now_ms: u64,
) -> Result<Arc<stellar_agent_network::NoValueAdmission>, WalletError> {
    let unavailable = |_| {
        WalletError::Submission(SubmissionError::IntentRecordUnavailable {
            class: "policy_unavailable",
        })
    };
    let engine = crate::commands::policy_engine::build_v1_policy_engine(
        tool,
        &profile.policy.engine,
        profile,
        profile_name,
    )
    .map_err(|_| {
        WalletError::Submission(SubmissionError::IntentRecordUnavailable {
            class: "policy_unavailable",
        })
    })?;
    let sizing = engine
        .size_no_value(
            &descriptor_for(tool, chain_id, ToolValueKind::ReadOnly),
            profile,
            now_ms,
        )
        .map_err(unavailable)?;
    stellar_agent_network::NoValueAdmission::new(profile.clone(), profile_name, sizing)
        .map(Arc::new)
}

/// What a mainnet write's recorder records, prepared before the
/// authorization is minted.
///
/// Everything that can fail is done here: the receipt store is open, the
/// approval directory is resolved, and the clock is read. Binding to the
/// minted authorization cannot fail, so no refusal falls between the mint and
/// the signer.
pub(crate) struct PreparedMainnetRecorder<'a> {
    profile: &'a Profile,
    profile_name: String,
    tool: &'static str,
    chain_id: String,
    decision: stellar_agent_core::audit_log::PolicyDecision,
    legs: Vec<ValueLegRecord>,
    receipts: ReceiptStore,
    window: PersistedWindowStore,
    audit: AuditWriterHandle,
    request_id: String,
    now_ms: u64,
    witness: Option<&'a CrossCheckWitness>,
    tombstone: ApprovalTombstone,
}

/// Prepares the recorder of a mainnet write under `context`.
///
/// The legs are the evaluation's `effects`; the window entries come from the
/// authorization at [`PreparedMainnetRecorder::bind_authorized`], never from
/// a rebuilt engine. The audit writer is the one `readiness` verified. The
/// confirmation entry `approval` names is tombstoned when the submission
/// settles.
///
/// # Errors
///
/// `submission.record_unavailable` when the receipt store cannot be opened,
/// the approval directory cannot be resolved, or the clock cannot be read.
pub(crate) fn prepare_mainnet_recorder<'a>(
    context: &'a MainnetWriteContext,
    tool: &'static str,
    decision: stellar_agent_core::audit_log::PolicyDecision,
    effects: Option<&ValueEffects>,
    readiness: &AuditReadiness,
    witness: Option<&'a CrossCheckWitness>,
    approval: &ApprovalWitness,
) -> Result<PreparedMainnetRecorder<'a>, WalletError> {
    let profile_name = context.profile_name().to_owned();
    let receipts = ReceiptStore::open(&profile_name).map_err(|e| {
        record_unavailable(format!(
            "the submission receipt store could not be opened: {e}"
        ))
    })?;
    let store_dir = crate::commands::approve::approval_store_dir().map_err(|e| {
        record_unavailable(format!(
            "the approval store directory could not be resolved: {e}"
        ))
    })?;
    let now_ms = stellar_agent_network::mainnet::clock::now_ms()
        .map_err(|e| record_unavailable(format!("the clock could not be read: {e}")))?;
    let legs: Vec<ValueLegRecord> = effects
        .map(|e| e.legs().iter().map(Into::into).collect())
        .unwrap_or_default();
    Ok(PreparedMainnetRecorder {
        profile: context.profile(),
        tombstone: ApprovalTombstone {
            store_dir,
            profile_name: profile_name.clone(),
            approval_nonce: approval.nonce().to_owned(),
        },
        window: PersistedWindowStore::for_profile(&profile_name),
        chain_id: context.chain().caip2_str().to_owned(),
        profile_name,
        tool,
        decision,
        legs,
        receipts,
        audit: Arc::clone(readiness.writer()),
        request_id: uuid::Uuid::new_v4().to_string(),
        now_ms,
        witness,
    })
}

impl<'a> PreparedMainnetRecorder<'a> {
    /// Binds the prepared recorder to the minted `authorization`, whose
    /// window entries it records, with the witness and the confirmation's
    /// tombstone.
    #[must_use]
    pub(crate) fn bind_authorized(
        self,
        authorization: &MainnetTxSignAuthorization,
    ) -> StageMarkedRecorder<'a> {
        let recorder = WalletSubmissionRecorder::new_authorized(
            self.profile,
            self.profile_name,
            self.tool,
            Some(self.chain_id),
            self.decision,
            self.legs,
            authorization,
            self.receipts,
            self.window,
            Some(self.audit),
            None,
            self.request_id,
            self.now_ms,
        )
        .with_witness(self.witness)
        .with_approval(Some(self.tombstone));
        StageMarkedRecorder {
            inner: recorder,
            pre_send_entered: AtomicBool::new(false),
        }
    }
}

/// The recorder of a mainnet write, marking whether the submit reached the
/// authorized pre-send hook.
///
/// The mark separates the two refusals of the submit that share a code: a
/// refusal of the submit gate before the hook, and a refusal inside it.
pub(crate) struct StageMarkedRecorder<'a> {
    inner: WalletSubmissionRecorder<'a>,
    pre_send_entered: AtomicBool,
}

impl StageMarkedRecorder<'_> {
    /// Whether [`SubmissionRecorder::pre_send_authorized`] was entered.
    #[must_use]
    pub(crate) fn pre_send_entered(&self) -> bool {
        self.pre_send_entered.load(Ordering::SeqCst)
    }
}

impl std::fmt::Debug for StageMarkedRecorder<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StageMarkedRecorder")
            .field("inner", &self.inner)
            .field("pre_send_entered", &self.pre_send_entered())
            .finish()
    }
}

#[async_trait::async_trait]
impl SubmissionRecorder for StageMarkedRecorder<'_> {
    async fn admit_signed_intent(
        &self,
        plan: &stellar_agent_network::SignedIntentPlan,
    ) -> Result<stellar_agent_network::IntentProof, WalletError> {
        self.inner.admit_signed_intent(plan).await
    }
    async fn cancel_unexposed(
        &self,
        proof: stellar_agent_network::IntentProof,
    ) -> Result<(), WalletError> {
        self.inner.cancel_unexposed(proof).await
    }
    async fn pre_send_bound(
        &self,
        intent: &stellar_agent_network::SubmissionIntent,
        binding: &stellar_agent_network::IntentBinding<'_>,
    ) -> Result<(), WalletError> {
        self.inner.pre_send_bound(intent, binding).await
    }

    async fn pre_send(&self, intent: &SubmissionIntent) -> Result<(), WalletError> {
        self.inner.pre_send(intent).await
    }

    async fn pre_send_authorized(
        &self,
        intent: &SubmissionIntent,
        grant: MainnetSubmitGrant,
    ) -> Result<AuthorizationConsumed, WalletError> {
        self.pre_send_entered.store(true, Ordering::SeqCst);
        self.inner.pre_send_authorized(intent, grant).await
    }

    async fn outcome(&self, intent: &SubmissionIntent, outcome: &SubmissionOutcome) {
        self.inner.outcome(intent, outcome).await;
    }
}

/// Reconstructs the [`ToolDescriptor`] the gate evaluated against.
fn descriptor_for(tool: &'static str, chain_id: &str, value_kind: ToolValueKind) -> ToolDescriptor {
    let reg = McpToolRegistration {
        name: tool,
        destructive_hint: true,
        read_only_hint: false,
        chain_id_required: true,
        value_kind,
    };
    let mut descriptor = ToolDescriptor::from_registration(&reg);
    descriptor.chain_id = chain_id.to_owned();
    descriptor
}

/// The oracle a reconciliation pass of `profile` asks before a negative
/// answer of the primary endpoint settles a mainnet reservation, built from
/// the profile.
///
/// See [`settlement_oracle_in`].
pub(crate) fn settlement_oracle(profile: &Profile) -> Option<StellarRpcClient> {
    settlement_oracle_in(profile, &NetworkContext::from_profile(profile))
}

/// The oracle a reconciliation pass of `profile` asks before a negative
/// answer of the primary endpoint settles a mainnet reservation, built as
/// `context` builds its clients.
///
/// `None` for a profile on another chain, whose pass never reads an oracle,
/// and for a mainnet profile that names none. An oracle client that cannot
/// be built is logged and also yields `None`: the pass then keeps every
/// reservation the primary reports as failed or unknown, as it does when the
/// oracle cannot be reached.
pub(crate) fn settlement_oracle_in(
    profile: &Profile,
    context: &NetworkContext,
) -> Option<StellarRpcClient> {
    let name = stellar_agent_core::profile::name::derive_profile_name_from_owner_key(profile)?;
    let scope = PersistedWindowStore::for_profile(name)
        .chain_scope(profile)
        .ok()?;
    if !scope.chain().is_mainnet() {
        return None;
    }
    match context.oracle_client(profile) {
        Ok(oracle) => oracle,
        Err(e) => {
            tracing::warn!(
                code = %e.code(),
                "window reconcile: the oracle client could not be built; negative answers of \
                 the primary endpoint settle nothing this pass"
            );
            None
        }
    }
}

/// Settles the reservations that have stood long enough to be settleable,
/// before the policy gate counts them.
///
/// A reservation counts against the operator's caps while it stands, so a
/// verb that is about to be gated asks the chain about the oldest few first.
/// Reconciliation is not a gate of its own: a pass that cannot reach the
/// endpoint leaves every reservation standing and the verb continues, because
/// counting a reservation that may still apply is the safe direction.
///
/// On a mainnet profile `oracle` witnesses the primary endpoint's negative
/// answers; [`settlement_oracle`] builds it.
///
/// Every owed accounting obligation is then drained under the audit binding
/// check of `origin`, so a synthesized profile records no binding. The drain
/// runs whatever the pass reported, also after a refused pass, so obligations
/// of earlier passes are delivered too.
pub(crate) async fn reconcile_open_reservations(
    profile: &Profile,
    profile_name: &str,
    origin: ProfileOrigin,
    client: &StellarRpcClient,
    oracle: Option<&StellarRpcClient>,
    now_ms: u64,
) {
    let receipts = match ReceiptStore::open(profile_name) {
        Ok(store) => Some(store),
        Err(e) => {
            tracing::debug!(
                profile = %profile_name,
                error = %e,
                "window reconcile: receipt store unavailable; receipts are not updated by this pass"
            );
            None
        }
    };
    let window = PersistedWindowStore::for_profile(profile_name);
    match window
        .reconcile_due(
            profile,
            client,
            oracle,
            receipts.as_ref(),
            now_ms,
            RECONCILE_BUDGET,
        )
        .await
    {
        Ok(report) if report.receipt_write_failed > 0 => tracing::debug!(
            profile = %profile_name,
            receipt_write_failed = report.receipt_write_failed,
            "window reconcile: receipt writes stay owed"
        ),
        Ok(_) => {}
        Err(e) => tracing::debug!(
            profile = %profile_name,
            error = ?e,
            "window reconcile: pass failed; open reservations stand"
        ),
    }

    // Accounting expiry commits its audit obligation with the expiry, so the
    // drain delivers it from the verified window state. A refusal is logged
    // and stays owed.
    let _ = stellar_agent_network::policy_state::drain_accounting_obligations(
        &window,
        profile,
        profile_name,
        receipts.as_ref(),
        || accounting_audit_writer(profile, profile_name, origin),
    );
}

/// The writer accounting delivery appends through, acquired under the audit
/// binding check of `origin`, for a caller that holds none.
///
/// # Errors
///
/// The acquisition refusal of
/// [`crate::commands::value_audit::require_value_audit_writer_for_origin`],
/// and `submission.record_unavailable` for a synthesized profile whose writer
/// cannot be acquired. The obligations then stay owed.
pub(crate) fn accounting_audit_writer(
    profile: &Profile,
    profile_name: &str,
    origin: ProfileOrigin,
) -> Result<Arc<Mutex<AuditWriter>>, WalletError> {
    crate::commands::value_audit::require_value_audit_writer_for_origin(
        profile,
        profile_name,
        origin,
    )?
    .ok_or_else(|| record_unavailable("no audit writer is available for accounting delivery"))
}

/// Renders a submit-path error, attaching the structured detail the three
/// unknown-outcome codes need.
///
/// `submission.tx_timeout`, `submission.tx_already_submitted` and
/// `submission.hash_mismatch` all describe a transaction whose outcome only
/// reconciliation can settle, and the caller needs the full transaction hash
/// to do it. The message stays redacted; the hash travels as data.
///
/// A policy denial from the reservation write renders as this binary's gate
/// denials do, under `verb`. Every other error renders as a wallet error.
pub(crate) fn error_envelope(err: &WalletError, signed_xdr: &str, verb: &str) -> Envelope<()> {
    if let Some(envelope) = policy_denial_envelope(err, verb) {
        return envelope;
    }
    match submission_details(err, signed_xdr) {
        Some(details) => Envelope::<()>::err_with_details(err, details),
        None => Envelope::<()>::err(err),
    }
}

/// The refusal envelope for a policy denial reported by the submit path, or
/// `None` for every other error.
///
/// The spending-window reservation write re-applies the governing criterion's
/// comparison under its own lock and refuses a submission the window can no
/// longer admit. That refusal is the same decision the gate makes, so it is
/// reported the same way: the criterion's own wire code, and the wording
/// `policy_engine`'s deny arm uses for `verb`.
pub(crate) fn policy_denial_envelope(err: &WalletError, verb: &str) -> Option<Envelope<()>> {
    let WalletError::PolicyDenied { reason } = err else {
        return None;
    };
    let message = match reason.as_ref() {
        stellar_agent_core::policy::DenyReason::EvaluationError { detail } => {
            format!("{verb} operation denied by operator policy: {detail}")
        }
        _ => format!("{verb} operation denied by operator policy"),
    };
    Some(Envelope::<()>::err_raw(reason.wire_code(), message))
}

/// The wire code a submission that was never sent reports. A pre-send
/// refusal, so it carries no `details`.
const UNRESOLVED_RECORD_UNAVAILABLE: &str = "submission.record_unavailable";

/// An unresolved submission reported by a verb that holds the typed DeFi or
/// smart-account error rather than a [`WalletError`].
///
/// The submit layer's refusal reaches those verbs through
/// `SaError::SubmissionUnresolved` and `DefiAdapterError::SubmissionUnresolved`,
/// which carry the wire code and the identifiers. Flattening them to a generic
/// failure would leave the operator with a redacted message and no hash, which
/// is the state the durable record exists to remove.
pub(crate) struct UnresolvedSubmission<'a> {
    /// The stable `submission.*` code for the condition.
    pub wire_code: &'static str,
    /// The redacted operator-facing message.
    pub message: &'a str,
    /// The transaction to reconcile, in full.
    pub tx_hash: Option<&'a str>,
    /// The submission record's identity, when the verb holds it.
    pub envelope_hash: Option<&'a str>,
    /// The submission timeout in seconds, on the one condition that has one.
    pub timeout_seconds: Option<u64>,
}

impl UnresolvedSubmission<'_> {
    /// The `details` object the recovery protocol reads, or `None`.
    ///
    /// Only the three codes that describe a transaction whose outcome is
    /// unknown carry one. `submission.record_unavailable` is a pre-send
    /// refusal: nothing was sent, there is no transaction to reconcile, and an
    /// `outcome: "unknown"` on it would say the opposite of what happened.
    fn details(&self) -> Option<serde_json::Value> {
        if self.wire_code == UNRESOLVED_RECORD_UNAVAILABLE {
            return None;
        }
        let mut details = serde_json::Map::new();
        if let Some(tx_hash) = self.tx_hash {
            details.insert("tx_hash".to_owned(), tx_hash.into());
        }
        if let Some(envelope_hash) = self.envelope_hash {
            details.insert("envelope_hash".to_owned(), envelope_hash.into());
        }
        if let Some(seconds) = self.timeout_seconds {
            details.insert("timeout_seconds".to_owned(), seconds.into());
        }
        details.insert("outcome".to_owned(), "unknown".into());
        details.insert("reconcile_with".to_owned(), RECONCILE_VERB.into());
        Some(serde_json::Value::Object(details))
    }

    /// The envelope this submission is reported in.
    pub(crate) fn envelope(&self) -> Envelope<()> {
        match self.details() {
            Some(details) => Envelope::<()>::err_raw_with_details(
                self.wire_code,
                self.message.to_owned(),
                details,
            ),
            None => Envelope::<()>::err_raw(self.wire_code, self.message.to_owned()),
        }
    }
}

/// Reads an unresolved submission out of a smart-account error, or `None`.
pub(crate) fn unresolved_from_sa(
    error: &stellar_agent_smart_account::SaError,
) -> Option<UnresolvedSubmission<'_>> {
    match error {
        stellar_agent_smart_account::SaError::SubmissionUnresolved {
            kind,
            message,
            tx_hash,
            envelope_hash,
            timeout_seconds,
        } => Some(UnresolvedSubmission {
            wire_code: kind.wire_code(),
            message,
            tx_hash: tx_hash.as_deref(),
            envelope_hash: envelope_hash.as_deref(),
            timeout_seconds: *timeout_seconds,
        }),
        _ => None,
    }
}

/// Reads an unresolved submission out of a DeFi adapter error, or `None`.
pub(crate) fn unresolved_from_defi(
    error: &stellar_agent_defi::adapter::DefiAdapterError,
) -> Option<UnresolvedSubmission<'_>> {
    match error {
        stellar_agent_defi::adapter::DefiAdapterError::SubmissionUnresolved {
            wire_code,
            message,
            tx_hash,
            envelope_hash,
            timeout_seconds,
        } => Some(UnresolvedSubmission {
            wire_code,
            message,
            tx_hash: tx_hash.as_deref(),
            envelope_hash: envelope_hash.as_deref(),
            timeout_seconds: *timeout_seconds,
        }),
        _ => None,
    }
}

/// Renders a DeFi submit failure and returns the process exit code.
///
/// A policy denial renders as this binary's gate denials do, under `verb`. A
/// mainnet refusal reports `network.mainnet_write_forbidden`. A signing refusal
/// keeps its own code, with no transaction to reconcile. An unresolved
/// submission keeps its `submission.*` code and its `details`; everything else
/// is reported under `fallback_code`.
pub(crate) fn render_defi_submit_error(
    error: &stellar_agent_defi::adapter::DefiAdapterError,
    verb: &str,
    fallback_code: &str,
) -> i32 {
    crate::common::render::render_json(&defi_submit_error_envelope(error, verb, fallback_code));
    1
}

/// The refusal envelope a DeFi submit failure is reported in.
///
/// A policy denial reads as this binary's gate denials read, under `verb`. A
/// mainnet refusal reports `network.mainnet_write_forbidden`. A signing refusal
/// keeps its own code, with no transaction to reconcile. An unresolved
/// submission keeps its `submission.*` code and its `details`; everything else
/// is reported under `fallback_code`.
fn defi_submit_error_envelope(
    error: &stellar_agent_defi::adapter::DefiAdapterError,
    verb: &str,
    fallback_code: &str,
) -> Envelope<()> {
    if let stellar_agent_defi::adapter::DefiAdapterError::PolicyDenied { reason } = error {
        return Envelope::<()>::err_raw(
            reason.wire_code(),
            format!("{verb} operation denied by operator policy"),
        );
    }
    if matches!(
        error,
        stellar_agent_defi::adapter::DefiAdapterError::MainnetWriteForbidden
    ) {
        return Envelope::<()>::err(&WalletError::Network(NetworkError::MainnetWriteForbidden));
    }
    if let stellar_agent_defi::adapter::DefiAdapterError::SigningRefusal { wire_code, message } =
        error
    {
        return Envelope::<()>::err_raw(*wire_code, message.clone());
    }
    match unresolved_from_defi(error) {
        Some(unresolved) => unresolved.envelope(),
        None => Envelope::<()>::err_raw(fallback_code, error.to_string()),
    }
}

/// Renders a submit-path error for a verb whose other submission failures
/// carry their own wire code.
///
/// The three unknown-outcome codes are reported unchanged, with their
/// reconciliation detail: an agent told the submission failed under a
/// verb-specific code would rebuild and re-submit, which is exactly what a
/// transaction that may still apply forbids. A policy denial keeps the
/// criterion's own code, so an agent reads a refused cap as a refused cap.
/// Everything else keeps `fallback_code`.
pub(crate) fn error_envelope_with_fallback(
    err: &WalletError,
    signed_xdr: &str,
    verb: &str,
    fallback_code: &str,
) -> Envelope<()> {
    if let Some(envelope) = policy_denial_envelope(err, verb) {
        return envelope;
    }
    match submission_details(err, signed_xdr) {
        Some(details) => Envelope::<()>::err_with_details(err, details),
        None => Envelope::<()>::err_raw(fallback_code, err.message()),
    }
}

/// The structured detail for the three codes that carry one, or `None`.
fn submission_details(err: &WalletError, signed_xdr: &str) -> Option<serde_json::Value> {
    let WalletError::Submission(submission) = err else {
        return None;
    };
    let mut details = serde_json::Map::new();
    match submission {
        SubmissionError::TxTimeout { tx_hash, seconds } => {
            details.insert("tx_hash".to_owned(), tx_hash.clone().into());
            details.insert("timeout_seconds".to_owned(), (*seconds).into());
        }
        SubmissionError::TxAlreadySubmitted { hash } => {
            details.insert("tx_hash".to_owned(), hash.clone().into());
        }
        SubmissionError::HashMismatch { local, server } => {
            details.insert("tx_hash".to_owned(), local.clone().into());
            details.insert("server_tx_hash".to_owned(), server.clone().into());
        }
        _ => return None,
    }
    // The envelope hash names the submission record the operator verbs
    // address. A caller that does not hold the signed bytes reports the
    // transaction hash alone rather than a hash of nothing.
    if !signed_xdr.is_empty() {
        details.insert(
            "envelope_hash".to_owned(),
            envelope_hash_hex(signed_xdr).into(),
        );
    }
    details.insert("outcome".to_owned(), "unknown".into());
    details.insert("reconcile_with".to_owned(), RECONCILE_VERB.into());
    Some(serde_json::Value::Object(details))
}

fn record_unavailable(detail: impl Into<String>) -> WalletError {
    WalletError::Submission(SubmissionError::RecordUnavailable {
        detail: detail.into(),
    })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::*;
    use stellar_agent_core::profile::receipt::{ReceiptStatus, ReleaseEvidence};
    use stellar_agent_network::policy_state::DeliveryReport;

    const SIGNED_XDR: &str = "AAAAAgAAAAA=";

    /// The accounting audit writer applies the binding check of the origin: a
    /// synthesized profile records no binding and refuses a changed one, and a
    /// persisted profile records an absent one.
    #[test]
    #[serial_test::serial]
    fn the_accounting_audit_writer_applies_the_binding_check_of_the_origin() {
        use stellar_agent_core::audit_log::AuditBinding;
        use stellar_agent_network::keyring::{KeyringAuditBindingStore, rotate_keyring_secret_32};

        stellar_agent_test_support::keyring_mock::install().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let keyed = |name: &str| {
            let mut profile = Profile::builder_testnet_named(name, "s", name, "n", name).build();
            profile.audit_log_path = dir.path().join(name).join("audit.jsonl");
            let coord = &profile.audit_log_hash_chain_key_id;
            rotate_keyring_secret_32(&coord.service, &coord.account).unwrap();
            profile
        };
        let recorded = |name: &str| {
            KeyringAuditBindingStore::for_profile(name)
                .load_raw()
                .unwrap()
                .is_some()
        };

        let synthesized = keyed("reconcile-synthesized");
        assert!(
            accounting_audit_writer(
                &synthesized,
                "reconcile-synthesized",
                ProfileOrigin::Synthesized
            )
            .is_ok()
        );
        assert!(
            !recorded("reconcile-synthesized"),
            "a synthesized profile records no binding"
        );

        let persisted = keyed("reconcile-persisted");
        assert!(
            accounting_audit_writer(&persisted, "reconcile-persisted", ProfileOrigin::Persisted)
                .is_ok()
        );
        assert!(
            recorded("reconcile-persisted"),
            "a persisted profile records its binding"
        );

        let mut changed = keyed("reconcile-changed");
        KeyringAuditBindingStore::for_profile("reconcile-changed")
            .store(&AuditBinding::for_profile(&changed))
            .unwrap();
        changed.audit_log_path = dir.path().join("repointed").join("audit.jsonl");
        assert!(
            accounting_audit_writer(&changed, "reconcile-changed", ProfileOrigin::Synthesized)
                .is_err(),
            "a changed binding leaves the obligations owed"
        );
        assert!(!dir.path().join("repointed").exists());
    }

    #[test]
    fn timeout_carries_the_full_hash_and_the_recovery_protocol() {
        let hash = "ab".repeat(32);
        let err = WalletError::Submission(SubmissionError::TxTimeout {
            tx_hash: hash.clone(),
            seconds: 30,
        });
        let envelope = error_envelope(&err, SIGNED_XDR, "pay");
        let details = envelope.error.as_ref().unwrap().details.as_ref().unwrap();
        assert_eq!(details["tx_hash"], hash);
        assert_eq!(details["timeout_seconds"], 30);
        assert_eq!(details["outcome"], "unknown");
        assert_eq!(details["reconcile_with"], RECONCILE_VERB);
        assert_eq!(details["envelope_hash"], envelope_hash_hex(SIGNED_XDR));
    }

    #[test]
    fn timeout_message_stays_redacted() {
        let hash = "ab".repeat(32);
        let err = WalletError::Submission(SubmissionError::TxTimeout {
            tx_hash: hash.clone(),
            seconds: 30,
        });
        let envelope = error_envelope(&err, SIGNED_XDR, "pay");
        let message = &envelope.error.as_ref().unwrap().message;
        assert!(!message.contains(&hash), "message must stay redacted");
        assert!(message.contains("..."));
    }

    #[test]
    fn other_errors_carry_no_details() {
        let err = WalletError::Submission(SubmissionError::TxMalformed {
            detail: "txINSUFFICIENT_FEE".to_owned(),
        });
        let envelope = error_envelope(&err, SIGNED_XDR, "pay");
        assert!(envelope.error.as_ref().unwrap().details.is_none());
    }

    /// A DeFi submit failure whose outcome is unknown keeps the submission
    /// code and carries the transaction to reconcile.
    #[test]
    fn a_defi_unresolved_submission_reports_the_submission_code_and_details() {
        let error = stellar_agent_defi::adapter::DefiAdapterError::SubmissionUnresolved {
            wire_code: "submission.tx_timeout",
            message: "transaction 'aaaaaaaa...bbbbbbbb' was not confirmed within 30s".to_owned(),
            tx_hash: Some("ab".repeat(32)),
            envelope_hash: Some("cd".repeat(32)),
            timeout_seconds: Some(30),
        };

        let unresolved = unresolved_from_defi(&error).expect("an unresolved submission");
        let envelope = unresolved.envelope();
        let rendered = envelope.error.as_ref().unwrap();
        assert_eq!(rendered.code, "submission.tx_timeout");
        let details = rendered.details.as_ref().unwrap();
        assert_eq!(details["tx_hash"], "ab".repeat(32));
        assert_eq!(details["envelope_hash"], "cd".repeat(32));
        assert_eq!(details["outcome"], "unknown");
        assert_eq!(details["reconcile_with"], RECONCILE_VERB);
    }

    /// A smart-account submit failure whose outcome is unknown does the same.
    #[test]
    fn a_smart_account_unresolved_submission_reports_the_submission_code() {
        let error = stellar_agent_smart_account::SaError::SubmissionUnresolved {
            kind: stellar_agent_smart_account::SubmissionUnresolvedKind::AlreadySubmitted,
            message: "a pending record already holds this sequence".to_owned(),
            tx_hash: Some("ef".repeat(32)),
            envelope_hash: None,
            timeout_seconds: None,
        };

        let unresolved = unresolved_from_sa(&error).expect("an unresolved submission");
        let envelope = unresolved.envelope();
        let rendered = envelope.error.as_ref().unwrap();
        assert_eq!(rendered.code, "submission.tx_already_submitted");
        let details = rendered.details.as_ref().unwrap();
        assert_eq!(details["tx_hash"], "ef".repeat(32));
        assert!(
            details.get("envelope_hash").is_none(),
            "a verb that holds no signed bytes reports the transaction hash alone"
        );
    }

    #[test]
    fn multicall_timeout_preserves_full_hash_in_details() {
        let tx_hash = "ab".repeat(32);
        let envelope_hash = "cd".repeat(32);
        let error = stellar_agent_smart_account::SaError::SubmissionUnresolved {
            kind: stellar_agent_smart_account::SubmissionUnresolvedKind::Timeout,
            message: "transaction 'abababab...abababab' was not confirmed within 2s".to_owned(),
            tx_hash: Some(tx_hash.clone()),
            envelope_hash: Some(envelope_hash.clone()),
            timeout_seconds: Some(2),
        };
        let rendered = serde_json::to_value(
            unresolved_from_sa(&error)
                .expect("typed multicall timeout")
                .envelope(),
        )
        .unwrap();
        assert_eq!(rendered["error"]["code"], "submission.tx_timeout");
        assert_eq!(rendered["error"]["details"]["tx_hash"], tx_hash);
        assert_eq!(rendered["error"]["details"]["envelope_hash"], envelope_hash);
        assert_eq!(rendered["error"]["details"]["timeout_seconds"], 2);
        assert_eq!(
            rendered["error"]["details"]["reconcile_with"],
            RECONCILE_VERB
        );
        assert!(
            !rendered["error"]["message"]
                .as_str()
                .unwrap()
                .contains(&tx_hash)
        );
    }

    /// Every other failure keeps the surface's own code.
    #[test]
    fn a_failure_that_moved_nothing_is_not_an_unresolved_submission() {
        let error = stellar_agent_defi::adapter::DefiAdapterError::Network {
            reason: "endpoint unreachable".to_owned(),
        };
        assert!(unresolved_from_defi(&error).is_none());
    }

    /// A timeout carries the window it ran out of.
    #[test]
    fn a_defi_timeout_carries_its_timeout_seconds() {
        let error = stellar_agent_defi::adapter::DefiAdapterError::SubmissionUnresolved {
            wire_code: "submission.tx_timeout",
            message: "not confirmed".to_owned(),
            tx_hash: Some("ab".repeat(32)),
            envelope_hash: None,
            timeout_seconds: Some(45),
        };
        let unresolved = unresolved_from_defi(&error).expect("an unresolved submission");
        let envelope = unresolved.envelope();
        let details = envelope.error.as_ref().unwrap().details.as_ref().unwrap();
        assert_eq!(details["timeout_seconds"], 45);
    }

    /// A per-period cap the reservation write refused reports the criterion's
    /// own code and reads as this binary's gate denials read.
    #[test]
    fn a_refused_reservation_reports_the_gate_code_and_wording() {
        let err = WalletError::PolicyDenied {
            reason: Box::new(
                stellar_agent_core::policy::DenyReason::PerPeriodCapExceeded {
                    asset: "native".to_owned(),
                    window: "1d".to_owned(),
                    max_stroops: 1_000,
                    attempted_stroops: 600,
                    period_used_stroops: 600,
                },
            ),
        };
        let envelope = error_envelope(&err, SIGNED_XDR, "pay");
        let rendered = envelope.error.as_ref().unwrap();
        assert_eq!(rendered.code, "policy.deny.per_period_cap_exceeded");
        assert_eq!(rendered.message, "pay operation denied by operator policy");
        assert!(
            rendered.details.is_none(),
            "nothing was sent, so there is no transaction to reconcile"
        );
    }

    /// Clock refusals identify the host-clock offset on the CLI response.
    #[test]
    fn a_clock_refusal_reports_the_host_clock_offset() {
        let detail = stellar_agent_core::policy::v1::criteria::state_store::StateStoreError::ClockSkewExceeded {
            entry_ts_ms: 1_031_000, now_ms: 1_000_000,
        }.to_string();
        let err = WalletError::PolicyDenied {
            reason: Box::new(stellar_agent_core::policy::DenyReason::EvaluationError { detail }),
        };
        let envelope = error_envelope(&err, SIGNED_XDR, "pay");
        let error = envelope.error.as_ref().unwrap();
        assert_eq!(error.code, "policy.deny.evaluation_error");
        assert!(error.message.contains("host clock is 31000 ms behind"));
    }

    #[test]
    fn a_refused_rate_limited_reservation_reports_the_gate_code() {
        let err = WalletError::PolicyDenied {
            reason: Box::new(stellar_agent_core::policy::DenyReason::RateLimitExceeded {
                window: "1m".to_owned(),
                max_calls: 1,
                calls_in_window: 1,
            }),
        };
        let envelope = error_envelope(&err, SIGNED_XDR, "claim");
        let rendered = envelope.error.as_ref().unwrap();
        assert_eq!(rendered.code, "policy.deny.rate_limit_exceeded");
        assert_eq!(
            rendered.message,
            "claim operation denied by operator policy"
        );
    }

    /// A verb whose other submission failures carry their own code keeps the
    /// denial rather than flattening it into that fallback.
    #[test]
    fn a_verb_with_a_fallback_code_keeps_the_denial() {
        let err = WalletError::PolicyDenied {
            reason: Box::new(
                stellar_agent_core::policy::DenyReason::PerPeriodCapExceeded {
                    asset: "native".to_owned(),
                    window: "1d".to_owned(),
                    max_stroops: 1_000,
                    attempted_stroops: 600,
                    period_used_stroops: 600,
                },
            ),
        };
        let envelope =
            error_envelope_with_fallback(&err, SIGNED_XDR, "trustline", "trustline.submit_failed");
        let rendered = envelope.error.as_ref().unwrap();
        assert_eq!(
            rendered.code, "policy.deny.per_period_cap_exceeded",
            "a refused cap must not read as a submission failure"
        );
        assert_eq!(
            rendered.message,
            "trustline operation denied by operator policy"
        );
    }

    /// A DeFi verb reports the denial rather than its own submit-failure code.
    #[test]
    fn a_defi_verb_keeps_the_denial_rather_than_its_submit_failure_code() {
        let error = stellar_agent_defi::adapter::DefiAdapterError::PolicyDenied {
            reason: Box::new(
                stellar_agent_core::policy::DenyReason::PerPeriodCapExceeded {
                    asset: "native".to_owned(),
                    window: "1d".to_owned(),
                    max_stroops: 1_000,
                    attempted_stroops: 600,
                    period_used_stroops: 600,
                },
            ),
        };
        let envelope = defi_submit_error_envelope(&error, "trade", "dex.submit_failed");
        let rendered = envelope.error.as_ref().unwrap();
        assert_eq!(
            rendered.code, "policy.deny.per_period_cap_exceeded",
            "a refused cap must not read as a submit failure"
        );
        assert_eq!(
            rendered.message,
            "trade operation denied by operator policy"
        );
        assert!(rendered.details.is_none());
    }

    /// A DeFi mainnet refusal reports the canonical code, not the verb's
    /// submit-failure code.
    #[test]
    fn a_defi_mainnet_refusal_reports_the_canonical_code() {
        let error = stellar_agent_defi::adapter::DefiAdapterError::MainnetWriteForbidden;
        for (verb, fallback) in [
            ("trade", "dex.submit_failed"),
            ("vault deposit", "vault.submit_failed"),
        ] {
            let envelope = defi_submit_error_envelope(&error, verb, fallback);
            let rendered = envelope.error.as_ref().unwrap();
            assert_eq!(
                rendered.code, "network.mainnet_write_forbidden",
                "verb {verb}"
            );
            assert!(rendered.details.is_none());
        }
    }

    /// A DeFi signing refusal reports its own code on every verb, with no
    /// transaction to reconcile.
    #[test]
    fn a_defi_signing_refusal_reports_its_own_code_without_a_transaction() {
        for code in [
            "smart_account.ledger_witness_unavailable",
            "simulation.divergence.ledger_skew",
            "submission.intent_record_unavailable",
            "submission.intent_binding_mismatch",
        ] {
            let error = stellar_agent_defi::adapter::DefiAdapterError::SigningRefusal {
                wire_code: code,
                message: "fixed".to_owned(),
            };
            for (verb, fallback) in [
                ("trade", "dex.submit_failed"),
                ("vault deposit", "vault.submit_failed"),
            ] {
                let envelope = defi_submit_error_envelope(&error, verb, fallback);
                let rendered = envelope.error.as_ref().unwrap();
                assert_eq!(rendered.code, code, "verb {verb}");
                assert_eq!(rendered.message, "fixed", "verb {verb}");
                assert!(
                    rendered.details.is_none(),
                    "a refusal before signing names no transaction"
                );
            }
        }
    }

    /// Every other DeFi failure still reports under the verb's own code.
    #[test]
    fn a_defi_network_failure_still_reports_the_fallback_code() {
        let error = stellar_agent_defi::adapter::DefiAdapterError::Network {
            reason: "endpoint unreachable".to_owned(),
        };
        let envelope = defi_submit_error_envelope(&error, "trade", "dex.submit_failed");
        assert_eq!(envelope.error.as_ref().unwrap().code, "dex.submit_failed");
    }

    /// A store this binary cannot write still reports a record it could not
    /// make, under the code that names exactly that.
    #[test]
    fn a_record_that_cannot_be_written_is_still_record_unavailable() {
        let err = record_unavailable("the spending-window reservation could not be written");
        let envelope = error_envelope(&err, SIGNED_XDR, "pay");
        let rendered = envelope.error.as_ref().unwrap();
        assert_eq!(rendered.code, "submission.record_unavailable");
        assert!(rendered.details.is_none());
    }

    /// A submission that was never sent carries no `details`.
    ///
    /// There is no transaction to reconcile, and `outcome: "unknown"` would
    /// say the opposite of what happened.
    #[test]
    fn a_pre_send_refusal_carries_no_details() {
        let error = stellar_agent_defi::adapter::DefiAdapterError::SubmissionUnresolved {
            wire_code: "submission.record_unavailable",
            message: "the receipt store could not be written".to_owned(),
            tx_hash: None,
            envelope_hash: None,
            timeout_seconds: None,
        };
        let unresolved = unresolved_from_defi(&error).expect("an unresolved submission");
        let envelope = unresolved.envelope();
        let rendered = envelope.error.as_ref().unwrap();
        assert_eq!(rendered.code, "submission.record_unavailable");
        assert!(
            rendered.details.is_none(),
            "a pre-send refusal carries no details; got {:?}",
            rendered.details
        );
    }
    /// A profile under `dir` whose window key and audit chain key live in the
    /// keyring mock, with its window and receipt stores.
    struct DrainFixture {
        _dir: tempfile::TempDir,
        profile: Profile,
        name: String,
        window: PersistedWindowStore,
        receipts: ReceiptStore,
    }

    fn drain_fixture(name: &str) -> DrainFixture {
        use base64::Engine as _;
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut profile = Profile::builder_testnet(name, "acct", "nonce", name).build();
        profile.audit_log_path = dir.path().join("audit").join("log.jsonl");
        profile.policy_window_state_key_id =
            stellar_agent_core::profile::schema::KeyringEntryRef::default_policy_window_state_key(
                name,
            );
        let coordinate = &profile.audit_log_hash_chain_key_id;
        keyring_core::Entry::new(&coordinate.service, &coordinate.account)
            .unwrap()
            .set_password(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x53; 32]))
            .unwrap();
        let window = PersistedWindowStore::at_path(dir.path().join(format!("{name}.window")));
        let receipts = ReceiptStore::open_at(dir.path(), name).unwrap();
        DrainFixture {
            _dir: dir,
            profile,
            name: name.to_owned(),
            window,
            receipts,
        }
    }

    impl DrainFixture {
        fn writer(&self) -> Arc<Mutex<AuditWriter>> {
            accounting_audit_writer(&self.profile, &self.name, ProfileOrigin::Persisted).unwrap()
        }

        fn drain(&self) -> Result<DeliveryReport, WalletError> {
            stellar_agent_network::policy_state::drain_accounting_obligations(
                &self.window,
                &self.profile,
                &self.name,
                Some(&self.receipts),
                || accounting_audit_writer(&self.profile, &self.name, ProfileOrigin::Persisted),
            )
        }

        /// A sent submission `id` whose receipt reads `status`.
        fn receipt(&self, id: &str, status: Option<ReceiptStatus>) {
            self.receipts
                .try_begin(id, id, "GSOURCE", 7, 0, 1_000)
                .unwrap();
            self.receipts.mark_submitted(id).unwrap();
            match status {
                None | Some(ReceiptStatus::Pending) => {}
                Some(ReceiptStatus::Ambiguous) => self
                    .receipts
                    .finalize_released(id, ReleaseEvidence::TimeBoundPassed)
                    .unwrap(),
                Some(ReceiptStatus::ClearedByOperator) => {
                    self.receipts
                        .finalize_released(id, ReleaseEvidence::SequenceConsumed)
                        .unwrap();
                    self.receipts.clear_by_operator(id).unwrap();
                }
                Some(ReceiptStatus::Reorged) => {
                    self.receipts
                        .finalize(id, ReceiptStatus::Success, Some(5))
                        .unwrap();
                    self.receipts.finalize_reorged(id).unwrap();
                }
                Some(other) => self.receipts.finalize(id, other, Some(5)).unwrap(),
            }
        }

        /// Commits the accounting expiry of a bounded hold whose horizon has
        /// passed, through an ordinary reconciliation pass, and returns its
        /// decision identifier.
        async fn committed_expiry(&self, id: &str) -> String {
            let now = self.expired_hold(id);
            let client = StellarRpcClient::new("http://127.0.0.1:9").unwrap();
            let report = self
                .window
                .reconcile_due(&self.profile, &client, None, None, now, 4)
                .await
                .unwrap();
            assert_eq!(report.rpc_calls, 0, "local expiry asks no endpoint");
            let [settled] = report.settled.as_slice() else {
                panic!("one committed expiry: {report:?}");
            };
            settled.decision_id.clone()
        }

        /// Takes a bounded hold `id` whose accounting horizon has passed, so
        /// the next pass commits its expiry without asking an endpoint.
        /// Returns the time the hold was taken at.
        fn expired_hold(&self, id: &str) -> u64 {
            use stellar_agent_core::policy::v1::criteria::state_store::{
                StateKey, WindowEntry, WindowLimit,
            };
            let now = stellar_agent_core::timefmt::now_unix_ms().unwrap();
            let since = now - stellar_agent_network::policy_state::RECONCILE_MIN_AGE_MS;
            let hold = stellar_agent_network::policy_state::SubmissionHold {
                chain_scope: stellar_agent_network::policy_state::ChainScope::for_chain(
                    self.profile.chain_id,
                ),
                id: id.to_owned(),
                tx_hash: id.to_owned(),
                source: "GSOURCE".to_owned(),
                sequence: 7,
                max_time: now / 1_000 - 61,
                pending_since_ms: since,
                submission_ledger: 1_000,
                submission_anchor: None,
                operator_required: false,
            };
            let entry = WindowEntry::new(
                StateKey::new(&self.name, 1, "native", 60),
                since,
                300,
                WindowLimit::Amount {
                    asset: "native".to_owned(),
                    window: "1m".to_owned(),
                    max_stroops: 1_000_000,
                },
            );
            self.window
                .record_pending(&self.profile, &[entry], &hold)
                .unwrap();
            now
        }

        fn rows(&self) -> Vec<serde_json::Value> {
            std::fs::read_to_string(&self.profile.audit_log_path)
                .unwrap_or_default()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect()
        }
    }

    /// Success and failure receipts leave exactly the original pending row,
    /// with its tool, policy decision and approval nonce unchanged.
    #[test]
    #[serial_test::serial]
    fn settlement_rows_preserve_pending_approval_context() {
        use stellar_agent_core::audit_log::{AuditEntry, PolicyDecision};
        for approved in [false, true] {
            for failed in [false, true] {
                let f = drain_fixture(&format!("approval-context-{approved}-{failed}"));
                let envelope = "e1".repeat(32);
                let decision = if approved {
                    PolicyDecision::RequireApproval
                } else {
                    PolicyDecision::Allow
                };
                let nonce = approved.then(|| "approval-binding".to_owned());
                f.writer()
                    .lock()
                    .unwrap()
                    .write_entry(AuditEntry::new_value_action_pending(
                        "stellar_pay_commit",
                        "stellar:testnet",
                        Vec::new(),
                        &envelope,
                        "source",
                        7,
                        decision.clone(),
                        Some(envelope.clone()),
                        None,
                        nonce.clone(),
                        "pending-request",
                        None,
                    ))
                    .unwrap();
                f.receipt(
                    &envelope,
                    Some(if failed {
                        ReceiptStatus::Failed {
                            code: "ledger.failed".to_owned(),
                        }
                    } else {
                        ReceiptStatus::Success
                    }),
                );
                f.drain().unwrap();
                let rows: Vec<_> = f
                    .rows()
                    .into_iter()
                    .filter(|row| row["envelope_hash"] == envelope.as_str())
                    .collect();
                assert_eq!(rows.len(), 1, "{rows:?}");
                assert_eq!(rows[0]["kind"], "value_action_pending");
                assert_eq!(
                    rows[0]["policy_decision"],
                    serde_json::to_value(decision).unwrap()
                );
                assert_eq!(
                    rows[0]["approval_nonce"],
                    serde_json::to_value(nonce).unwrap()
                );
                assert_eq!(rows[0]["tool"], "stellar_pay_commit");
            }
        }
    }

    /// No receipt status selects an audit row: every receipt-only case,
    /// `Failed` included, leaves the log untouched. Delivery of an identifier
    /// the verified window state does not hold refuses before any append.
    #[test]
    #[serial_test::serial]
    fn no_receipt_status_selects_an_audit_row() {
        for (label, status) in [
            ("success", Some(ReceiptStatus::Success)),
            (
                "failed",
                Some(ReceiptStatus::Failed {
                    code: "ledger.failed".to_owned(),
                }),
            ),
            ("ambiguous", Some(ReceiptStatus::Ambiguous)),
            ("pending", None),
            ("reorged", Some(ReceiptStatus::Reorged)),
            ("cleared", Some(ReceiptStatus::ClearedByOperator)),
        ] {
            let f = drain_fixture(&format!("row-kind-{label}"));
            f.receipt(&"ab".repeat(32), status);
            assert_eq!(f.drain().unwrap(), DeliveryReport::default(), "{label}");
            assert!(f.rows().is_empty(), "{label}: {:?}", f.rows());
        }

        let f = drain_fixture("row-kind-unverifiable");
        let writer = f.writer();
        let before = std::fs::read(&f.profile.audit_log_path).ok();
        let error = stellar_agent_network::policy_state::deliver_accounting_expiry(
            &mut writer.lock().unwrap(),
            &f.window,
            &f.profile,
            &f.name,
            Some(&f.receipts),
            &"cd".repeat(32),
        )
        .unwrap_err();
        assert_eq!(error.code(), "submission.settlement_unverifiable");
        assert_eq!(std::fs::read(&f.profile.audit_log_path).ok(), before);
    }

    /// An authentic owed expiry over a retained history with a broken
    /// archive link: the drain leaves the audit bytes unchanged, keeps the
    /// obligation, and logs the integrity refusal at WARN with the profile
    /// and its code.
    #[tokio::test]
    #[serial_test::serial]
    async fn an_unreadable_history_leaves_the_expiry_owed() {
        use stellar_agent_core::audit_log::rotation::test_seam::set_rotation_threshold;
        use stellar_agent_core::audit_log::test_helpers::break_newest_archive_link;
        use stellar_agent_core::audit_log::{AuditEntry, NewToolInvocation, PolicyDecision};

        let f = drain_fixture("unreadable-history");
        let decision_id = f.committed_expiry(&"c1".repeat(32)).await;
        let unrelated = |request_id: &str| {
            AuditEntry::new_tool_invocation(NewToolInvocation::new(
                "stellar_balance",
                "stellar:testnet",
                Vec::new(),
                PolicyDecision::Allow,
                request_id,
            ))
        };
        {
            let writer = f.writer();
            let mut guard = writer.lock().unwrap();
            guard.write_entry(unrelated("archived")).unwrap();
            let size = std::fs::metadata(&f.profile.audit_log_path).unwrap().len();
            let threshold = set_rotation_threshold(&f.profile.audit_log_path, size);
            guard.write_entry(unrelated("active")).unwrap();
            drop(threshold);
        }
        break_newest_archive_link(&f.profile.audit_log_path);
        let active = std::fs::read(&f.profile.audit_log_path).unwrap();
        let mut refused = None;
        let logs = stellar_agent_test_support::with_captured_logs(|| {
            refused = Some(f.drain());
        });
        let code = refused.unwrap().map(|_| ()).unwrap_err().code().to_owned();
        assert_eq!(
            std::fs::read(&f.profile.audit_log_path).unwrap(),
            active,
            "no expiry event is written"
        );
        assert_eq!(
            f.window
                .owed_accounting_expiries(&f.profile)
                .unwrap()
                .unacknowledged,
            vec![decision_id],
            "the obligation stays owed"
        );
        let line = logs
            .lines()
            .find(|line| line.contains("accounting delivery refused"));
        assert!(
            line.is_some_and(|line| line.contains("WARN")
                && line.contains("unreadable-history")
                && line.contains(code.as_str())
                && line.contains("audit.")),
            "the refusal is logged with the profile and its code: {logs}"
        );
    }

    /// Receipt-only reconciliation leaves the pending row, with its witness,
    /// as the one row of the submission.
    #[test]
    #[serial_test::serial]
    fn pending_witness_survives_cli_reconciliation() {
        use stellar_agent_core::audit_log::{AuditEntry, PolicyDecision};
        for (label, status) in [
            ("success", ReceiptStatus::Success),
            (
                "failed",
                ReceiptStatus::Failed {
                    code: "ledger.failed".to_owned(),
                },
            ),
        ] {
            let f = drain_fixture(&format!("witness-{label}"));
            let envelope = "ef".repeat(32);
            let witness = stellar_agent_core::audit_log::CrossCheckRecord {
                provider: "https://oracle.example".to_owned(),
                ledger: 123,
                inputs_digest: "09".repeat(32),
                kinds: vec![stellar_agent_core::cross_check::WitnessEntry::SourceAccount],
            };
            f.writer()
                .lock()
                .unwrap()
                .write_entry(AuditEntry::new_value_action_pending(
                    "stellar_pay_commit",
                    "stellar:testnet",
                    vec![],
                    &envelope,
                    "source",
                    7,
                    PolicyDecision::Allow,
                    Some(envelope.clone()),
                    None,
                    None,
                    "pending-request",
                    Some(witness.clone()),
                ))
                .unwrap();
            f.receipt(&envelope, Some(status));
            f.drain().unwrap();
            let rows: Vec<_> = f
                .rows()
                .into_iter()
                .filter(|row| row["envelope_hash"] == envelope.as_str())
                .collect();
            assert_eq!(rows.len(), 1, "{label}: {rows:?}");
            assert_eq!(rows[0]["kind"], "value_action_pending");
            assert_eq!(rows[0]["witness"], serde_json::to_value(&witness).unwrap());
        }
    }

    /// The gate drain delivers an obligation an earlier pass left even when
    /// its own pass refuses. With the window lock held, the pass cannot commit
    /// the due expiry, and the old event is still appended. Once the lock is
    /// released, the next pass acknowledges it without a second row.
    #[tokio::test]
    #[serial_test::serial]
    async fn the_gate_drain_delivers_an_old_obligation_after_a_refused_pass() {
        let home = tempfile::tempdir().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
        let mut f = drain_fixture("gate-refused-drain");
        f.window = PersistedWindowStore::for_profile(&f.name);
        f.receipts = ReceiptStore::open(&f.name).unwrap();
        let old = f.committed_expiry(&"c1".repeat(32)).await;
        f.expired_hold(&"c2".repeat(32));
        let expiry_rows = |decision_id: &str| {
            f.rows()
                .iter()
                .filter(|row| {
                    row["kind"] == "submission_accounting_expired"
                        && row["decision_id"] == decision_id
                })
                .count()
        };
        let client = StellarRpcClient::new("http://127.0.0.1:9").unwrap();
        let pass = || async {
            reconcile_open_reservations(
                &f.profile,
                &f.name,
                ProfileOrigin::Persisted,
                &client,
                None,
                stellar_agent_core::timefmt::now_unix_ms().unwrap(),
            )
            .await;
        };

        let lock = stellar_agent_core::policy::state_lock::WindowStoreLock::acquire_for(
            f.window.path(),
            &f.profile.policy_window_state_key_id,
        )
        .unwrap();
        pass().await;
        assert_eq!(
            f.window.pending_reservations(&f.profile).unwrap().len(),
            1,
            "the refused pass commits nothing"
        );
        assert_eq!(
            expiry_rows(&old),
            1,
            "the old event is appended after the refused pass"
        );
        assert_eq!(
            f.window
                .owed_accounting_expiries(&f.profile)
                .unwrap()
                .unacknowledged,
            vec![old.clone()],
            "the held lock refuses the acknowledgement"
        );
        drop(lock);

        pass().await;
        assert_eq!(expiry_rows(&old), 1, "no second row");
        assert!(
            f.window
                .pending_reservations(&f.profile)
                .unwrap()
                .is_empty()
        );
        assert!(
            f.window
                .owed_accounting_expiries(&f.profile)
                .unwrap()
                .unacknowledged
                .is_empty()
        );
        assert_eq!(
            f.rows()
                .iter()
                .filter(|row| row["kind"] == "submission_accounting_expired")
                .count(),
            2,
            "each decision has one row"
        );
    }
}

#[cfg(test)]
pub(crate) mod intent_gate_fixture {
    #![allow(clippy::unwrap_used, clippy::panic, reason = "test fixture assertions")]
    use super::*;
    use stellar_agent_core::policy::v1::criteria::state_store::StateKey;
    use stellar_agent_core::profile::schema::PolicyEngineKind;
    use stellar_xdr::{OperationBody, TransactionEnvelope};
    use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

    pub(crate) struct IntentGateState {
        name: String,
        store: PersistedWindowStore,
        endpoint: MockServer,
        clock: stellar_agent_network::mainnet::clock::TestClockGuard,
        query_clock: stellar_agent_core::policy::v1::criteria::state_store::QueryTimeGuard,
        key: StateKey,
    }

    impl IntentGateState {
        pub(crate) async fn seed(name: &str, profile: &mut Profile) -> Self {
            let clock = stellar_agent_network::mainnet::clock::set_now_ms_for_test(1000);
            let query_clock =
                stellar_agent_core::policy::v1::criteria::state_store::set_query_time_for_test(
                    1000,
                );
            let endpoint = MockServer::start().await;
            Mock::given(method("POST")).respond_with(|request: &wiremock::Request| {
                let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
                let result = match body["method"].as_str().unwrap() {
                    "getNetwork" => stellar_agent_test_support::signed_envelope::get_network_result(stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE),
                    "getLatestLedger" => serde_json::json!({"id": "ab".repeat(32), "sequence": 101, "protocolVersion": 27}),
                    method => panic!("unexpected observation request {method}"),
                };
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"jsonrpc":"2.0", "id":body["id"], "result":result}))
            }).mount(&endpoint).await;
            let profiles = stellar_agent_core::profile::loader::default_profile_dir().unwrap();
            std::fs::create_dir_all(&profiles).unwrap();
            std::fs::write(profiles.join(format!("{name}.toml")), format!(
                "version = 2\nchain_id = \"stellar:testnet\"\nrpc_url = {:?}\nsecondary_rpc_url = {:?}\n",
                endpoint.uri(), stellar_agent_test_support::second_loopback_host(&endpoint.uri()),
            )).unwrap();
            profile.policy.engine = PolicyEngineKind::V1;
            let owner = ed25519_dalek::SigningKey::from_bytes(&[0x57; 32]);
            let owner_key = owner.verifying_key().to_bytes();
            let key = &profile.policy_owner_key_id;
            keyring_core::Entry::new(&key.service, &key.account)
                .unwrap()
                .set_password(
                    &stellar_agent_core::profile::owner_key::encode_owner_public_key(&owner_key),
                )
                .unwrap();
            let policy = format!(
                "version = 1\nscope = \"profile:{name}\"\n[[rules]]\nmatch = {{ tool = \"*\", chain = \"*\" }}\ncriteria = [{{ kind = \"rate_limit\", window = \"1w\", max_calls = 1 }}]\ndecision = \"allow\"\n"
            );
            let canonical =
                stellar_agent_core::policy::v1::canonical::canonical_bytes(&policy).unwrap();
            let digest = stellar_agent_core::policy::v1::signature::digest(&canonical);
            let signature = stellar_agent_core::policy::v1::signature::sign(&digest, &owner);
            let owner_g = stellar_strkey::ed25519::PublicKey(owner_key).to_string();
            let signed = format!(
                "{policy}\n[signature]\nowner_id = {:?}\nsig = {:?}\n",
                owner_g.as_str(),
                hex::encode(signature)
            );
            let policies = stellar_agent_core::profile::schema::default_policy_dir().unwrap();
            std::fs::create_dir_all(&policies).unwrap();
            std::fs::write(policies.join(format!("{name}.toml")), signed).unwrap();
            let engine = crate::commands::policy_engine::build_v1_policy_engine(
                "fixture",
                &profile.policy.engine,
                profile,
                name,
            )
            .unwrap();
            let descriptor = ToolDescriptor::from_registration(&McpToolRegistration {
                name: "fixture",
                destructive_hint: true,
                read_only_hint: false,
                chain_id_required: true,
                value_kind: ToolValueKind::ReadOnly,
            });
            let sizing = engine.size_no_value(&descriptor, profile, 1000).unwrap();
            assert_eq!(sizing.entries().len(), 1);
            let key = sizing.entries()[0].key().clone();
            let (fixture, envelope) =
                stellar_agent_network::signed_intent::test_helpers::intent_fixture_plan(1, 1);
            let TransactionEnvelope::Tx(tx) = envelope else {
                panic!("transaction")
            };
            let OperationBody::InvokeHostFunction(op) = &tx.tx.operations[0].body else {
                panic!("invoke")
            };
            let plan = fixture
                .classify_purpose(&op.host_function, None)
                .unwrap()
                .with_envelope_max_ledger(100)
                .unwrap();
            let plan = stellar_agent_network::signed_intent::test_helpers::with_legs(
                &plan,
                sizing.entries(),
            );
            let store = PersistedWindowStore::for_profile(name);
            let _exposure = store.admit_signed_intent(profile, &plan).unwrap().expose();
            clock.set(2000);
            query_clock.set(2000);
            Self {
                name: name.into(),
                store,
                endpoint,
                clock,
                query_clock,
                key,
            }
        }

        pub(crate) async fn assert_closed(&self, profile: &Profile, count: u32) {
            let views = self.store.signed_intents(&self.name, profile).unwrap();
            assert_eq!(views.len(), 1);
            assert_eq!(views[0].expiry_observed_at_ms, Some(2000));
            assert_eq!(views[0].accounting_horizon, "604802000");
            let engine = crate::commands::policy_engine::build_v1_policy_engine(
                "fixture",
                &profile.policy.engine,
                profile,
                &self.name,
            )
            .unwrap();
            assert_eq!(
                engine
                    .window_state_store()
                    .unwrap()
                    .query_window(&self.key, if count == 0 { 604802001 } else { 2000 })
                    .unwrap(),
                (i128::from(count), count)
            );
            assert_eq!(self.endpoint.received_requests().await.unwrap().len(), 4);
        }

        pub(crate) fn after_retention(&self) {
            self.clock.set(604802001);
            self.query_clock.set(604802001);
        }

        pub(crate) fn bytes(&self) -> Vec<u8> {
            std::fs::read(self.store.path()).unwrap()
        }
    }

    #[tokio::test(flavor = "current_thread")]
    #[serial_test::serial]
    async fn early_observation_precedes_window_gate() {
        let (_home, _guard) = home();
        let name = "intent-refresh";
        let mut profile =
            Profile::builder_testnet_named(name, "signer", "account", "nonce", name).build();
        let state = IntentGateState::seed(name, &mut profile).await;
        let engine = crate::commands::policy_engine::build_v1_policy_engine(
            "fixture",
            &profile.policy.engine,
            &profile,
            name,
        )
        .unwrap();
        let memory = engine.window_state_store().unwrap();
        assert_eq!(memory.query_window(&state.key, 2000).unwrap(), (1, 1));
        for after in [false, false, true] {
            if after {
                state.after_retention();
            }
            observe_and_refresh_intents(&profile, name, engine.as_ref())
                .await
                .unwrap();
            let now = if after { 604802001 } else { 2000 };
            let expected = if after { (0, 0) } else { (1, 1) };
            assert_eq!(memory.query_window(&state.key, now).unwrap(), expected);
            state.assert_closed(&profile, u32::from(!after)).await;
        }
    }

    pub(crate) fn home() -> (
        tempfile::TempDir,
        stellar_agent_test_support::StellarAgentHomeGuard,
    ) {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let scratch = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/tmp");
        std::fs::create_dir_all(&scratch).unwrap();
        let home = tempfile::Builder::new()
            .prefix("intent-gate-")
            .tempdir_in(scratch)
            .unwrap();
        let guard = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
        (home, guard)
    }
}
