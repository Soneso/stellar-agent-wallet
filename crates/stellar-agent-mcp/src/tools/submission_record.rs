//! Building the durable-submission recorder, and reporting what it refused.
//!
//! Every value-moving tool in this server records its submission before the
//! transaction is sent. The construction is identical across them — the same
//! stores, the same audit writer, the same policy-sized window entries — so it
//! lives here once, and so does the mapping that turns the three submission
//! refusals into a response an agent can act on.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use rmcp::model::{CallToolResult, Content};
use stellar_agent_core::audit_log::schema::ValueLegRecord;
use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::{SubmissionError, WalletError};
use stellar_agent_core::policy::v1::ValueClass;
use stellar_agent_core::policy::{PolicyEngine, ToolDescriptor};
use stellar_agent_core::profile::receipt::ReceiptStore;
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_network::policy_state::PersistedWindowStore;
use stellar_agent_network::submission_flow::{
    self, RecorderInputs, StageMarkedRecorder, assemble_recorder, checked_sizing, open_receipts,
};
use stellar_agent_network::{ApprovalTombstone, SequenceFloorHook, WalletSubmissionRecorder};

use super::common::profile_bound_descriptor;

/// The tool this server names as the way to reconcile a submission whose
/// outcome is not known.
pub(crate) const RECONCILE_TOOL: &str = "stellar_transaction_status";

/// Everything a commit path knows about the submission it is about to make.
///
/// Built at the call site and turned into a recorder by
/// [`build_recorder`]; the split keeps the argument list at the call site
/// readable and names every value the recorder carries.
pub(crate) struct CommitRecord<'a> {
    /// The profile the submission is made under.
    pub profile: &'a Profile,
    /// The profile name, which names the receipt, window and approval files.
    pub profile_name: String,
    /// The registered tool name, as it appears in the audit log.
    pub tool: &'static str,
    /// The policy decision that admitted this submission.
    pub policy_decision: stellar_agent_core::audit_log::PolicyDecision,
    /// CAIP-2 chain identifier for the audit rows.
    pub chain_id: String,
    /// The value legs the policy gate sized, in their audit-row form.
    pub legs: Vec<ValueLegRecord>,
    /// The policy engine that sized the action.
    pub engine: &'a dyn PolicyEngine,
    /// The tool registry used to bind the accounting descriptor to the profile.
    /// A missing entry refuses with `submission.record_unavailable`.
    pub registry: &'a HashMap<&'static str, ToolDescriptor>,
    /// The SAME value class the gate evaluated.
    pub value_class: ValueClass,
    /// The audit writer acquired by the value-audit pre-flight.
    pub audit: Arc<Mutex<AuditWriter>>,
    /// The commit nonce prefix recorded on the audit rows.
    pub nonce_id: Option<String>,
    /// The approval nonce this commit spends, when it presented one.
    pub approval_nonce: Option<String>,
    /// The directory holding the profile's pending-approval store, as this
    /// server resolves it.
    pub approval_dir: Option<std::path::PathBuf>,
    /// The caller's clock in unix milliseconds.
    pub now_ms: u64,
    /// The provenance of the governing mainnet decision, which the pending
    /// audit row records; `None` off mainnet.
    pub provenance: Option<stellar_agent_core::mainnet::decision::MainnetProvenance>,
}

/// Builds the recorder for one submission.
///
/// The window entries come from the policy engine's own accounting for this
/// action: the SAME derivation the gate evaluated and the audit rows carry.
/// They are taken here, before the send, because the reservation they become
/// has to be in place by the time the bytes leave.
///
/// # Errors
///
/// Returns `submission.record_unavailable` when the receipt store cannot be
/// opened, the tool has no registry entry, or the policy engine cannot account
/// for the action. A send the wallet cannot record is one it cannot reconcile,
/// cap, or audit afterwards.
pub(crate) fn build_recorder<'a>(
    record: CommitRecord<'a>,
    sequence_floor: Option<&'a dyn SequenceFloorHook>,
) -> Result<WalletSubmissionRecorder<'a>, WalletError> {
    let approval = approval_binding(&record)?;

    let descriptor = profile_bound_descriptor(record.registry, record.profile, record.tool)
        .ok_or_else(|| {
            WalletError::Submission(SubmissionError::RecordUnavailable {
                detail: format!("the submission tool {} has no registry entry", record.tool),
            })
        })?;

    let receipts = open_receipts(&record.profile_name)?;

    let sizing = record
        .engine
        .record_confirmed_checked(&descriptor, record.profile, &record.value_class)
        .map_err(|e| {
            WalletError::Submission(SubmissionError::RecordUnavailable {
                detail: format!("the policy engine could not account for this action: {e}"),
            })
        })?;

    let sizing = checked_sizing(sizing, || {
        WalletError::Submission(SubmissionError::IntentRecordUnavailable {
            class: "policy_unavailable",
        })
    })?;
    Ok(assemble_recorder(
        RecorderInputs {
            profile: record.profile,
            profile_name: record.profile_name,
            tool: record.tool,
            chain_id: record.chain_id,
            policy_decision: record.policy_decision,
            legs: record.legs,
            audit: Some(record.audit),
            nonce_id: record.nonce_id,
            now_ms: record.now_ms,
            provenance: None,
            operation: None,
            pre_exposure_ledger: None,
            observation: None,
        },
        receipts,
        Some(sizing),
    )
    .with_sequence_floor(sequence_floor)
    .with_approval(approval))
}

/// Builds checked count admission with the server's governing policy.
pub(crate) fn no_value_admission(
    server: &crate::server::WalletServer,
    tool: &'static str,
    now_ms: u64,
) -> Result<Arc<stellar_agent_network::NoValueAdmission>, WalletError> {
    let unavailable = || {
        WalletError::Submission(SubmissionError::IntentRecordUnavailable {
            class: "policy_unavailable",
        })
    };
    let descriptor = profile_bound_descriptor(&server.tool_registry, &server.profile, tool)
        .ok_or_else(unavailable)?;
    let sizing = server
        .policy_engine
        .size_no_value(&descriptor, &server.profile, now_ms)
        .map_err(|_| unavailable())?;
    stellar_agent_network::NoValueAdmission::with_store(
        server.profile.as_ref().clone(),
        server.window_store.clone(),
        sizing,
    )
    .map(Arc::new)
}

fn approval_binding(record: &CommitRecord<'_>) -> Result<Option<ApprovalTombstone>, WalletError> {
    // Only a gate that required approval verified the presented nonce, so only
    // that decision binds, spends and records it.
    let approval = match record.policy_decision {
        stellar_agent_core::audit_log::PolicyDecision::RequireApproval => {
            match (record.approval_nonce.clone(), record.approval_dir.clone()) {
                (Some(approval_nonce), Some(store_dir)) => Some(ApprovalTombstone {
                    store_dir,
                    profile_name: record.profile_name.clone(),
                    approval_nonce,
                }),
                (None, _) => {
                    return Err(WalletError::Submission(
                        SubmissionError::RecordUnavailable {
                            detail: "the approved submission presented no approval nonce"
                                .to_owned(),
                        },
                    ));
                }
                (Some(_), None) => {
                    return Err(WalletError::Submission(
                        SubmissionError::RecordUnavailable {
                            detail: "the approved submission has no approval store".to_owned(),
                        },
                    ));
                }
            }
        }
        _ => None,
    };

    Ok(approval)
}

/// Fallible local inputs prepared before an authorization is minted.
pub(crate) struct PreparedRecorder<'a> {
    record: CommitRecord<'a>,
    approval: Option<ApprovalTombstone>,
    receipts: ReceiptStore,
    pub window: PersistedWindowStore,
}

/// The tombstone a mainnet submission under `authority` owes: the verified
/// approval nonce under `Approval`, and none under `Policy`.
///
/// # Errors
///
/// `submission.record_unavailable` for an approval without a store.
fn authority_tombstone(
    record: &CommitRecord<'_>,
    authority: &stellar_agent_network::mainnet::authority::MainnetAuthority<'_>,
) -> Result<Option<ApprovalTombstone>, WalletError> {
    use stellar_agent_network::mainnet::authority::MainnetAuthority;
    let MainnetAuthority::Approval(witness) = authority else {
        return Ok(None);
    };
    let Some(store_dir) = record.approval_dir.clone() else {
        return Err(WalletError::Submission(
            SubmissionError::RecordUnavailable {
                detail: "the approved submission has no approval store".to_owned(),
            },
        ));
    };
    Ok(Some(ApprovalTombstone {
        store_dir,
        profile_name: record.profile_name.clone(),
        approval_nonce: witness.nonce().to_owned(),
    }))
}

pub(crate) fn prepare_authorized_recorder<'a>(
    record: CommitRecord<'a>,
    window: PersistedWindowStore,
    authority: &stellar_agent_network::mainnet::authority::MainnetAuthority<'_>,
) -> Result<PreparedRecorder<'a>, WalletError> {
    let approval = authority_tombstone(&record, authority)?;
    profile_bound_descriptor(record.registry, record.profile, record.tool).ok_or_else(|| {
        WalletError::Submission(SubmissionError::RecordUnavailable {
            detail: format!("the submission tool {} has no registry entry", record.tool),
        })
    })?;
    let receipts = open_receipts(&record.profile_name)?;
    window
        .load_into(
            &record.profile_name,
            record.profile,
            &stellar_agent_core::policy::v1::PolicyStateStore::new(),
        )
        .map_err(|error| {
            if let Some(refusal) = error.chain_validation_error() {
                return WalletError::Validation(refusal);
            }
            WalletError::Submission(SubmissionError::RecordUnavailable {
                detail: format!("the submission window store could not be opened: {error}"),
            })
        })?;
    Ok(PreparedRecorder {
        record,
        approval,
        receipts,
        window,
    })
}

impl<'a> PreparedRecorder<'a> {
    fn build(
        self,
        authorization: &stellar_agent_network::mainnet::authorization::MainnetTxSignAuthorization,
        floor: Option<&'a dyn SequenceFloorHook>,
        witness: Option<&'a stellar_agent_network::cross_check::CrossCheckWitness>,
        operation: Option<stellar_agent_network::OperationAttempt>,
        request_id: String,
        observation: stellar_agent_network::policy_state::SubmissionObservation,
    ) -> StageMarkedRecorder<'a> {
        let record = self.record;
        let recorder = WalletSubmissionRecorder::new_authorized(
            record.profile,
            record.profile_name,
            record.tool,
            Some(record.chain_id),
            record.policy_decision,
            record.legs,
            authorization,
            self.receipts,
            self.window,
            Some(record.audit),
            record.nonce_id,
            request_id,
            record.now_ms,
        )
        .with_sequence_floor(floor)
        .with_approval(self.approval)
        .with_witness(witness)
        .with_operation(operation)
        .with_pre_exposure_ledger(observation.pre_exposure_ledger)
        .with_observation(observation.observation);
        // Both authority variants record the governing decision's provenance.
        StageMarkedRecorder::new(match record.provenance {
            Some(provenance) => recorder.with_provenance(provenance),
            None => recorder,
        })
    }
}

pub(crate) fn submit_failure_stage(
    entered: bool,
) -> stellar_agent_network::mainnet::resolve::InvalidationStage {
    use stellar_agent_network::mainnet::resolve::InvalidationStage;
    if entered {
        InvalidationStage::PreSendRefused
    } else {
        InvalidationStage::SubmitGateRefused
    }
}

pub(crate) fn sign_failure_stage(
    error: &WalletError,
) -> stellar_agent_network::mainnet::resolve::InvalidationStage {
    use stellar_agent_network::mainnet::resolve::InvalidationStage;
    if matches!(error, WalletError::Auth(_)) {
        InvalidationStage::SignerUnavailable
    } else {
        InvalidationStage::SignRefused
    }
}

pub(crate) fn cleanup_authorization(
    store: &PersistedWindowStore,
    context: &stellar_agent_network::MainnetWriteContext,
    id: stellar_agent_network::mainnet::AuthorizationId,
    stage: stellar_agent_network::mainnet::resolve::InvalidationStage,
) {
    if let Err(error) =
        stellar_agent_network::mainnet::resolve::invalidate_unconsumed(store, context, id, stage)
    {
        let settled = matches!(
            &error,
            stellar_agent_network::mainnet::MainnetAuthorizationError::Refused(
                stellar_agent_network::mainnet::MainnetPrecondition::NotOpen
            )
        );
        tracing::warn!(
            ?stage,
            settled,
            code = stellar_agent_core::WalletError::from(error).code(),
            "authorization cleanup refused; primary failure retained"
        );
    }
}

/// Signs and submits the approved bytes under the same client and consumer.
///
/// Under a mainnet guard with an operation record, the record's next attempt is
/// committed as `Sending` after the mint and before the signature. Every
/// refusal before any send ends it as `NotSent`.
#[allow(
    clippy::too_many_arguments,
    reason = "one call owns the signing and submission lifecycle"
)]
pub(crate) async fn sign_and_submit_classic(
    server: &crate::server::WalletServer,
    guard: Option<&crate::server::MainnetWriteGuard<'_>>,
    authority: Option<&stellar_agent_network::mainnet::authority::MainnetAuthority<'_>>,
    audit: Option<stellar_agent_network::mainnet::audit_readiness::AuditReadiness>,
    consumer: stellar_agent_network::mainnet::MainnetConsumer,
    client: &stellar_agent_network::StellarRpcClient,
    envelope: &str,
    source: &str,
    record: CommitRecord<'_>,
    witness: Option<&stellar_agent_network::cross_check::CrossCheckWitness>,
    floor: Option<&dyn SequenceFloorHook>,
    operation: Option<&stellar_agent_network::policy_state::OperationHandle>,
) -> Result<stellar_agent_network::submit::SubmissionResult, CallToolResult> {
    use stellar_agent_network::{
        signing::envelope_signing::{attach_signature, attach_signature_authorized},
        submit::{
            MainnetSubmitGrant, SubmissionSignerKind, submit_authorized_transaction_and_wait,
            submit_transaction_and_wait,
        },
    };
    let render = |error: WalletError| submission_error_result(&error, envelope);
    let timeout = super::common::submit_timeout(record.profile);
    if let Some(guard) = guard {
        let authority = authority.ok_or_else(|| {
            super::common::approval_required_indistinguishable(&record.profile_name)
        })?;
        let audit = audit.ok_or_else(|| {
            super::common::business_error_result(
                "audit.chain_key_unavailable",
                "audit readiness missing",
            )
        })?;
        // The oracle confirms a negative answer of the primary endpoint after
        // the send; a client that cannot be built refuses before the signer
        // loads.
        let oracle = guard.context.oracle_client().map_err(render)?;
        let observation = stellar_agent_network::policy_state::submission_observation(
            client,
            oracle.as_ref(),
            None,
            stellar_agent_network::operational::readiness_deadline(),
        )
        .await;
        let signer = server.mainnet_enrolled_signer(guard).map_err(render)?;
        let handle = stellar_agent_network::keyring::lazy_signer_from_keyring(
            signer.seed_entry(),
            &stellar_strkey::ed25519::PublicKey(signer.public_key()).to_string(),
        )
        .map_err(render)?;
        let store = server.window_store.clone();
        let profile = record.profile;
        let writer = Arc::clone(&record.audit);
        let request_id = uuid::Uuid::new_v4().to_string();
        let prepared = prepare_authorized_recorder(record, server.window_store.clone(), authority)
            .map_err(render)?;
        let authorization = stellar_agent_network::mainnet::resolve::resolve_tx_sign(
            stellar_agent_network::mainnet::resolve::TxSignRequest {
                context: guard.context,
                consumer,
                unsigned_envelope_xdr: envelope,
                client,
                probe_deadline: stellar_agent_network::PRE_SEND_BUDGET,
                witness,
                signer: &signer,
                policy: guard.policy,
                enablement: guard.enablement,
                authority,
                audit,
                store: &prepared.window,
                operation: operation.map(stellar_agent_network::operation_entry::next_attempt_link),
            },
        )
        .await
        .map_err(|error| render(error.into()))?;
        let id = authorization.id();
        // The attempt is committed before the signature exists: a crash from
        // here on leaves a `Sending` record that recovery reads.
        let attempt = match operation {
            Some(handle) => match stellar_agent_network::operation_entry::begin_classic_attempt(
                &store,
                profile,
                &writer,
                &request_id,
                handle,
                envelope,
            ) {
                Ok(attempt) => Some(attempt),
                Err(error) => {
                    cleanup_authorization(
                        &store,
                        guard.context,
                        id,
                        stellar_agent_network::mainnet::resolve::InvalidationStage::SignRefused,
                    );
                    return Err(render(error));
                }
            },
            None => None,
        };
        let end_unsent = |code: &str| {
            if let Some(attempt) = attempt {
                end_unsent_attempt(&store, profile, &writer, &request_id, attempt, code);
            }
        };
        let signed = match attach_signature_authorized(
            envelope,
            &handle,
            guard.context.network_passphrase(),
            consumer,
            &authorization,
        )
        .await
        {
            Ok(signed) => signed,
            Err(error) => {
                cleanup_authorization(&store, guard.context, id, sign_failure_stage(&error));
                end_unsent(error.code());
                return Err(render(error));
            }
        };
        let recorder = prepared.build(
            &authorization,
            floor,
            witness,
            attempt,
            request_id.clone(),
            observation,
        );
        let result = submit_authorized_transaction_and_wait(
            client,
            oracle.as_ref(),
            &signed,
            timeout,
            guard.context.network_passphrase(),
            Some(SubmissionSignerKind::Keyring),
            &recorder,
            consumer,
            MainnetSubmitGrant::Tx(authorization),
        )
        .await;
        if let Err(error) = &result {
            cleanup_authorization(
                &store,
                guard.context,
                id,
                submit_failure_stage(recorder.pre_send_entered()),
            );
            recorder.end_refused_attempt(error.code());
        }
        result.map_err(|error| submission_error_result(&error, &signed))
    } else {
        let handle = stellar_agent_network::keyring::enrolled_keyring_signer(
            &record.profile_name,
            record.profile,
            source,
            server.established_owner().as_ref(),
        )
        .await
        .map_err(render)?;
        let signed = attach_signature(envelope, &handle, server.context.network_passphrase())
            .await
            .map_err(render)?;
        let recorder = build_recorder(record, floor)
            .map_err(render)?
            .with_witness(witness);
        submit_transaction_and_wait(
            client,
            &signed,
            timeout,
            server.context.network_passphrase(),
            Some(SubmissionSignerKind::Keyring),
            Some(&recorder),
        )
        .await
        .map_err(|error| submission_error_result(&error, &signed))
    }
}

/// Ends `attempt` as `NotSent` after a refusal with wire code `code` before
/// any send. The caller's refusal stands either way, so a failure is logged.
fn end_unsent_attempt(
    store: &PersistedWindowStore,
    profile: &Profile,
    writer: &stellar_agent_network::AuditWriterHandle,
    request_id: &str,
    attempt: stellar_agent_network::OperationAttempt,
    code: &str,
) {
    if let Err(error) = stellar_agent_network::end_operation_attempt(
        store,
        profile,
        writer,
        request_id,
        attempt,
        &stellar_agent_network::AttemptEnd::NotSent {
            code: code.to_owned(),
        },
    ) {
        tracing::warn!(
            code = error.code(),
            "operation record: the unsent attempt's end was not recorded; it stays sending \
             until recovery reads it"
        );
    }
}

/// Renders a submit-path error as a tool result, attaching the structured
/// detail the three unknown-outcome codes need.
///
/// `submission.tx_timeout`, `submission.tx_already_submitted` and
/// `submission.hash_mismatch` all describe a transaction whose outcome only
/// reconciliation can settle, and the agent needs the full transaction hash to
/// do it. The message stays redacted; the hash travels as data.
///
/// A policy denial from the reservation write renders as the dispatch gate
/// renders one. Every other error renders as a wallet error.
pub(crate) fn submission_error_result(err: &WalletError, signed_xdr: &str) -> CallToolResult {
    if let Some(result) = policy_denial_result(err) {
        return result;
    }
    let envelope = submission_flow::submission_error_envelope(err, signed_xdr, RECONCILE_TOOL);
    let json = envelope
        .to_json_pretty()
        .unwrap_or_else(|_| String::from("{}"));
    let mut result = CallToolResult::success(vec![Content::text(json)]);
    result.is_error = Some(true);
    result
}

/// The tool result for a policy denial reported by the submit path, or `None`
/// for every other error.
///
/// The spending-window reservation write re-applies the governing criterion's
/// comparison under its own lock and refuses a submission the window can no
/// longer admit. That refusal is the same decision the dispatch gate makes, so
/// it is reported the same way, down to the redaction the reason passes
/// through on its way to the wire.
pub(crate) fn policy_denial_result(err: &WalletError) -> Option<CallToolResult> {
    let WalletError::PolicyDenied { reason } = err else {
        return None;
    };
    Some(crate::tools::common::policy_denial_error_result(reason))
}

/// The wire code a submission that was never sent reports. A pre-send
/// refusal, so it carries no `details`.
const RECORD_UNAVAILABLE_CODE: &str = "submission.record_unavailable";

/// An unresolved submission reported by a surface that holds the typed DeFi
/// or smart-account error rather than a [`WalletError`].
///
/// The submit layer's refusal reaches those surfaces through
/// `SaError::SubmissionUnresolved` and `DefiAdapterError::SubmissionUnresolved`,
/// which carry the wire code and the identifiers. Flattening them to a generic
/// failure would leave the agent with a redacted message and no hash, which is
/// the state the durable record exists to remove.
pub(crate) struct UnresolvedSubmission<'a> {
    /// The stable `submission.*` code for the condition.
    pub wire_code: &'static str,
    /// The redacted operator-facing message.
    pub message: &'a str,
    /// The transaction to reconcile, in full.
    pub tx_hash: Option<&'a str>,
    /// The submission record's identity, when the surface holds it.
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
        if self.wire_code == RECORD_UNAVAILABLE_CODE {
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
        details.insert("reconcile_with".to_owned(), RECONCILE_TOOL.into());
        Some(serde_json::Value::Object(details))
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

/// Renders a DeFi submit failure as a tool result.
///
/// A policy denial renders as the dispatch gate renders one. A mainnet refusal
/// reports `network.mainnet_write_forbidden`. A signing refusal keeps its own
/// code, with no transaction to reconcile. An unresolved submission keeps its
/// `submission.*` code and its `details`; everything else is reported under
/// `fallback_code`.
pub(crate) fn defi_submit_error_result(
    error: &stellar_agent_defi::adapter::DefiAdapterError,
    fallback_code: &str,
) -> CallToolResult {
    if let stellar_agent_defi::adapter::DefiAdapterError::PolicyDenied { reason } = error {
        return crate::tools::common::policy_denial_error_result(reason);
    }
    if matches!(
        error,
        stellar_agent_defi::adapter::DefiAdapterError::MainnetWriteForbidden
    ) {
        return crate::tools::common::mainnet_write_forbidden_result();
    }
    if let stellar_agent_defi::adapter::DefiAdapterError::SigningRefusal { wire_code, message } =
        error
    {
        return crate::tools::common::business_error_result(*wire_code, message.clone());
    }
    match unresolved_from_defi(error) {
        Some(unresolved) => unresolved_result(&unresolved),
        None => crate::tools::common::business_error_result(fallback_code, error.to_string()),
    }
}

/// Renders an unresolved submission as a tool result.
pub(crate) fn unresolved_result(unresolved: &UnresolvedSubmission<'_>) -> CallToolResult {
    let envelope = match unresolved.details() {
        Some(details) => Envelope::<()>::err_raw_with_details(
            unresolved.wire_code,
            unresolved.message.to_owned(),
            details,
        ),
        None => Envelope::<()>::err_raw(unresolved.wire_code, unresolved.message.to_owned()),
    };
    let json = envelope
        .to_json_pretty()
        .unwrap_or_else(|_| String::from("{}"));
    let mut result = CallToolResult::success(vec![Content::text(json)]);
    result.is_error = Some(true);
    result
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
    use stellar_agent_core::profile::receipt::ReceiptStatus;
    use stellar_agent_network::policy_state::{DeliveryReport, ReconcileReport};
    use stellar_agent_network::submission_flow::{ReconcilePass, finish_reconciliation};
    use stellar_agent_network::{envelope_hash_hex, submission_flow::submission_details};

    #[cfg(feature = "mainnet-write")]
    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn recovery_mcp_build_stores_the_minimum_bound_or_none() {
        use crate::tools::common::tests::mainnet::{ClassicRun, Tool, ledger, mount_rpc};
        use wiremock::MockServer;
        for oracle_ledger in [Some(90_u32), Some(110), None] {
            let mut run = ClassicRun::allowed(Tool::Pay).await;
            let primary = MockServer::start().await;
            let oracle = MockServer::start().await;
            mount_rpc(&run.f, &primary).await;
            mount_rpc(&run.f, &oracle).await;
            mount_oracle_ledger(&oracle, oracle_ledger).await;
            run.f.server = crate::server::WalletServer::new_with_selection_and_routes_for_test(
                (*run.f.server.profile).clone(),
                stellar_agent_core::profile::name::ProfileNameSource::Flag,
                &stellar_agent_core::profile::schema::default_profile_dir().unwrap(),
                &[
                    ("rpc.example.invalid", &primary.uri()),
                    ("oracle.example.invalid", &oracle.uri()),
                ],
            )
            .unwrap();
            let result = run.commit().await;
            assert_eq!(result["ok"], true, "{result}");
            let state = ledger(&run.f).unwrap();
            let exposure = &state["operations"]["records"][0]["attempts"][0];
            assert_eq!(
                exposure["pre_exposure_ledger"],
                serde_json::json!(oracle_ledger.map(|value| value.min(100)))
            );
            assert_eq!(state["last_observation"]["ledger"], 100);
        }
    }

    /// Mounts an oracle at `latest`, or a failing one for `None`. Its
    /// `getLedgers` refuses a start beyond `latest`, as an RPC endpoint does.
    #[cfg(feature = "mainnet-write")]
    async fn mount_oracle_ledger(oracle: &wiremock::MockServer, latest: Option<u32>) {
        use wiremock::{Mock, ResponseTemplate, matchers::body_partial_json};
        let answer = move |request: &wiremock::Request, result: serde_json::Value| {
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"jsonrpc":"2.0", "id":body["id"], "result":result}),
            )
        };
        Mock::given(body_partial_json(
            serde_json::json!({"method":"getLatestLedger"}),
        ))
        .respond_with(move |request: &wiremock::Request| {
            let Some(latest) = latest else {
                return ResponseTemplate::new(500);
            };
            answer(
                request,
                serde_json::json!({"id":"00".repeat(32), "protocolVersion":23, "sequence":latest}),
            )
        })
        .with_priority(1)
        .mount(oracle)
        .await;
        Mock::given(body_partial_json(serde_json::json!({"method":"getLedgers"})))
            .respond_with(move |request: &wiremock::Request| {
                let Some(latest) = latest else {
                    return ResponseTemplate::new(500);
                };
                let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
                if body["params"]["startLedger"].as_u64() > Some(u64::from(latest)) {
                    return ResponseTemplate::new(200).set_body_json(serde_json::json!({
                        "jsonrpc":"2.0", "id":body["id"],
                        "error":{"code":-32600, "message":"startLedger must be at most the latest ledger"}
                    }));
                }
                answer(
                    request,
                    serde_json::json!({
                        "latestLedger":latest, "oldestLedger":1,
                        "latestLedgerCloseTime":(stellar_agent_core::timefmt::now_unix_ms().unwrap()/1000).to_string(),
                        "oldestLedgerCloseTime":1, "cursor":latest.to_string(), "ledgers":[]
                    }),
                )
            })
            .with_priority(1)
            .mount(oracle)
            .await;
    }

    #[test]
    fn submission_error_wire_guard_timeout() {
        let err = WalletError::Submission(SubmissionError::TxTimeout {
            tx_hash: "ab".repeat(32),
            seconds: 30,
        });
        let text = submission_error_result(&err, SIGNED_XDR).content[0]
            .as_text()
            .unwrap()
            .text
            .clone();
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        let text = text.replace(value["request_id"].as_str().unwrap(), "REQUEST_ID");
        assert_eq!(
            text,
            r#"{
  "ok": false,
  "error": {
    "code": "submission.tx_timeout",
    "message": "transaction 'abababab...abababab' was not confirmed within 30s; its outcome is unknown: settle it by its transaction hash and do not resubmit",
    "details": {
      "envelope_hash": "fdca46b81c5c77753f52cce8845503c8eef69ef48266f0e4ded1ea19060db975",
      "outcome": "unknown",
      "reconcile_with": "stellar_transaction_status",
      "timeout_seconds": 30,
      "tx_hash": "abababababababababababababababababababababababababababababababab"
    }
  },
  "request_id": "REQUEST_ID"
}"#
        );
    }

    #[test]
    fn submission_error_wire_guard_policy_denied() {
        let err = WalletError::PolicyDenied {
            reason: Box::new(stellar_agent_core::policy::DenyReason::EvaluationError {
                detail: "guard refusal".to_owned(),
            }),
        };
        let text = submission_error_result(&err, SIGNED_XDR).content[0]
            .as_text()
            .unwrap()
            .text
            .clone();
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        let text = text.replace(value["request_id"].as_str().unwrap(), "REQUEST_ID");
        assert_eq!(
            text,
            r#"{
  "ok": false,
  "error": {
    "code": "policy.deny.evaluation_error",
    "message": "policy denied this operation: {\"EvaluationError\":{\"detail\":\"guard refusal\"}}"
  },
  "request_id": "REQUEST_ID"
}"#
        );
    }

    const SIGNED_XDR: &str = "AAAAAgAAAAA=";

    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn an_opaque_class_under_a_value_cap_builds_no_recorder() {
        use stellar_agent_core::policy::v1::criteria::{
            per_period_cap::{PerPeriodCapCriterion, Window},
            rate_limit::RateLimitCriterion,
            state_store::{StateKey, WindowEntry, WindowLimit},
        };
        use stellar_agent_core::policy::v1::loader::{
            PolicyDocument, PolicyRule, RuleMatch, ScopeId,
        };
        use stellar_agent_core::policy::v1::{OpaqueReason, PolicyEngineV1};
        use stellar_agent_network::SubmissionRecorder;
        for exemption in [false, true] {
            stellar_agent_test_support::keyring_mock::install().unwrap();
            let dir = tempfile::tempdir().unwrap();
            let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(dir.path());
            let profile = Profile::builder_testnet_named(
                "intent",
                "opaque",
                "account",
                "opaque-nonce",
                "account",
            )
            .build();
            let audit = Arc::new(Mutex::new(
                AuditWriter::open(dir.path().join("audit.jsonl"), None).unwrap(),
            ));
            let tool = "stellar_smart_account_execute";
            let engine = PolicyEngineV1::new(
                PolicyDocument {
                    version: 1,
                    scope: ScopeId::AllProfiles,
                    signature: None,
                    rules: vec![PolicyRule {
                        r#match: RuleMatch {
                            tool: tool.into(),
                            chain: "*".into(),
                        },
                        criteria: vec![
                            Box::new(PerPeriodCapCriterion::new(
                                "native".into(),
                                Window::parse("1m").unwrap(),
                                10,
                            )),
                            Box::new(RateLimitCriterion::new(Window::parse("1m").unwrap(), 1)),
                        ],
                        decision: stellar_agent_core::policy::Decision::Allow,
                        allow_opaque_signing: exemption,
                    }],
                },
                "intent".into(),
            );
            let registry = HashMap::from([(
                tool,
                ToolDescriptor::from_registration(
                    &stellar_agent_core::policy::McpToolRegistration {
                        name: tool,
                        destructive_hint: true,
                        read_only_hint: false,
                        chain_id_required: true,
                        value_kind: stellar_agent_core::policy::ToolValueKind::MovesValue,
                    },
                ),
            )]);
            let window = PersistedWindowStore::for_profile("intent");
            let now = stellar_agent_core::timefmt::now_unix_ms().unwrap();
            let before = if exemption {
                window
                    .record_and_persist(
                        &profile,
                        &[WindowEntry::new(
                            StateKey::new("intent", 1, "rate_limit", 60),
                            now,
                            1,
                            WindowLimit::Count {
                                window: "1m".into(),
                                max_calls: 1,
                            },
                        )],
                    )
                    .unwrap();
                Some(std::fs::read(window.path()).unwrap())
            } else {
                None
            };
            let result = build_recorder(
                CommitRecord {
                    profile: &profile,
                    profile_name: "intent".into(),
                    tool,
                    chain_id: "stellar:testnet".into(),
                    policy_decision: stellar_agent_core::audit_log::PolicyDecision::Allow,
                    legs: vec![],
                    engine: &engine,
                    registry: &registry,
                    value_class: ValueClass::Opaque(OpaqueReason::UnvaluedContractCall),
                    audit,
                    nonce_id: None,
                    approval_nonce: None,
                    approval_dir: None,
                    now_ms: now,
                    provenance: None,
                },
                None,
            );
            if exemption {
                let recorder = result.unwrap();
                let plan =
                    stellar_agent_network::signed_intent::test_helpers::intent_fixture_plan(1, 60)
                        .0;
                let error = recorder.admit_signed_intent(&plan).await.err().unwrap();
                assert_eq!(error.code(), "policy.deny.rate_limit_exceeded");
                assert_eq!(std::fs::read(window.path()).unwrap(), before.unwrap());
            } else {
                assert_eq!(
                    result.unwrap_err().code(),
                    "policy.deny.unsizable_value_effect"
                );
                assert!(!window.path().exists());
            }
            assert!(
                window
                    .signed_intents("intent", &profile)
                    .unwrap()
                    .is_empty()
            );
        }
    }

    #[test]
    fn timeout_carries_the_full_hash_and_the_recovery_protocol() {
        let hash = "ab".repeat(32);
        let err = WalletError::Submission(SubmissionError::TxTimeout {
            tx_hash: hash.clone(),
            seconds: 30,
        });
        let details = submission_details(&err, SIGNED_XDR, RECONCILE_TOOL).unwrap();
        assert_eq!(details["tx_hash"], hash);
        assert_eq!(details["timeout_seconds"], 30);
        assert_eq!(details["outcome"], "unknown");
        assert_eq!(details["reconcile_with"], RECONCILE_TOOL);
        assert_eq!(details["envelope_hash"], envelope_hash_hex(SIGNED_XDR));
    }

    #[test]
    fn already_submitted_names_the_transaction_to_reconcile() {
        let hash = "cd".repeat(32);
        let err =
            WalletError::Submission(SubmissionError::TxAlreadySubmitted { hash: hash.clone() });
        let details = submission_details(&err, SIGNED_XDR, RECONCILE_TOOL).unwrap();
        assert_eq!(details["tx_hash"], hash);
        assert_eq!(details["outcome"], "unknown");
    }

    #[test]
    fn hash_mismatch_carries_both_hashes() {
        let local = "ab".repeat(32);
        let server = "cd".repeat(32);
        let err = WalletError::Submission(SubmissionError::HashMismatch {
            local: local.clone(),
            server: server.clone(),
        });
        let details = submission_details(&err, SIGNED_XDR, RECONCILE_TOOL).unwrap();
        assert_eq!(details["tx_hash"], local);
        assert_eq!(details["server_tx_hash"], server);
    }

    #[test]
    fn other_submission_errors_carry_no_details() {
        let err = WalletError::Submission(SubmissionError::TxMalformed {
            detail: "txINSUFFICIENT_FEE".to_owned(),
        });
        assert!(submission_details(&err, SIGNED_XDR, RECONCILE_TOOL).is_none());
    }

    #[test]
    fn non_submission_errors_carry_no_details() {
        let err =
            WalletError::Network(stellar_agent_core::error::NetworkError::MainnetWriteForbidden);
        assert!(submission_details(&err, SIGNED_XDR, RECONCILE_TOOL).is_none());
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

        let result = defi_submit_error_result(&error, "vault.submit_failed");
        assert_eq!(result.is_error, Some(true));
        let text = match &result.content[0].raw {
            rmcp::model::RawContent::Text(t) => t.text.clone(),
            other => panic!("expected text content; got {other:?}"),
        };
        let json: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(json["error"]["code"], "submission.tx_timeout");
        assert_eq!(json["error"]["details"]["tx_hash"], "ab".repeat(32));
        assert_eq!(json["error"]["details"]["envelope_hash"], "cd".repeat(32));
        assert_eq!(json["error"]["details"]["outcome"], "unknown");
        assert_eq!(json["error"]["details"]["reconcile_with"], RECONCILE_TOOL);
    }

    /// A DeFi mainnet refusal reports the canonical code under every surface
    /// fallback.
    #[test]
    fn a_defi_mainnet_refusal_reports_the_canonical_code() {
        let error = stellar_agent_defi::adapter::DefiAdapterError::MainnetWriteForbidden;

        for fallback in ["vault.submit_failed", "dex.submit_failed"] {
            let result = defi_submit_error_result(&error, fallback);
            let (code, _message, _text) = crate::tools::common::assert_business_envelope(&result);
            assert_eq!(
                code, "network.mainnet_write_forbidden",
                "fallback {fallback}"
            );
        }
    }

    /// A DeFi signing refusal reports its own code under every surface
    /// fallback, with no transaction to reconcile.
    #[test]
    fn a_defi_signing_refusal_reports_its_own_code_without_a_transaction() {
        for expected in [
            "smart_account.ledger_witness_unavailable",
            "simulation.divergence.ledger_skew",
            "submission.intent_record_unavailable",
            "submission.intent_binding_mismatch",
        ] {
            let error = stellar_agent_defi::adapter::DefiAdapterError::SigningRefusal {
                wire_code: expected,
                message: "fixed".to_owned(),
            };
            for fallback in ["vault.submit_failed", "dex.submit_failed"] {
                let result = defi_submit_error_result(&error, fallback);
                let text = match &result.content[0].raw {
                    rmcp::model::RawContent::Text(t) => t.text.clone(),
                    other => panic!("expected text content; got {other:?}"),
                };
                let json: serde_json::Value = serde_json::from_str(&text).unwrap();
                assert_eq!(json["error"]["code"], expected, "fallback {fallback}");
                assert_eq!(json["error"]["message"], "fixed", "fallback {fallback}");
                assert!(
                    json["error"]["details"].is_null(),
                    "a refusal before signing names no transaction"
                );
            }
        }
    }

    /// Every other DeFi failure reports under the surface's own code.
    #[test]
    fn a_defi_failure_that_moved_nothing_keeps_its_own_code() {
        let error = stellar_agent_defi::adapter::DefiAdapterError::Network {
            reason: "endpoint unreachable".to_owned(),
        };

        let result = defi_submit_error_result(&error, "vault.submit_failed");
        let text = match &result.content[0].raw {
            rmcp::model::RawContent::Text(t) => t.text.clone(),
            other => panic!("expected text content; got {other:?}"),
        };
        let json: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(json["error"]["code"], "vault.submit_failed");
        assert!(json["error"]["details"].is_null());
    }

    /// A submission that was never sent carries no `details`.
    #[test]
    fn a_pre_send_refusal_carries_no_details() {
        let error = stellar_agent_defi::adapter::DefiAdapterError::SubmissionUnresolved {
            wire_code: "submission.record_unavailable",
            message: "the receipt store could not be written".to_owned(),
            tx_hash: None,
            envelope_hash: None,
            timeout_seconds: None,
        };

        let result = defi_submit_error_result(&error, "vault.submit_failed");
        let text = match &result.content[0].raw {
            rmcp::model::RawContent::Text(t) => t.text.clone(),
            other => panic!("expected text content; got {other:?}"),
        };
        let json: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(json["error"]["code"], "submission.record_unavailable");
        assert!(
            json["error"]["details"].is_null(),
            "a pre-send refusal carries no details; got {json}"
        );
    }

    /// The result envelope's error code and message.
    fn rendered(result: &CallToolResult) -> (String, String) {
        let text = match &result.content[0].raw {
            rmcp::model::RawContent::Text(t) => t.text.clone(),
            other => panic!("expected text content; got {other:?}"),
        };
        let json: serde_json::Value = serde_json::from_str(&text).unwrap();
        (
            json["error"]["code"].as_str().unwrap().to_owned(),
            json["error"]["message"].as_str().unwrap().to_owned(),
        )
    }

    fn per_period_denial() -> stellar_agent_core::policy::DenyReason {
        stellar_agent_core::policy::DenyReason::PerPeriodCapExceeded {
            asset: "native".to_owned(),
            window: "1d".to_owned(),
            max_stroops: 1_000,
            attempted_stroops: 600,
            period_used_stroops: 600,
        }
    }

    /// A submission the spending window refused reads exactly as a denial the
    /// dispatch gate made: the criterion's own code, and the reason in the
    /// message.
    #[test]
    fn a_refused_reservation_reads_as_a_gate_denial() {
        let err = WalletError::PolicyDenied {
            reason: Box::new(per_period_denial()),
        };
        let result = submission_error_result(&err, SIGNED_XDR);
        assert_eq!(result.is_error, Some(true));
        let (code, message) = rendered(&result);
        assert_eq!(code, "policy.deny.per_period_cap_exceeded");
        assert_eq!(
            message,
            format!(
                "policy denied this operation: {}",
                serde_json::to_string(&per_period_denial()).unwrap()
            ),
            "the message is the one the dispatch gate produces for this reason"
        );
    }

    /// A refused submission was never sent, so it carries no reconciliation
    /// detail.
    #[test]
    fn a_refused_reservation_carries_no_reconciliation_detail() {
        let err = WalletError::PolicyDenied {
            reason: Box::new(per_period_denial()),
        };
        let text = match &submission_error_result(&err, SIGNED_XDR).content[0].raw {
            rmcp::model::RawContent::Text(t) => t.text.clone(),
            other => panic!("expected text content; got {other:?}"),
        };
        let json: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert!(
            json["error"]["details"].is_null(),
            "nothing was sent, so there is no transaction to reconcile: {json}"
        );
    }

    /// A DeFi tool reports the denial rather than its own submit-failure code.
    #[test]
    fn a_defi_tool_keeps_the_denial_rather_than_its_submit_failure_code() {
        let error = stellar_agent_defi::adapter::DefiAdapterError::PolicyDenied {
            reason: Box::new(per_period_denial()),
        };
        let result = defi_submit_error_result(&error, "dex.submit_failed");
        assert_eq!(result.is_error, Some(true));
        let (code, _message) = rendered(&result);
        assert_eq!(
            code, "policy.deny.per_period_cap_exceeded",
            "a refused cap must not read as a submit failure"
        );
    }

    /// A store this server cannot write still reports a record it could not
    /// make, under the code that names exactly that.
    #[test]
    fn a_record_that_cannot_be_written_is_still_record_unavailable() {
        let err = WalletError::Submission(SubmissionError::RecordUnavailable {
            detail: "the spending-window reservation could not be written".to_owned(),
        });
        let (code, _message) = rendered(&submission_error_result(&err, SIGNED_XDR));
        assert_eq!(code, "submission.record_unavailable");
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

        let result = defi_submit_error_result(&error, "vault.submit_failed");
        let text = match &result.content[0].raw {
            rmcp::model::RawContent::Text(t) => t.text.clone(),
            other => panic!("expected text content; got {other:?}"),
        };
        let json: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(json["error"]["details"]["timeout_seconds"], 45);
    }
    #[test]
    #[serial_test::serial(keyring)]
    fn allowed_recorder_requires_a_registered_tool() {
        let dir = tempfile::tempdir().expect("isolated audit directory");
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(dir.path());
        let profile = Profile::builder_testnet("signer", "default", "nonce", "default").build();
        let audit = Arc::new(Mutex::new(
            AuditWriter::open(dir.path().join("audit.jsonl"), None).expect("audit writer"),
        ));
        let error = build_recorder(
            CommitRecord {
                profile: &profile,
                profile_name: "missing-registry-entry".to_owned(),
                tool: "stellar_unregistered_commit",
                chain_id: "stellar:testnet".to_owned(),
                policy_decision: stellar_agent_core::audit_log::PolicyDecision::Allow,
                legs: Vec::new(),
                engine: &stellar_agent_core::policy::NoopPolicyEngine,
                registry: &HashMap::new(),
                value_class: ValueClass::ReadOnly,
                audit,
                nonce_id: None,
                approval_nonce: None,
                approval_dir: None,
                now_ms: 0,
                provenance: None,
            },
            None,
        )
        .expect_err("an allowed submission requires a registered tool");
        assert_eq!(error.code(), "submission.record_unavailable");
        assert!(error.message().contains("stellar_unregistered_commit"));
    }

    #[test]
    fn approved_recorder_requires_its_approval_store() {
        let dir = tempfile::tempdir().unwrap();
        let profile = Profile::builder_testnet("signer", "default", "nonce", "default").build();
        let audit = Arc::new(Mutex::new(
            AuditWriter::open(dir.path().join("audit.jsonl"), None).unwrap(),
        ));
        let error = build_recorder(
            CommitRecord {
                profile: &profile,
                profile_name: "missing-approval-store".to_owned(),
                tool: "stellar_pay_commit",
                chain_id: "stellar:testnet".to_owned(),
                policy_decision: stellar_agent_core::audit_log::PolicyDecision::RequireApproval,
                legs: Vec::new(),
                engine: &stellar_agent_core::policy::NoopPolicyEngine,
                registry: &HashMap::new(),
                value_class: ValueClass::ReadOnly,
                audit,
                nonce_id: None,
                approval_nonce: Some("approval-binding".to_owned()),
                approval_dir: None,
                now_ms: 0,
                provenance: None,
            },
            None,
        )
        .expect_err("an approval binding must not be silently dropped");
        assert_eq!(error.code(), "submission.record_unavailable");
        assert!(error.message().contains("approval store"));
    }
    #[test]
    fn approved_recorder_requires_its_approval_nonce() {
        let dir = tempfile::tempdir().unwrap();
        let profile = Profile::builder_testnet("signer", "default", "nonce", "default").build();
        let audit = Arc::new(Mutex::new(
            AuditWriter::open(dir.path().join("audit.jsonl"), None).unwrap(),
        ));
        let error = build_recorder(
            CommitRecord {
                profile: &profile,
                profile_name: "missing-approval-nonce".to_owned(),
                tool: "stellar_pay_commit",
                chain_id: "stellar:testnet".to_owned(),
                policy_decision: stellar_agent_core::audit_log::PolicyDecision::RequireApproval,
                legs: Vec::new(),
                engine: &stellar_agent_core::policy::NoopPolicyEngine,
                registry: &HashMap::new(),
                value_class: ValueClass::ReadOnly,
                audit,
                nonce_id: None,
                approval_nonce: None,
                approval_dir: Some(dir.path().to_path_buf()),
                now_ms: 0,
                provenance: None,
            },
            None,
        )
        .expect_err("an approved submission must carry its approval nonce");
        assert_eq!(error.code(), "submission.record_unavailable");
        assert!(error.message().contains("approval nonce"));
    }

    /// A mainnet recorder refuses each defect before any authorization: an
    /// approval without a store, an unregistered tool, unreadable receipts,
    /// an unreadable window and a window of another chain. Policy authority
    /// owes no tombstone, so it needs no approval store.
    #[cfg(feature = "mainnet-write")]
    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn mainnet_recorder_preparation_refuses_before_authorization() {
        use crate::tools::common::tests::mainnet::{Fixture, payment_witness};
        use stellar_agent_network::mainnet::authority::MainnetAuthority;
        for defect in [
            "none",
            "policy",
            "approval_dir",
            "registry",
            "receipts",
            "window",
            "window_chain",
        ] {
            let f = Fixture::new(|raw| raw);
            let witness = payment_witness(&f).await;
            let decision = stellar_agent_core::mainnet::decision::MainnetDecision::for_test(
                stellar_agent_core::policy::Decision::Allow,
                None,
                [4; 32],
                7,
                0,
                "operator",
                "stellar:mainnet",
                stellar_agent_core::timefmt::now_unix_ms().unwrap(),
                600_000,
                stellar_agent_core::mainnet::decision::AuthorityScope::Classic,
            );
            let authority = if defect == "policy" {
                MainnetAuthority::from_decision(&decision, None).unwrap()
            } else {
                MainnetAuthority::Approval(&witness)
            };
            let profile = f.server.security_profile();
            let readiness = stellar_agent_network::mainnet::audit_readiness::audit_readiness(
                profile, "operator",
            )
            .unwrap();
            if defect == "receipts" {
                let directory =
                    stellar_agent_core::profile::receipt::default_receipts_dir().unwrap();
                std::fs::create_dir_all(&directory).unwrap();
                std::fs::write(directory.join("operator.json"), "invalid receipt state").unwrap();
            }
            if defect == "window" {
                std::fs::create_dir_all(f.server.window_store.path().parent().unwrap()).unwrap();
                std::fs::write(f.server.window_store.path(), "invalid window state").unwrap();
            }
            if defect == "window_chain" {
                let mut foreign = profile.clone();
                foreign.chain_id = stellar_agent_core::profile::caip2::Caip2::Testnet;
                f.server
                    .window_store
                    .record_and_persist(&foreign, &[])
                    .unwrap();
            }
            let window_before = std::fs::read(f.server.window_store.path()).ok();
            let result = prepare_authorized_recorder(
                CommitRecord {
                    profile,
                    profile_name: "operator".to_owned(),
                    tool: if defect == "registry" {
                        "stellar_unregistered_commit"
                    } else {
                        "stellar_pay_commit"
                    },
                    policy_decision: stellar_agent_core::audit_log::PolicyDecision::RequireApproval,
                    chain_id: "stellar:mainnet".to_owned(),
                    legs: Vec::new(),
                    engine: f.server.policy_engine.as_ref(),
                    registry: &f.server.tool_registry,
                    value_class: ValueClass::ReadOnly,
                    audit: Arc::clone(readiness.writer()),
                    nonce_id: None,
                    approval_nonce: Some("approval-binding".to_owned()),
                    approval_dir: (!matches!(defect, "approval_dir" | "policy"))
                        .then(|| f.server.resolve_approval_dir().unwrap()),
                    now_ms: stellar_agent_core::timefmt::now_unix_ms().unwrap(),
                    provenance: Some(decision.provenance()),
                },
                f.server.window_store.clone(),
                &authority,
            );
            if matches!(defect, "none" | "policy") {
                assert!(result.is_ok());
            } else {
                let error = match result {
                    Ok(_) => panic!("accepted {defect}"),
                    Err(error) => error,
                };
                let code = if defect == "window_chain" {
                    "policy.window_chain_mismatch"
                } else {
                    "submission.record_unavailable"
                };
                assert_eq!(error.code(), code, "{defect}");
                assert_eq!(
                    std::fs::read(f.server.window_store.path()).ok(),
                    window_before
                );
            }
            assert_eq!(f.seed_reads.load(std::sync::atomic::Ordering::SeqCst), 0);
            if defect != "window" && f.server.window_store.exists() {
                let bytes = std::fs::read(f.server.window_store.path()).unwrap();
                let state: serde_json::Value = serde_json::from_slice(&bytes[32..]).unwrap();
                assert!(state["authorizations"].as_array().is_none_or(Vec::is_empty));
            }
        }
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
            .set_password(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x52; 32]))
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
        /// Acquires the profile's bound keyed writer, as every value verb
        /// acquires it.
        fn acquire(&self) -> Result<Arc<Mutex<AuditWriter>>, WalletError> {
            crate::tools::value_audit::require_value_audit_writer(
                &self.profile,
                &self.name,
                stellar_agent_core::audit_log::BindingCheck::Enforce,
            )
        }

        fn writer(&self) -> Arc<Mutex<AuditWriter>> {
            self.acquire().unwrap()
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
                    .finalize_released(
                        id,
                        stellar_agent_core::profile::receipt::ReleaseEvidence::TimeBoundPassed,
                    )
                    .unwrap(),
                Some(ReceiptStatus::ClearedByOperator) => {
                    self.receipts
                        .finalize_released(
                            id,
                            stellar_agent_core::profile::receipt::ReleaseEvidence::SequenceConsumed,
                        )
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
            let client =
                stellar_agent_network::StellarRpcClient::new("http://127.0.0.1:9").unwrap();
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

        /// Every row of the active audit file.
        fn rows(&self) -> Vec<serde_json::Value> {
            std::fs::read_to_string(&self.profile.audit_log_path)
                .unwrap_or_default()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect()
        }

        fn rows_of(&self, kind: &str) -> usize {
            self.rows().iter().filter(|row| row["kind"] == kind).count()
        }
    }

    /// No receipt status selects an audit row: every receipt-only case,
    /// `Failed` included, leaves the log untouched and never acquires the
    /// writer. Delivery of an identifier the verified window state does not
    /// hold refuses before any append.
    #[test]
    #[serial_test::serial(keyring)]
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
            let report = stellar_agent_network::policy_state::drain_accounting_obligations(
                &f.window,
                &f.profile,
                &f.name,
                Some(&f.receipts),
                || panic!("{label}: no obligation acquires the writer"),
            )
            .unwrap();
            assert_eq!(report, DeliveryReport::default(), "{label}");
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

    /// Receipt-only reconciliation leaves the pending row, with its witness,
    /// as the one row of the submission.
    #[test]
    #[serial_test::serial(keyring)]
    fn pending_witness_survives_mcp_reconciliation() {
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
            stellar_agent_network::policy_state::drain_accounting_obligations(
                &f.window,
                &f.profile,
                &f.name,
                Some(&f.receipts),
                || f.acquire(),
            )
            .unwrap();
            let rows: Vec<_> = f
                .rows()
                .into_iter()
                .filter(|row| row["envelope_hash"] == envelope.as_str())
                .collect();
            assert_eq!(rows.len(), 1, "{label}: {rows:?}");
            assert_eq!(rows[0]["kind"], "value_action_pending");
            assert_eq!(rows[0]["tool"], "stellar_pay_commit");
            assert_eq!(rows[0]["witness"], serde_json::to_value(&witness).unwrap());
        }
    }

    /// A forged tail past the writer's verified tip cannot acknowledge an
    /// authentic expiry: the integrity refusal appends nothing and leaves the
    /// expiry owed. A forged `Failed` receipt emits no outcome row.
    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn a_forged_tail_cannot_acknowledge_an_owed_expiry() {
        use stellar_agent_core::audit_log::{AuditEntry, PolicyDecision};
        let f = drain_fixture("forged-tail");
        let envelope = "a1".repeat(32);
        let decision_id = f.committed_expiry(&envelope).await;
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
                None,
            ))
            .unwrap();
        f.receipts
            .finalize(
                &envelope,
                ReceiptStatus::Failed {
                    code: "ledger.failed".to_owned(),
                },
                Some(5),
            )
            .unwrap();
        let forged = f
            .window
            .accounting_expiry_event(&f.profile, &decision_id)
            .unwrap()
            .unwrap();
        stellar_agent_core::audit_log::test_helpers::append_forged_entry(
            &f.profile.audit_log_path,
            forged,
            |_| None,
        );
        let before = std::fs::read(&f.profile.audit_log_path).unwrap();

        let refused = stellar_agent_network::policy_state::drain_accounting_obligations(
            &f.window,
            &f.profile,
            &f.name,
            Some(&f.receipts),
            || f.acquire(),
        );
        assert_eq!(
            refused.map(|_| ()).unwrap_err().code(),
            "audit.tip_anchor_mismatch"
        );
        assert_eq!(std::fs::read(&f.profile.audit_log_path).unwrap(), before);
        assert_eq!(f.rows_of("value_action_failed"), 0);
        assert_eq!(
            f.window
                .owed_accounting_expiries(&f.profile)
                .unwrap()
                .unacknowledged,
            vec![decision_id],
            "the expiry stays owed"
        );
    }

    /// The dispatch-time drain delivers an obligation an earlier pass left,
    /// whatever the current pass did: completed, refused, or skipped for an
    /// unavailable clock or primary client.
    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn the_dispatch_drain_delivers_old_obligations_after_any_pass() {
        for (label, pass) in [
            (
                "completed",
                ReconcilePass::Completed(ReconcileReport::default()),
            ),
            (
                "failed",
                ReconcilePass::Failed(
                    stellar_agent_network::policy_state::WindowStoreError::WriterLocked,
                ),
            ),
            ("clock", ReconcilePass::ClockUnavailable),
            ("client", ReconcilePass::ClientUnavailable),
        ] {
            let f = drain_fixture(&format!("dispatch-drain-{label}"));
            let envelope = "b2".repeat(32);
            let decision_id = f.committed_expiry(&envelope).await;
            let report = finish_reconciliation(
                &f.profile,
                &f.name,
                &f.window,
                Some(&f.receipts),
                &pass,
                || f.acquire(),
            )
            .unwrap();
            assert_eq!(
                (report.appended, report.acknowledged, report.projected),
                (1, 1, 1),
                "{label}: {report:?}"
            );
            let rows = f.rows();
            let expiries: Vec<_> = rows
                .iter()
                .filter(|row| row["kind"] == "submission_accounting_expired")
                .collect();
            assert_eq!(expiries.len(), 1, "{label}");
            assert_eq!(expiries[0]["decision_id"], decision_id.as_str());
            assert!(
                f.window
                    .owed_accounting_expiries(&f.profile)
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(
                f.receipts
                    .get(&envelope)
                    .unwrap()
                    .unwrap()
                    .settlement_decision_id,
                Some(decision_id)
            );
        }
    }

    #[test]
    fn mainnet_classic_cleanup_tracks_signing_and_pre_send_entry() {
        use stellar_agent_network::mainnet::resolve::InvalidationStage as S;
        assert!(matches!(submit_failure_stage(false), S::SubmitGateRefused));
        assert!(matches!(submit_failure_stage(true), S::PreSendRefused));
        let unavailable =
            WalletError::Auth(stellar_agent_core::error::AuthError::SignerKeyMismatch {
                what: "the expected signing account",
                expected: "expected".to_owned(),
                got: "missing".to_owned(),
            });
        assert!(matches!(
            sign_failure_stage(&unavailable),
            S::SignerUnavailable
        ));
        let refused =
            WalletError::from(stellar_agent_core::error::NetworkError::MainnetAuthorizationRefused);
        assert!(matches!(sign_failure_stage(&refused), S::SignRefused));
    }
}
