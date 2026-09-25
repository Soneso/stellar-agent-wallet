//! Building the durable-submission recorder, and reporting what it refused.
//!
//! Every value-moving tool in this server records its submission before the
//! transaction is sent. The construction is identical across them — the same
//! stores, the same audit writer, the same policy-sized window entries — so it
//! lives here once, and so does the mapping that turns the three submission
//! refusals into a response an agent can act on.

use std::sync::{Arc, Mutex};

use rmcp::model::{CallToolResult, Content};
use stellar_agent_core::audit_log::schema::ValueLegRecord;
use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::{SubmissionError, WalletError};
use stellar_agent_core::policy::v1::ValueClass;
use stellar_agent_core::policy::{PolicyEngine, ToolDescriptor};
use stellar_agent_core::profile::receipt::{ReceiptStatus, ReceiptStore};
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_network::policy_state::PersistedWindowStore;
use stellar_agent_network::{
    ApprovalTombstone, SequenceFloorHook, WalletSubmissionRecorder, envelope_hash_hex,
};

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
    /// The registry descriptor the gate evaluated against. `None` where the
    /// tool is not registered, which records no window entries.
    pub descriptor: Option<&'a ToolDescriptor>,
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
/// opened or the policy engine cannot account for the action. Both refuse the
/// submission: a send the wallet cannot record is one it cannot reconcile,
/// cap, or audit afterwards.
pub(crate) fn build_recorder<'a>(
    record: CommitRecord<'a>,
    sequence_floor: Option<&'a dyn SequenceFloorHook>,
) -> Result<WalletSubmissionRecorder<'a>, WalletError> {
    // Only a gate that required approval verified the presented nonce, so only
    // that decision binds, spends and records it.
    let approval = match record.policy_decision {
        stellar_agent_core::audit_log::PolicyDecision::RequireApproval => {
            match (record.approval_nonce, record.approval_dir) {
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

    let receipts = ReceiptStore::open(&record.profile_name).map_err(|e| {
        WalletError::Submission(SubmissionError::RecordUnavailable {
            detail: format!("the submission receipt store could not be opened: {e}"),
        })
    })?;

    let window_entries = match record.descriptor {
        Some(descriptor) => record
            .engine
            .record_confirmed(descriptor, record.profile, &record.value_class)
            .map_err(|e| {
                WalletError::Submission(SubmissionError::RecordUnavailable {
                    detail: format!("the policy engine could not account for this action: {e}"),
                })
            })?,
        None => Vec::new(),
    };

    Ok(WalletSubmissionRecorder::new(
        record.profile,
        record.profile_name.clone(),
        record.tool,
        Some(record.chain_id),
        record.policy_decision,
        record.legs,
        window_entries,
        receipts,
        PersistedWindowStore::for_profile(&record.profile_name),
        Some(record.audit),
        record.nonce_id,
        uuid::Uuid::new_v4().to_string(),
        record.now_ms,
    )
    .with_sequence_floor(sequence_floor)
    .with_approval(approval))
}

/// Writes the value-action row that settles a reconciled submission.
///
/// The row carries the SAME value legs the gate sized, read back from the
/// pending row this submission wrote before it was sent: they were derived
/// once, at the gate, and are never re-derived here. `ledger` is the ledger
/// the chain reports the transaction in.
///
/// Non-fatal: the chain has already answered, and the settled record is the
/// receipt and the spending window. A row that cannot be appended is logged.
#[allow(
    clippy::too_many_arguments,
    reason = "settlement carries submission identity and the reconciliation decision"
)]
pub(crate) fn write_settled_row(
    profile: &Profile,
    profile_name: &str,
    audit: &Arc<Mutex<AuditWriter>>,
    envelope_hash: &str,
    tx_hash: &str,
    status: &ReceiptStatus,
    ledger: Option<u32>,
    reconciliation_decision: stellar_agent_core::audit_log::PolicyDecision,
) {
    use stellar_agent_core::audit_log::reader::ValueActionSettlement;

    let (tool, chain_id, legs, nonce_id, policy_decision, approval_nonce) =
        match stellar_agent_core::audit_log::reader::value_action_settlement(
            &profile.audit_log_path,
            envelope_hash,
        ) {
            // Already accounted for. Reconciliation is repeatable, and a second
            // row would count one spend twice.
            ValueActionSettlement::Settled => return,
            ValueActionSettlement::Owed(pending) => (
                pending.tool,
                pending.chain_id,
                pending.legs,
                pending.nonce_id,
                pending.policy_decision,
                pending.approval_nonce,
            ),
            // The pending row has rotated out of the active file, so its sizing is
            // gone. The outcome still belongs in the log, under the name of the
            // surface that settled it.
            ValueActionSettlement::OwedWithoutLegs => (
                RECONCILE_TOOL.to_owned(),
                profile.chain_id.caip2_str().to_owned().into(),
                Vec::new(),
                None,
                reconciliation_decision,
                None,
            ),
        };
    let chain_id: Option<String> = chain_id;
    let tx_redacted = stellar_agent_network::redact_tx_hash(tx_hash);
    let request_id = uuid::Uuid::new_v4().to_string();
    let entry = match status {
        ReceiptStatus::Success => {
            stellar_agent_core::audit_log::AuditEntry::new_value_action_submitted(
                tool,
                chain_id,
                legs,
                tx_redacted.as_str(),
                ledger.unwrap_or(0),
                policy_decision,
                Some(envelope_hash.to_owned()),
                nonce_id,
                approval_nonce,
                &request_id,
            )
        }
        ReceiptStatus::Failed { code } => {
            stellar_agent_core::audit_log::AuditEntry::new_value_action_failed(
                tool,
                chain_id,
                legs,
                tx_redacted.as_str(),
                code.as_str(),
                policy_decision,
                Some(envelope_hash.to_owned()),
                nonce_id,
                approval_nonce,
                &request_id,
            )
        }
        // Every other status leaves the submission's outcome open, and an
        // open outcome is what the pending row already records.
        _ => return,
    };
    crate::tools::value_audit::emit_value_audit_row_with_writer(audit, profile_name, entry);
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
    let envelope = match submission_details(err, signed_xdr) {
        Some(details) => Envelope::<()>::err_with_details(err, details),
        None => Envelope::<()>::err(err),
    };
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
/// A policy denial renders as the dispatch gate renders one. An unresolved
/// submission keeps its `submission.*` code and its `details`; everything else
/// is reported under `fallback_code`.
pub(crate) fn defi_submit_error_result(
    error: &stellar_agent_defi::adapter::DefiAdapterError,
    fallback_code: &str,
) -> CallToolResult {
    if let stellar_agent_defi::adapter::DefiAdapterError::PolicyDenied { reason } = error {
        return crate::tools::common::policy_denial_error_result(reason);
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
    details.insert("reconcile_with".to_owned(), RECONCILE_TOOL.into());
    Some(serde_json::Value::Object(details))
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

    const SIGNED_XDR: &str = "AAAAAgAAAAA=";

    #[test]
    fn timeout_carries_the_full_hash_and_the_recovery_protocol() {
        let hash = "ab".repeat(32);
        let err = WalletError::Submission(SubmissionError::TxTimeout {
            tx_hash: hash.clone(),
            seconds: 30,
        });
        let details = submission_details(&err, SIGNED_XDR).unwrap();
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
        let details = submission_details(&err, SIGNED_XDR).unwrap();
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
        let details = submission_details(&err, SIGNED_XDR).unwrap();
        assert_eq!(details["tx_hash"], local);
        assert_eq!(details["server_tx_hash"], server);
    }

    #[test]
    fn other_submission_errors_carry_no_details() {
        let err = WalletError::Submission(SubmissionError::TxMalformed {
            detail: "txINSUFFICIENT_FEE".to_owned(),
        });
        assert!(submission_details(&err, SIGNED_XDR).is_none());
    }

    #[test]
    fn non_submission_errors_carry_no_details() {
        let err =
            WalletError::Network(stellar_agent_core::error::NetworkError::MainnetWriteForbidden);
        assert!(submission_details(&err, SIGNED_XDR).is_none());
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
    fn approved_recorder_requires_its_approval_store() {
        let dir = tempfile::tempdir().unwrap();
        let profile = Profile::builder_testnet("signer", "default", "nonce", "default").build();
        let audit = Arc::new(Mutex::new(
            AuditWriter::open(dir.path().join("audit.jsonl"), None).unwrap(),
        ));
        let result = build_recorder(
            CommitRecord {
                profile: &profile,
                profile_name: "missing-approval-store".to_owned(),
                tool: "stellar_pay_commit",
                chain_id: "stellar:testnet".to_owned(),
                policy_decision: stellar_agent_core::audit_log::PolicyDecision::RequireApproval,
                legs: Vec::new(),
                engine: &stellar_agent_core::policy::NoopPolicyEngine,
                descriptor: None,
                value_class: ValueClass::ReadOnly,
                audit,
                nonce_id: None,
                approval_nonce: Some("approval-binding".to_owned()),
                approval_dir: None,
                now_ms: 0,
            },
            None,
        );
        let error = result.expect_err("an approval binding must not be silently dropped");
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
        let result = build_recorder(
            CommitRecord {
                profile: &profile,
                profile_name: "missing-approval-nonce".to_owned(),
                tool: "stellar_pay_commit",
                chain_id: "stellar:testnet".to_owned(),
                policy_decision: stellar_agent_core::audit_log::PolicyDecision::RequireApproval,
                legs: Vec::new(),
                engine: &stellar_agent_core::policy::NoopPolicyEngine,
                descriptor: None,
                value_class: ValueClass::ReadOnly,
                audit,
                nonce_id: None,
                approval_nonce: None,
                approval_dir: Some(dir.path().to_path_buf()),
                now_ms: 0,
            },
            None,
        );
        let error = result.expect_err("an approved submission must carry its approval nonce");
        assert_eq!(error.code(), "submission.record_unavailable");
        assert!(error.message().contains("approval nonce"));
    }
}
