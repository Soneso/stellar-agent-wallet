//! Building the durable-submission recorder, reconciling what stands open, and
//! reporting what the submit layer refused.
//!
//! Every value verb that broadcasts records its submission before the
//! transaction is sent, and settles that record against what the network
//! answers. The construction is identical across the verbs, so it lives here
//! once, alongside the reconciliation pass each verb runs before its policy
//! gate and the mapping that turns the three unresolved-submission refusals
//! into a response an operator or an agent can act on.

use std::sync::{Arc, Mutex};

use stellar_agent_core::audit_log::schema::ValueLegRecord;
use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::{SubmissionError, WalletError};
use stellar_agent_core::policy::v1::{ValueClass, ValueEffects};
use stellar_agent_core::policy::{McpToolRegistration, ToolDescriptor, ToolValueKind};
use stellar_agent_core::profile::receipt::{ReceiptStatus, ReceiptStore};
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_network::StellarRpcClient;
use stellar_agent_network::policy_state::{PersistedWindowStore, RECONCILE_BUDGET};
use stellar_agent_network::{WalletSubmissionRecorder, envelope_hash_hex};

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
    /// CAIP-2 chain identifier for the audit rows.
    pub chain_id: &'a str,
    /// The value effects the policy gate sized. `None` records no window
    /// entries and no legs.
    pub effects: Option<&'a ValueEffects>,
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

    let window_entries = match record.effects {
        Some(effects) => {
            let engine = crate::commands::policy_engine::build_v1_policy_engine(
                record.verb,
                &record.profile.policy.engine,
                record.profile,
                &record.profile_name,
            )
            .map_err(|e| {
                record_unavailable(format!("the policy engine could not be rebuilt: {e}"))
            })?;
            engine
                .record_confirmed(
                    &descriptor_for(record.tool, record.chain_id),
                    record.profile,
                    &ValueClass::Value(effects.clone()),
                )
                .map_err(|e| {
                    record_unavailable(format!(
                        "the policy engine could not account for this action: {e}"
                    ))
                })?
        }
        None => Vec::new(),
    };

    Ok(WalletSubmissionRecorder::new(
        record.profile,
        record.profile_name.clone(),
        record.tool,
        Some(record.chain_id.to_owned()),
        legs,
        window_entries,
        receipts,
        PersistedWindowStore::for_profile(&record.profile_name),
        record.audit,
        None,
        uuid::Uuid::new_v4().to_string(),
        record.now_ms,
    ))
}

/// Reconstructs the [`ToolDescriptor`] the gate evaluated against.
fn descriptor_for(tool: &'static str, chain_id: &str) -> ToolDescriptor {
    let reg = McpToolRegistration {
        name: tool,
        destructive_hint: true,
        read_only_hint: false,
        chain_id_required: true,
        value_kind: ToolValueKind::MovesValue,
    };
    let mut descriptor = ToolDescriptor::from_registration(&reg);
    descriptor.chain_id = chain_id.to_owned();
    descriptor
}

/// Settles the reservations that have stood long enough to be settleable,
/// before the policy gate counts them.
///
/// A reservation counts against the operator's caps while it stands, so a
/// verb that is about to be gated asks the chain about the oldest few first.
/// Reconciliation is not a gate of its own: a pass that cannot reach the
/// endpoint leaves every reservation standing and the verb continues, because
/// counting a reservation that may still apply is the safe direction.
pub(crate) async fn reconcile_open_reservations(
    profile: &Profile,
    profile_name: &str,
    client: &StellarRpcClient,
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
    let report = match window
        .reconcile_due(profile, client, receipts.as_ref(), now_ms, RECONCILE_BUDGET)
        .await
    {
        Ok(report) => report,
        Err(e) => {
            tracing::debug!(
                profile = %profile_name,
                error = ?e,
                "window reconcile: pass failed; open reservations stand"
            );
            return;
        }
    };

    // A submission the pass settled is owed the value-action row it never got
    // to write. The writer is the same keyed one the verb itself uses, so a
    // log that cannot be appended leaves the row owed rather than the
    // settlement undone.
    if report.settled.is_empty() {
        return;
    }
    let Ok(audit) = crate::commands::value_audit::require_value_audit_writer(profile, profile_name)
    else {
        tracing::debug!(
            profile = %profile_name,
            settled = report.settled.len(),
            "window reconcile: no audit writer; the settled rows stay owed"
        );
        return;
    };
    for settled in &report.settled {
        write_settled_row(
            profile,
            profile_name,
            &audit,
            &settled.envelope_hash,
            &settled.tx_hash,
            &settled.status,
            settled.ledger,
        );
    }
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
pub(crate) fn write_settled_row(
    profile: &Profile,
    profile_name: &str,
    audit: &Arc<Mutex<AuditWriter>>,
    envelope_hash: &str,
    tx_hash: &str,
    status: &ReceiptStatus,
    ledger: Option<u32>,
) {
    use stellar_agent_core::audit_log::reader::ValueActionSettlement;

    let (tool, chain_id, legs, nonce_id) =
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
            ),
            // The pending row has rotated out of the active file, so its sizing is
            // gone. The outcome still belongs in the log, under the name of the
            // surface that settled it.
            ValueActionSettlement::OwedWithoutLegs => (
                RECONCILE_VERB.to_owned(),
                profile.chain_id.caip2_str().to_owned().into(),
                Vec::new(),
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
                stellar_agent_core::audit_log::PolicyDecision::Allow,
                Some(envelope_hash.to_owned()),
                nonce_id,
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
                stellar_agent_core::audit_log::PolicyDecision::Allow,
                Some(envelope_hash.to_owned()),
                nonce_id,
                &request_id,
            )
        }
        // Every other status leaves the submission's outcome open, and an
        // open outcome is what the pending row already records.
        _ => return,
    };
    crate::commands::value_audit::emit_value_audit_row_with_writer(audit, profile_name, entry);
}

/// Renders a submit-path error, attaching the structured detail the three
/// unknown-outcome codes need.
///
/// `submission.tx_timeout`, `submission.tx_already_submitted` and
/// `submission.hash_mismatch` all describe a transaction whose outcome only
/// reconciliation can settle, and the caller needs the full transaction hash
/// to do it. The message stays redacted; the hash travels as data.
///
/// Every other error renders exactly as it did before.
pub(crate) fn error_envelope(err: &WalletError, signed_xdr: &str) -> Envelope<()> {
    match submission_details(err, signed_xdr) {
        Some(details) => Envelope::<()>::err_with_details(err, details),
        None => Envelope::<()>::err(err),
    }
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
/// An unresolved submission keeps its `submission.*` code and its `details`;
/// everything else is reported under `fallback_code`, as it was.
pub(crate) fn render_defi_submit_error(
    error: &stellar_agent_defi::adapter::DefiAdapterError,
    fallback_code: &str,
) -> i32 {
    match unresolved_from_defi(error) {
        Some(unresolved) => {
            crate::common::render::render_json(&unresolved.envelope());
        }
        None => {
            crate::common::render::render_json(&Envelope::<()>::err_raw(
                fallback_code,
                error.to_string(),
            ));
        }
    }
    1
}

/// Renders a submit-path error for a verb whose other submission failures
/// carry their own wire code.
///
/// The three unknown-outcome codes are reported unchanged, with their
/// reconciliation detail: an agent told the submission failed under a
/// verb-specific code would rebuild and re-submit, which is exactly what a
/// transaction that may still apply forbids. Everything else keeps
/// `fallback_code`.
pub(crate) fn error_envelope_with_fallback(
    err: &WalletError,
    signed_xdr: &str,
    fallback_code: &str,
) -> Envelope<()> {
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
        let envelope = error_envelope(&err, SIGNED_XDR);
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
        let envelope = error_envelope(&err, SIGNED_XDR);
        let message = &envelope.error.as_ref().unwrap().message;
        assert!(!message.contains(&hash), "message must stay redacted");
        assert!(message.contains("..."));
    }

    #[test]
    fn other_errors_carry_no_details() {
        let err = WalletError::Submission(SubmissionError::TxMalformed {
            detail: "txINSUFFICIENT_FEE".to_owned(),
        });
        let envelope = error_envelope(&err, SIGNED_XDR);
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
}
