//! One authenticated image for approval status and its read-policy evaluation.

use std::path::Path;

use serde_json::{Value, json};
use stellar_agent_core::approval::{
    ApprovalKind, AttestationBinding, PendingApproval,
    inspection::{InspectionEntry, inspect_stored_approval, read_pending_approval},
    presence::approval_view_subject,
    subject::SubjectKind,
};
use stellar_agent_core::error::{ApprovalFailure, SubmissionError, WalletError};
use stellar_agent_core::policy::{pin::PinState, v1::PolicyStateStore};
use stellar_agent_core::profile::schema::Profile;

use super::{ApprovalState, ApprovalStatus, Approvals, records};
use crate::policy_state::operations::WindowSection;
use crate::policy_state::{PersistedWindowStore, WindowStoreError, operations, store};

/// A verified window image shared by status projection and policy hydration.
/// Reads never collect records or persist expiry. The public ID is the inbox nonce.
pub struct ApprovalStatusSnapshot<'a> {
    wire: Option<store::WireFile>,
    store: &'a PersistedWindowStore,
    profile: &'a Profile,
    name: &'a str,
    now_ms: u64,
}

impl<'a> ApprovalStatusSnapshot<'a> {
    /// Reads one authenticated generation without opening the inbox.
    ///
    /// # Errors
    /// Preserves strict decoding, integrity, generation and keyring refusals.
    pub fn read(
        store: &'a PersistedWindowStore,
        profile: &'a Profile,
        name: &'a str,
        now_ms: u64,
    ) -> Result<Self, WindowStoreError> {
        Ok(Self {
            wire: store.read_for_inspection(profile)?,
            store,
            profile,
            name,
            now_ms,
        })
    }

    /// Populates a cleared policy store from this image, with no second read.
    /// Earlier history uses the existing retirement rules on an in-memory copy.
    ///
    /// # Errors
    /// Returns the hydration and legacy policy-pin failures of the window store.
    pub fn hydrate_into(&self, dest: &PolicyStateStore) -> Result<(), WindowStoreError> {
        let Some(wire) = &self.wire else {
            return Ok(());
        };
        if store::earlier_build(wire) {
            let pin = stellar_agent_core::policy::v1::verified::read_pin_without_creating(
                self.store.path(),
                self.profile,
            )
            .map_err(|error| WindowStoreError::TotalEpochUnavailable {
                detail: error.to_string(),
            })?;
            let pinned = match pin {
                PinState::Present(pin) => Some(pin.digest()),
                PinState::Absent => None,
            };
            let mut copy = wire.clone();
            store::retire_earlier_build(&mut copy, pinned)?;
            return PersistedWindowStore::hydrate_inspected(&copy, self.name, dest, self.now_ms);
        }
        PersistedWindowStore::hydrate_inspected(wire, self.name, dest, self.now_ms)
    }

    /// Projects the retained durable record, falling back to a strictly loaded
    /// inbox only when no durable record remains. Proof material stays private.
    ///
    /// # Errors
    /// Returns `approval.unknown` for absent nonces and `approval.store_open_failed`
    /// for every inbox opening failure. Verification failures remain view fields.
    pub fn inspect(mut self, nonce: &str, inbox: &Path) -> Result<Value, WalletError> {
        if let Some(wire) = &mut self.wire {
            Approvals::prune(wire, self.now_ms);
            if let Some(record) = records(wire).iter().find(|record| record.nonce == nonce) {
                let expiry = record.expiry();
                let state = match record.state {
                    ApprovalState::Consumed => "consumed",
                    ApprovalState::Revoked => "revoked",
                    ApprovalState::Pending if self.now_ms >= expiry => "expired",
                    ApprovalState::Pending if record.consent.is_some() => "attested",
                    ApprovalState::Pending => "pending",
                };
                let mut view = json!({
                    "state": state, "kind": record.kind.kind_name(),
                    "created_at_ms": record.created_at_ms, "expires_at_ms": expiry,
                    "waiting_expires_at_ms": record.waiting_expires_at_ms,
                    "binding": binding(record.subject_kind),
                    "reusable": false, "reuse_kind": "none",
                });
                if record.state == ApprovalState::Pending {
                    view["subject_digest"] =
                        stellar_agent_core::hex::encode(&record.subject).into();
                }
                if let Some(consent) = &record.consent {
                    view["attested_at_ms"] = consent.consent_at_ms.into();
                    view["execution_expires_at_ms"] = consent.execution_expires_at_ms.into();
                }
                if let Some(operation) = operations::records(wire)
                    .iter()
                    .find(|operation| operation.id == record.operation_id)
                {
                    view["business_id"] = operation.business_id.as_str().into();
                    if matches!(
                        operation.state,
                        operations::OperationState::Sending
                            | operations::OperationState::SentOutcomeUnknown
                    ) && let Some(attempt) = operation.attempts.last()
                    {
                        view["open_attempt"] = attempt.index.into();
                    }
                    if record.state == ApprovalState::Consumed {
                        if let Some(operations::ExposureIdentity::Classic { tx_hash, .. }) =
                            operation
                                .attempts
                                .last()
                                .and_then(|attempt| attempt.exposure.as_ref())
                                .map(|exposure| &exposure.identity)
                        {
                            view["tx_hash"] = stellar_agent_core::hex::encode(tx_hash).into();
                            view["outcome"] = "unknown".into();
                        }
                        result_fields(&mut view, operation.state, operation.result.as_ref());
                    }
                } else if let Some(operation) = wire.operations.as_ref().and_then(|section| {
                    section
                        .tombstones
                        .iter()
                        .find(|operation| operation.id == record.operation_id)
                }) {
                    view["business_id"] = operation.business_id.as_str().into();
                    if record.state == ApprovalState::Consumed {
                        result_fields(&mut view, operation.state, operation.result.as_ref());
                    }
                }
                let facts = ApprovalStatus::facts(record.clone(), self.profile);
                verification(
                    &mut view,
                    InspectionEntry::Durable(&facts),
                    self.now_ms,
                    self.name,
                    self.profile,
                );
                return Ok(view);
            }
        }
        let entry = read_pending_approval(inbox, nonce)?.ok_or(ApprovalFailure::Unknown)?;
        Ok(pending_view(&entry, self.now_ms, self.name, self.profile))
    }
}

fn result_fields(
    view: &mut Value,
    state: operations::OperationState,
    result: Option<&operations::OperationResult>,
) {
    if let Some(hash) = result.and_then(|result| result.tx_hash) {
        view["tx_hash"] = stellar_agent_core::hex::encode(&hash).into();
        view["outcome"] = if matches!(
            state,
            operations::OperationState::Succeeded | operations::OperationState::Failed
        ) {
            "confirmed"
        } else {
            "unknown"
        }
        .into();
    }
}

/// Maps a failed authenticated read without exposing stored content.
#[must_use]
pub fn status_read_error(error: &WindowStoreError) -> WalletError {
    error
        .chain_validation_error()
        .map(WalletError::from)
        .or_else(|| error.operation_error())
        .unwrap_or_else(|| {
            SubmissionError::RecordUnavailable {
                detail: "the authenticated approval window is unavailable".to_owned(),
            }
            .into()
        })
}

fn binding(kind: SubjectKind) -> &'static str {
    match kind {
        SubjectKind::EnvelopeText => "legacy-envelope",
        SubjectKind::IntentDigest => "canonical-intent",
    }
}

fn pending_view(entry: &PendingApproval, now: u64, name: &str, profile: &Profile) -> Value {
    let kind = match &entry.kind {
        ApprovalKind::Consumed {
            original_kind_name, ..
        }
        | ApprovalKind::Rejected { original_kind_name } => original_kind_name.as_str(),
        other => other.kind_name(),
    };
    let attested = match &entry.kind {
        ApprovalKind::SignWithPasskey { .. } => entry.passkey_assertion.is_some(),
        ApprovalKind::RegisterPasskey {
            registration_input, ..
        } => registration_input.is_some(),
        ApprovalKind::ToolsetFirstInvokeGate { .. } => false,
        _ => entry.attestation_blob_b64.is_some(),
    };
    let state = match entry.kind {
        ApprovalKind::Consumed { .. } => "consumed",
        ApprovalKind::Rejected { .. } => "rejected",
        _ if now >= entry.expires_at_unix_ms => "expired",
        _ if attested => "attested",
        _ => "pending",
    };
    let mut view = json!({
        "state": state, "kind": kind,
        "expires_at_ms": entry.expires_at_unix_ms,
        "reusable": false, "reuse_kind": "none",
    });
    match &entry.kind {
        ApprovalKind::Rejected { .. } => {
            view["rejected_at_ms"] = entry.created_at_unix_ms.into();
        }
        ApprovalKind::Consumed {
            tx_hash, outcome, ..
        } => {
            view["created_at_ms"] = entry.created_at_unix_ms.into();
            view["tx_hash"] = tx_hash.clone().into();
            view["outcome"] = outcome.label().into();
        }
        _ => {
            view["created_at_ms"] = entry.created_at_unix_ms.into();
            if let Ok(subject) = approval_view_subject(
                entry,
                &AttestationBinding::new(name, profile.chain_id.caip2_str()),
            ) {
                view["subject_digest"] = stellar_agent_core::hex::encode(&subject).into();
            }
        }
    }
    if let Some(receipt) = &entry.mainnet_presence {
        view["attested_at_ms"] = receipt.verified_at_unix_ms().into();
    }
    if !matches!(entry.kind, ApprovalKind::Rejected { .. })
        && matches!(
            kind,
            "PaymentSimulated" | "ClaimSimulated" | "TrustlineSimulated" | "X402Payment"
        )
    {
        view["binding"] = binding(entry.subject_kind).into();
    }
    verification(
        &mut view,
        InspectionEntry::Pending(entry),
        now,
        name,
        profile,
    );
    view
}

fn verification(
    view: &mut Value,
    entry: InspectionEntry<'_>,
    now: u64,
    name: &str,
    profile: &Profile,
) {
    view["verification"] = match inspect_stored_approval(entry, now, name, profile, None) {
        Some(inspection) => {
            json!({"supported": true, "valid": inspection.valid, "reason": inspection.reason})
        }
        None => {
            view["valid"] = Value::Null;
            json!({"supported": false})
        }
    };
}

#[cfg(test)]
mod tests;
