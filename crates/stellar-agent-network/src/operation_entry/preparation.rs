//! Staged preparation of lasting classic intent.

use super::*;
use stellar_agent_core::audit_log::PolicyDecision;

/// Serializes inbox orphan cleanup and durable record opening across producers.
/// The guard precedes the inbox, audit writer and window locks. Consent paths
/// never acquire it. Both binaries use the inbox path with extension `producer.lock`.
///
/// # Errors
/// Returns `approval.writer_locked` for contention and typed inbox I/O errors.
pub fn approval_producer_lock(
    path: &std::path::Path,
) -> Result<stellar_agent_core::file_lock::HeldFileLock, WalletError> {
    let io_error = |error: std::io::Error| {
        stellar_agent_core::approval::attest::record_error(
            &stellar_agent_core::approval::ApprovalError::Io {
                kind: error.kind(),
                source: error,
            },
        )
    };
    let mut options = std::fs::OpenOptions::new();
    options.create(true).read(true).write(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let file = options.open(path).map_err(io_error)?;
    stellar_agent_core::file_lock::HeldFileLock::try_lock(file).map_err(|error| match error {
        std::fs::TryLockError::WouldBlock => WalletError::Approval(ApprovalFailure::WriterLocked {
            detail: "another preparation is opening an approval; retry the same business id"
                .to_owned(),
        }),
        std::fs::TryLockError::Error(error) => io_error(error),
    })
}

/// The binding selected by a classic producer before opening its record.
#[derive(Debug, Clone)]
pub enum Preparation {
    /// The reduced legacy request identity; the record binds one envelope.
    Envelope([u8; 32]),
    /// Full lasting facts and the decision recorded at preparation.
    Canonical {
        /// The validated full intent, including a claim's asset and amount.
        intent: Box<ClassicIntent>,
        /// The prepare decision, retained for audit and status.
        decision: PolicyDecision,
        /// The governing rule's waiting lifetime, when approval is required.
        rule_ttl_ms: Option<u64>,
    },
}

fn conflict() -> WalletError {
    operation_refusal(WindowStoreError::BusinessIdConflict)
}

fn admitted(intent: &ClassicIntent) -> CanonicalUse<'_> {
    CanonicalUse {
        chain_id: intent.base().chain_id(),
        source: intent.base().source(),
        policy_digest: *intent.base().policy_digest(),
    }
}

/// Validates a preparation's intent under the current policy and its retained source.
///
/// # Errors
/// Refuses malformed envelopes, invalid canonical facts and inconsistent policy scope.
pub fn preparation_intent(
    handle: &OperationHandle,
    profile: &Profile,
    policy: &VerifiedPolicy,
) -> Result<Option<ClassicIntent>, WalletError> {
    if handle.intent().kind() != SlotKind::Canonical {
        return Ok(None);
    }
    let envelope = handle.envelope_xdr().ok_or_else(conflict)?;
    let TransactionEnvelope::Tx(tx) = decode_envelope(envelope)? else {
        return Err(conflict());
    };
    let source = muxed_strkey(&tx.tx.source_account);
    canonical_slot_intent(
        handle.intent(),
        &CanonicalUse {
            chain_id: profile.chain_id.caip2_str(),
            source: &source,
            policy_digest: policy.digest(),
        },
    )
    .map(Some)
    .map_err(|_| conflict())
}

/// Tags a newly constructed pending entry before insertion and checks its clock arithmetic.
/// Explicit deadline clipping may shorten the signed interval, but overflow refuses.
///
/// # Errors
/// Returns `approval.clock_error` if creation plus the requested TTL overflows.
pub fn stage_pending(
    entry: &mut PendingApproval,
    intent: Option<&ClassicIntent>,
    requested_ttl_ms: u64,
) -> Result<(), WalletError> {
    if intent.is_some() {
        entry
            .created_at_unix_ms
            .checked_add(requested_ttl_ms)
            .ok_or_else(|| {
                WalletError::Approval(ApprovalFailure::ClockError {
                    detail: "the approval waiting interval overflows".to_owned(),
                })
            })?;
        entry.subject_kind = stellar_agent_core::approval::subject::SubjectKind::IntentDigest;
    }
    Ok(())
}

impl Preparation {
    /// Looks up the selected binding before building an envelope.
    ///
    /// # Errors
    /// Refuses a conflicting business id, an invalid stored intent or a store error.
    pub fn lookup(
        &self,
        recorder: &mut OperationRecorder<'_>,
        business_id: &BusinessId,
    ) -> Result<ClassicEntry, WalletError> {
        match self {
            Self::Envelope(identity) => lookup_classic(recorder, business_id, identity),
            Self::Canonical { intent, .. } => lookup_canonical(
                recorder,
                business_id,
                IntentBaseFacts {
                    chain_id: intent.base().chain_id(),
                    source: intent.base().source(),
                    policy_digest: *intent.base().policy_digest(),
                    signed_fee_cap: None,
                    profile_fee_cap: None,
                    fee_choice: ClassicFeeChoice::Explicit(intent.base().fee_bound_stroops()),
                    memo: intent.base().memo().clone(),
                },
                IdentityFacts::Intent(intent.payload().clone()),
            ),
        }
    }

    /// Opens the selected binding, preserving a concurrent winner's envelope and intent.
    ///
    /// # Errors
    /// Refuses conflicting identities, malformed retained intent, capacity and store errors.
    pub fn open(
        &self,
        recorder: &mut OperationRecorder<'_>,
        business_id: BusinessId,
        tool: crate::policy_state::OperationTool,
        kind: OperationKind,
        envelope: &str,
    ) -> Result<OpenedEntry, WalletError> {
        let (slot, decision, ttl) = match self {
            Self::Envelope(identity) => (
                envelope_slot(identity, envelope, envelope_max_time(envelope)?),
                None,
                None,
            ),
            Self::Canonical {
                intent,
                decision,
                rule_ttl_ms,
            } => (
                IntentSlot::Canonical {
                    intent_digest: *intent.digest().as_bytes(),
                    intent: json!(intent),
                },
                Some(json!(decision)),
                *rule_ttl_ms,
            ),
        };
        let request = OpenRequest {
            business_id,
            tool,
            kind,
            intent: slot,
            envelope_xdr: Some(envelope.to_owned()),
            prepared_decision: decision,
            rule_ttl_ms: ttl,
        };
        let opened = open_classic(recorder, &request)?;
        if let Self::Canonical { intent, .. } = self {
            let slot = match &opened {
                OpenedEntry::Resume(handle) => Some(handle.intent().clone()),
                OpenedEntry::Replay(view) => recorder
                    .retained_intent(view.operation_id)
                    .map_err(operation_refusal)?,
            };
            if let Some(slot) = slot {
                canonical_slot_intent(&slot, &admitted(intent)).map_err(|_| conflict())?;
            }
        }
        Ok(opened)
    }
}

/// Looks up canonical lasting facts, filling a partial claim only from a retained slot.
/// A compacted partial claim refuses because its asset and amount are no longer stored.
/// No ledger client is needed, including after the balance or its predicate expires.
/// An envelope record of the same identity answers as [`lookup_classic`] does: the
/// caller signs its stored envelope or replays it, and the record stays an envelope
/// record, so a rebuilt envelope with a fresh sequence refuses at its attempt.
///
/// # Errors
/// Returns `operation.business_id_conflict` for another binding or invalid intent,
/// the intent constructor's refusals, and store errors.
pub fn lookup_canonical(
    recorder: &mut OperationRecorder<'_>,
    business_id: &BusinessId,
    base: IntentBaseFacts<'_>,
    facts: IdentityFacts,
) -> Result<ClassicEntry, WalletError> {
    let Some(found) = recorder.lookup(business_id).map_err(operation_refusal)? else {
        return Ok(ClassicEntry::Build);
    };
    // A record prepared with its exact envelope keeps it: the request signs
    // that stored envelope or replays it, and the record is never rebuilt.
    if found.binding().0 == SlotKind::Envelope {
        if found.binding().1 != operation_identity(base.clone(), facts.clone())? {
            return Err(conflict());
        }
        return classic_dispatch(found);
    }
    if found.binding().0 != SlotKind::Canonical {
        return Err(conflict());
    }
    let slot = match &found {
        LookupOutcome::Resumable(handle) => Some(handle.intent().clone()),
        LookupOutcome::Replay(view) => recorder
            .retained_intent(view.operation_id)
            .map_err(operation_refusal)?,
    };
    let stored = slot
        .as_ref()
        .map(|slot| {
            canonical_slot_intent(
                slot,
                &CanonicalUse {
                    chain_id: base.chain_id,
                    source: base.source,
                    policy_digest: base.policy_digest,
                },
            )
        })
        .transpose()
        .map_err(|_| conflict())?;
    let payload = match facts {
        IdentityFacts::Intent(payload) => payload,
        IdentityFacts::Claim {
            balance_id,
            claimant,
        } => {
            let Some(IntentPayload::Claim {
                asset,
                amount_stroops,
                ..
            }) = stored.as_ref().map(ClassicIntent::payload)
            else {
                return Err(conflict());
            };
            IntentPayload::Claim {
                balance_id,
                claimant,
                asset: asset.clone(),
                amount_stroops: *amount_stroops,
            }
        }
    };
    if classic_intent(base, payload)?.digest().as_bytes() != &found.binding().1 {
        return Err(conflict());
    }
    Ok(match found {
        LookupOutcome::Resumable(handle) => ClassicEntry::Resume(resumable(handle)?),
        LookupOutcome::Replay(view) => ClassicEntry::Replay(view),
    })
}

/// Resolves an inbox entry through its authenticated approval and operation links.
/// The caller supplies the currently admitted chain, source and policy. The returned
/// intent is display and ceremony input; it grants no execution authority.
/// Legacy entries without canonical records return `None`.
///
/// # Errors
/// Returns `approval.wrong_kind` for inconsistent bindings or malformed intent,
/// `approval.revoked` for revocation, and the store's typed refusals.
pub fn intent_for_consent(
    store: &PersistedWindowStore,
    profile: &Profile,
    entry: &PendingApproval,
    scope: &CanonicalUse<'_>,
) -> Result<Option<ClassicIntent>, WalletError> {
    use stellar_agent_core::approval::{
        AttestationBinding, mainnet_consent_subject, subject::SubjectKind,
    };
    let invalid = || {
        WalletError::Approval(ApprovalFailure::WrongKind {
            detail: "the approval does not bind this stored canonical intent".to_owned(),
        })
    };
    let Some((operation, record)) = OperationStatus::new(store, profile)
        .operation_for_consent(&entry.approval_nonce)
        .map_err(operation_refusal)?
    else {
        return if entry.subject_kind == SubjectKind::IntentDigest {
            Err(invalid())
        } else {
            Ok(None)
        };
    };
    if operation.intent().kind() != SlotKind::Canonical {
        return if entry.subject_kind == SubjectKind::IntentDigest {
            Err(invalid())
        } else {
            Ok(None)
        };
    }
    if record.state == crate::policy_state::ApprovalState::Revoked {
        return Err(WalletError::Approval(ApprovalFailure::Revoked {
            detail: "this approval has been revoked".to_owned(),
        }));
    }
    let intent = canonical_slot_intent(operation.intent(), scope).map_err(|_| invalid())?;
    let name = stellar_agent_core::profile::name::profile_name_for_approval(profile);
    let challenge =
        mainnet_consent_subject(entry, &AttestationBinding::new(&name, scope.chain_id))?;
    if entry.subject_kind != SubjectKind::IntentDigest
        || record.subject_kind != SubjectKind::IntentDigest
        || record.kind != intent.approved_kind()
        || record.subject != *intent.digest().as_bytes()
        || record.created_at_ms != entry.created_at_unix_ms
        || record.waiting_expires_at_ms != entry.expires_at_unix_ms
        || operation
            .envelope_xdr()
            .map(stellar_agent_core::approval::subject::approval_subject_classic)
            != Some(challenge)
    {
        return Err(invalid());
    }
    Ok(Some(intent))
}
