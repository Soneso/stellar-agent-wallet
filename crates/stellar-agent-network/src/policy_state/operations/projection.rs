//! The status selection and projection of one retained operation.
//!
//! Both read one authenticated window image and no network. The projection
//! carries stored facts only: no amount, no recovery outcome and no next
//! action.

use serde::Serialize;
use stellar_agent_core::error::{ValidationError, WalletError};

use super::{
    BusinessId, ExposureIdentity, OperationId, OperationResult, OperationState, OperationStatus,
    WireAttempt, WireOperation, now_ms, records, tombstones,
};
use crate::policy_state::WindowStoreError;
use crate::policy_state::approvals::ApprovalState;
use crate::policy_state::ledger::opt_hex32;
use crate::policy_state::store::WireFile;

/// The selectors of one status call, checked for shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusSelectors {
    /// The transaction hash; the caller has checked it is 64 lowercase hex
    /// characters.
    pub tx_hash: Option<String>,
    /// The business id.
    pub business_id: Option<BusinessId>,
}

impl StatusSelectors {
    /// Checks that at least one selector is present and parses the business id.
    ///
    /// # Errors
    ///
    /// `validation.usage_error` without either selector, and the
    /// [`BusinessId::parse`] codes for a malformed business id.
    pub fn parse(tx_hash: Option<&str>, business_id: Option<&str>) -> Result<Self, WalletError> {
        if tx_hash.is_none() && business_id.is_none() {
            return Err(ValidationError::StatusSelectors {
                detail: "name a transaction hash, a business_id, or both",
            }
            .into());
        }
        Ok(Self {
            tx_hash: tx_hash.map(str::to_owned),
            business_id: business_id.map(BusinessId::parse).transpose()?,
        })
    }
}

/// The operation a mainnet status call names and the hash its status targets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusTarget {
    /// The named operation; `None` for a hash that no retained operation exposed.
    pub operation_id: Option<OperationId>,
    /// The classic transaction hash that recovery and the chain read target;
    /// `None` when the operation retains no exposed classic attempt.
    pub tx_hash: Option<String>,
}

/// One attempt's stored state and exposed identity. Identity fields are
/// null before exposure and when the exposure kind lacks them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AttemptProjection {
    /// The attempt index, starting at 1.
    pub index: u32,
    /// The attempt's recorded outcome; an attempt without one is `sending`.
    pub state: OperationState,
    /// A classic exposure's network transaction hash.
    #[serde(serialize_with = "opt_hex32::serialize")]
    pub tx_hash: Option<[u8; 32]>,
    /// A classic exposure's sequence.
    pub sequence: Option<i64>,
    /// A classic exposure's `max_time` in Unix seconds; zero for none.
    pub max_time: Option<u64>,
    /// An x402 exposure's signed authorization entry digest.
    #[serde(serialize_with = "opt_hex32::serialize")]
    pub auth_entry_sha256: Option<[u8; 32]>,
}

/// The record's latest state change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TransitionProjection {
    /// The state the change entered.
    pub kind: OperationState,
    /// When the change was recorded, in Unix milliseconds.
    pub at_ms: u64,
    /// The primary ledger of the recovery decision that made the change.
    pub ledger_primary: Option<u32>,
    /// The witness ledger of the recovery decision that made the change.
    pub ledger_witness: Option<u32>,
}

/// Whether a spending-window hold the record references is still held.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct HoldProjection {
    /// Whether at least one referenced bucket hold remains in the window.
    pub held: bool,
}

/// The durable approval an operation waits for, by its public nonce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApprovalLink {
    /// The public approval id, which is the approval nonce.
    pub id: String,
    /// `pending`, `expired`, `consumed` or `revoked`.
    pub state: &'static str,
}

/// The stored status of one operation, from one authenticated image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OperationProjection {
    /// The business id.
    pub business_id: BusinessId,
    /// The operation's state.
    pub state: OperationState,
    /// Whether the record was compacted to a tombstone.
    pub compacted: bool,
    /// Every retained attempt in index order; empty for a tombstone.
    pub attempts: Vec<AttemptProjection>,
    /// The latest state change; `None` for a tombstone, which keeps no history.
    pub last_transition: Option<TransitionProjection>,
    /// The bucket hold; `None` for a tombstone.
    pub hold: Option<HoldProjection>,
    /// The linked durable approval, present only while awaiting approval.
    pub approval: Option<ApprovalLink>,
    /// The stored result summary.
    pub result: Option<OperationResult>,
}

fn classic_hash(attempt: &WireAttempt) -> Option<[u8; 32]> {
    match attempt.exposure.as_ref().map(|exposure| &exposure.identity) {
        Some(ExposureIdentity::Classic { tx_hash, .. }) => Some(*tx_hash),
        _ => None,
    }
}

fn attempt(attempt: &WireAttempt) -> AttemptProjection {
    let mut view = AttemptProjection {
        index: attempt.index,
        state: attempt.outcome.unwrap_or(OperationState::Sending),
        tx_hash: None,
        sequence: None,
        max_time: None,
        auth_entry_sha256: None,
    };
    match attempt.exposure.as_ref().map(|exposure| &exposure.identity) {
        Some(ExposureIdentity::Classic {
            tx_hash,
            sequence,
            max_time,
            ..
        }) => {
            view.tx_hash = Some(*tx_hash);
            view.sequence = Some(*sequence);
            view.max_time = Some(*max_time);
        }
        Some(ExposureIdentity::X402 {
            auth_entry_sha256, ..
        }) => view.auth_entry_sha256 = Some(*auth_entry_sha256),
        None => {}
    }
    view
}

fn last_transition(record: &WireOperation) -> Option<TransitionProjection> {
    let entry = record.history.last()?;
    let decision = record
        .current_attempt()
        .filter(|attempt| attempt.outcome == Some(entry.to))
        .and_then(|attempt| attempt.decision.as_ref());
    Some(TransitionProjection {
        kind: entry.to,
        at_ms: entry.at_ms,
        ledger_primary: decision.map(|decision| decision.primary_ledger),
        ledger_witness: decision.map(|decision| decision.witness_ledger),
    })
}

fn approval(wire: &WireFile, record: &WireOperation, now: u64) -> Option<ApprovalLink> {
    if record.state != OperationState::AwaitingApproval {
        return None;
    }
    let id = record.approval_record_id?;
    let stored = wire
        .approvals
        .as_ref()?
        .records
        .iter()
        .find(|approval| approval.id == id && approval.operation_id == record.id)?;
    let state = match stored.state {
        ApprovalState::Pending if stored.view(now).expired => "expired",
        ApprovalState::Pending => "pending",
        ApprovalState::Consumed => "consumed",
        ApprovalState::Revoked => "revoked",
    };
    Some(ApprovalLink {
        id: stored.nonce.clone(),
        state,
    })
}

fn project(wire: &WireFile, record: &WireOperation, now: u64) -> OperationProjection {
    OperationProjection {
        business_id: record.business_id.clone(),
        state: record.state,
        compacted: false,
        attempts: record.attempts.iter().map(attempt).collect(),
        last_transition: last_transition(record),
        hold: Some(HoldProjection {
            held: record.holds.iter().any(|held| {
                wire.holds.iter().any(|hold| {
                    hold.authorization_id == held.authorization_id && hold.ordinal == held.ordinal
                })
            }),
        }),
        approval: approval(wire, record, now),
        result: record.result.clone(),
    }
}

impl OperationStatus<'_> {
    /// Resolves `selectors` to one operation from one authenticated read.
    /// A business id selects its record, then its tombstone; a hash selects
    /// the record that exposed it, including an earlier attempt, or the
    /// tombstone whose result names it. With both, the hash must belong to
    /// the business id's operation. A business id alone targets the latest
    /// exposed classic attempt, and nothing when no attempt exposed one.
    ///
    /// # Errors
    ///
    /// `Ok(Err)` carries `operation.unknown` for an unknown business id and
    /// `validation.usage_error` for selectors naming different operations.
    /// The outer error is the verified window's integrity, keyring, clock
    /// and I/O error.
    pub fn select(
        &self,
        selectors: &StatusSelectors,
    ) -> Result<Result<StatusTarget, WalletError>, WindowStoreError> {
        let hash = selectors
            .tx_hash
            .as_deref()
            .and_then(|text| stellar_agent_core::hex::decode_hex32(text).ok());
        let wire = self.read()?;
        let records = wire.as_ref().map_or(&[][..], records);
        let tombstones = wire.as_ref().map_or(&[][..], tombstones);
        let (operation_id, exposed) = match &selectors.business_id {
            Some(business_id) => {
                if let Some(record) = records.iter().find(|r| &r.business_id == business_id) {
                    let hashes: Vec<_> = record.attempts.iter().filter_map(classic_hash).collect();
                    (record.id, hashes)
                } else if let Some(tombstone) =
                    tombstones.iter().find(|t| &t.business_id == business_id)
                {
                    let hash = tombstone.result.as_ref().and_then(|result| result.tx_hash);
                    (tombstone.id, hash.into_iter().collect())
                } else {
                    return Ok(Err(ValidationError::OperationUnknown.into()));
                }
            }
            None => {
                let operation_id = records
                    .iter()
                    .find(|r| {
                        r.attempts
                            .iter()
                            .any(|a| hash.is_some() && classic_hash(a) == hash)
                    })
                    .map(|record| record.id)
                    .or_else(|| {
                        tombstones
                            .iter()
                            .find(|t| {
                                hash.is_some() && t.result.as_ref().and_then(|r| r.tx_hash) == hash
                            })
                            .map(|tombstone| tombstone.id)
                    });
                return Ok(Ok(StatusTarget {
                    operation_id,
                    tx_hash: selectors.tx_hash.clone(),
                }));
            }
        };
        let tx_hash = match (&selectors.tx_hash, hash) {
            (Some(text), Some(hash)) if exposed.contains(&hash) => Some(text.clone()),
            (Some(_), _) => {
                return Ok(Err(ValidationError::StatusSelectors {
                    detail: "tx_hash and business_id name different operations",
                }
                .into()));
            }
            (None, _) if records.iter().any(|r| r.id == operation_id) => exposed
                .last()
                .map(|hash| stellar_agent_core::hex::encode(hash)),
            (None, _) => None,
        };
        Ok(Ok(StatusTarget {
            operation_id: Some(operation_id),
            tx_hash,
        }))
    }

    /// Projects the operation `id` names from one authenticated read, after
    /// the status call's reconciliation and repair.
    ///
    /// # Errors
    ///
    /// Every integrity, keyring, clock and I/O error of the verified read.
    pub fn projection(
        &self,
        id: &OperationId,
    ) -> Result<Option<OperationProjection>, WindowStoreError> {
        let Some(wire) = self.read()? else {
            return Ok(None);
        };
        let now = now_ms()?;
        if let Some(record) = records(&wire).iter().find(|record| &record.id == id) {
            return Ok(Some(project(&wire, record, now)));
        }
        Ok(tombstones(&wire)
            .iter()
            .find(|tombstone| &tombstone.id == id)
            .map(|tombstone| OperationProjection {
                business_id: tombstone.business_id.clone(),
                state: tombstone.state,
                compacted: true,
                attempts: Vec::new(),
                last_transition: None,
                hold: None,
                approval: None,
                result: tombstone.result.clone(),
            }))
    }
}
