//! Read-only recovery results from authenticated attempts and decisions.

use super::*;
use crate::policy_state::{CommittedDecision, OperationState};

/// An included transaction's authenticated outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum RecoveryInclusion {
    /// The transaction succeeded.
    Success,
    /// The transaction failed and charged its recorded fee.
    Failed,
}

/// Evidence collection advice; none of these actions authorizes a submission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum RecoveryAction {
    /// Inspect the transaction through targeted status.
    TargetedStatus,
    /// Wait for the reported eligibility time before targeted status.
    Wait,
    /// The reported configuration, record or evidence requires attention.
    EvidenceRequired,
    /// Every run is spent; targeted status with the explicit retry request
    /// starts one new bounded evidence run.
    RetryRecovery,
}

/// The chain result, independent of accounting expiry and receipt display data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "result")]
pub enum RecoveryResult {
    /// An authenticated included decision.
    Included {
        /// Success or failure as committed.
        status: RecoveryInclusion,
        /// The including ledger.
        ledger: u32,
    },
    /// An authenticated non-inclusion decision.
    NeverApplicable {
        /// The existing proof, without an invented interval binding.
        proof: NotIncludedProof,
    },
    /// Evidence remains unavailable.
    NeedsEvidence {
        /// The normalized typed cause.
        reason: RecoveryReason,
        /// Bounded context from the stop, when a request supplied it.
        missing: Option<RecoveryFailure>,
        /// Evidence collection advice.
        next_action: RecoveryAction,
    },
}

/// A safe refusal, without provider text, URLs or credentials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RecoveryRefusal {
    /// The original stable wire code.
    pub code: &'static str,
    /// Whether the authenticated state could not be read after the refusal.
    pub state_unavailable: bool,
}

impl From<RecoveryStopReason> for RecoveryReason {
    fn from(reason: RecoveryStopReason) -> Self {
        use RecoveryStopReason as R;
        match reason {
            R::AwaitingExpiry => Self::AwaitingExpiry,
            R::Untimed => Self::Untimed,
            R::ResponseTooLarge => Self::ResponseTooLarge,
            R::RateLimited => Self::RateLimited,
            R::Transport => Self::Transport,
            R::MissingField => Self::MissingField,
            R::Lagging => Self::Lagging,
            R::Deadline => Self::Deadline,
            R::RequestBudget => Self::RequestBudget,
            R::AccountUnavailable => Self::AccountUnavailable,
            R::CoverageRequired => Self::CoverageRequired,
            R::HistoryLost => Self::HistoryLost,
            R::MissingProvenance => Self::MissingProvenance,
            R::Disagreement => Self::Disagreement,
            R::ClockRegression => Self::ClockRegression,
            R::RecordUnusable => Self::RecordUnusable,
            R::Interrupted => Self::Interrupted,
            R::ConfigurationRequired => Self::ConfigurationRequired,
        }
    }
}

impl RecoveryAttemptResult {
    pub(super) fn project(
        attempt: &RecoveryAttempt,
        selectable: bool,
        decision: Option<CommittedDecision>,
        now: u64,
    ) -> Self {
        let ExposureIdentity::Classic {
            tx_hash, max_time, ..
        } = attempt.exposure
        else {
            unreachable!("the reporting snapshot selects classic exposures")
        };
        let run = attempt.recovery_run.as_ref().and_then(|r| r.record());
        let view = normalize_recovery_run(
            attempt.recovery_run.as_ref(),
            max_time,
            attempt.send_by_ms,
            decision.is_some(),
            now,
        );
        let reservations = if matches!(view.state, RecoveryRunState::RetriesExhausted { .. }) {
            Some(16)
        } else {
            run.map(|r| r.automatic_runs)
        };
        let mut entry = Self {
            operation_id: attempt.operation_id,
            attempt_index: attempt.attempt_index,
            tx_hash,
            history_start: attempt.pre_exposure_ledger,
            view,
            stop: run.and_then(|r| r.stop.clone()),
            reservations,
            next_unread: run.and_then(|r| r.scan.as_ref().map(|s| s.next_unread)),
            settlement: decision,
            result: RecoveryResult::NeedsEvidence {
                reason: RecoveryReason::RecoveryRequired,
                missing: None,
                next_action: RecoveryAction::TargetedStatus,
            },
            selectable,
        };
        entry.refresh_result();
        entry
    }

    pub(super) fn refresh_result(&mut self) {
        self.result = match self
            .settlement
            .as_ref()
            .map(|d| (d.state, d.ledger, d.not_included))
        {
            Some((
                state @ (OperationState::Succeeded | OperationState::Failed),
                Some(ledger),
                _,
            )) => RecoveryResult::Included {
                status: if state == OperationState::Failed {
                    RecoveryInclusion::Failed
                } else {
                    RecoveryInclusion::Success
                },
                ledger,
            },
            Some((OperationState::NotIncluded, _, Some(proof))) => {
                RecoveryResult::NeverApplicable { proof }
            }
            _ => RecoveryResult::NeedsEvidence {
                reason: match self.view.state {
                    RecoveryRunState::RecoveryRequired => RecoveryReason::RecoveryRequired,
                    RecoveryRunState::Running => RecoveryReason::Running,
                    RecoveryRunState::Stopped(reason) => reason.into(),
                    RecoveryRunState::RetriesExhausted { .. } => RecoveryReason::RetriesExhausted,
                    RecoveryRunState::Resolved => RecoveryReason::MissingField,
                },
                missing: self.stop.as_ref().and_then(|s| {
                    Some(RecoveryFailure {
                        reason: s.reason.into(),
                        endpoint: match s.roles.first()? {
                            RecoveryRole::Primary => RecoveryEndpoint::Primary,
                            RecoveryRole::Oracle => RecoveryEndpoint::Oracle,
                        },
                        method: match s.stage {
                            RecoveryStage::Identity => RecoveryMethod::GetNetwork,
                            RecoveryStage::Health => RecoveryMethod::GetHealth,
                            _ => match s.method? {
                                RecoveryRunMethod::GetTransaction => RecoveryMethod::GetTransaction,
                                RecoveryRunMethod::GetLedgers => RecoveryMethod::GetLedgers,
                                RecoveryRunMethod::GetLedgerEntries => {
                                    RecoveryMethod::GetLedgerEntries
                                }
                            },
                        },
                        ledger: s.ledger,
                    })
                }),
                // Only a selectable attempt gets a status action: the driver
                // never evaluates a cancelled or expired record's attempt.
                next_action: match self.view.class {
                    _ if !self.selectable => RecoveryAction::EvidenceRequired,
                    _ if self.view.state == RecoveryRunState::RecoveryRequired => {
                        RecoveryAction::TargetedStatus
                    }
                    _ if matches!(self.view.state, RecoveryRunState::RetriesExhausted { last_reason }
                        if last_reason != RecoveryStopReason::RecordUnusable)
                        && self
                            .stop
                            .as_ref()
                            .is_none_or(|s| s.class == RecoveryClass::Automatic) =>
                    {
                        RecoveryAction::RetryRecovery
                    }
                    Some(RecoveryClass::Explicit) => RecoveryAction::EvidenceRequired,
                    Some(RecoveryClass::Automatic) if self.view.earliest_retry_ms.is_some() => {
                        RecoveryAction::Wait
                    }
                    _ => RecoveryAction::TargetedStatus,
                },
            },
        };
    }

    /// A cached chain answer; scheduling and receipts never imply inclusion.
    #[must_use]
    pub fn chain_status(&self) -> (&'static str, Option<u32>) {
        match self.result {
            RecoveryResult::Included { status, ledger } => (
                match status {
                    RecoveryInclusion::Success => "SUCCESS",
                    RecoveryInclusion::Failed => "FAILED",
                },
                Some(ledger),
            ),
            RecoveryResult::NeverApplicable { .. } => ("NOT_FOUND", None),
            RecoveryResult::NeedsEvidence { .. } => ("UNKNOWN", None),
        }
    }
}

impl RecoveryReport {
    pub(crate) fn refresh_settlements(
        &mut self,
        status: &OperationStatus<'_>,
        hash: Option<&[u8; 32]>,
    ) {
        match status.committed_decisions(hash) {
            Ok(decisions) => {
                for entry in &mut self.attempts {
                    if let Some(decision) = decisions.iter().find(|d| {
                        d.operation_id == entry.operation_id
                            && d.attempt_index == entry.attempt_index
                            && d.tx_hash == entry.tx_hash
                    }) {
                        entry.settlement = Some(decision.clone());
                        entry.refresh_result();
                    }
                }
            }
            Err(error) => {
                self.refusal = Some(RecoveryRefusal {
                    code: error.submission_code(),
                    state_unavailable: true,
                })
            }
        }
    }

    pub(crate) fn read(
        status: &OperationStatus<'_>,
        hash: Option<&[u8; 32]>,
        now: u64,
    ) -> Result<Self, WindowStoreError> {
        let attempts = status.reporting_snapshot(hash)?;
        let decisions = status.committed_decisions(hash)?;
        Ok(Self {
            attempts: attempts
                .iter()
                .map(|(a, selectable)| {
                    let decision = decisions
                        .iter()
                        .find(|d| {
                            d.operation_id == a.operation_id
                                && d.attempt_index == a.attempt_index
                                && matches!(
                                    a.exposure,
                                    ExposureIdentity::Classic { tx_hash, .. } if tx_hash == d.tx_hash
                                )
                        })
                        .cloned();
                    RecoveryAttemptResult::project(a, *selectable, decision, now)
                })
                .collect(),
            ..Self::default()
        })
    }

    pub(crate) fn refused(
        status: &OperationStatus<'_>,
        hash: Option<&[u8; 32]>,
        code: &'static str,
    ) -> Self {
        let read = super::super::store::now_ms().and_then(|now| Self::read(status, hash, now));
        let unavailable = read.is_err();
        let mut report = read.unwrap_or_default();
        report.refusal = Some(RecoveryRefusal {
            code,
            state_unavailable: unavailable,
        });
        report
    }

    /// The recovery object that both status adapters render, absent when
    /// the report has no attempt and no refusal. Each attempt carries its
    /// typed result, its settlement commit identifier when a decision settles
    /// it, an exhausted attempt's underlying reason, retry class and earliest
    /// retry time; no field authorizes a submission or a successor.
    #[must_use]
    pub fn status_json(&self) -> Option<serde_json::Value> {
        #[derive(Serialize)]
        struct Attempt<'a> {
            operation_id: String,
            attempt_index: u32,
            tx_hash: String,
            #[serde(flatten)]
            result: &'a RecoveryResult,
            /// The commit identifier of the authenticated decision that settles it.
            settlement_commit_id: Option<String>,
            /// The underlying cause of an exhausted attempt.
            last_reason: Option<RecoveryReason>,
            class: Option<RecoveryClass>,
            earliest_retry_ms: Option<u64>,
            reservations: Option<u8>,
            next_unread: Option<u32>,
        }
        if self.attempts.is_empty() && self.refusal.is_none() {
            return None;
        }
        let attempts: Vec<_> = self
            .attempts
            .iter()
            .map(|a| Attempt {
                operation_id: a.operation_id.to_hex(),
                attempt_index: a.attempt_index,
                tx_hash: stellar_agent_core::hex::encode(&a.tx_hash),
                result: &a.result,
                settlement_commit_id: a.settlement.as_ref().map(|d| d.commit_id.to_hex()),
                last_reason: match a.view.state {
                    RecoveryRunState::RetriesExhausted { last_reason } => Some(last_reason.into()),
                    _ => None,
                },
                class: a.view.class,
                earliest_retry_ms: a.view.earliest_retry_ms,
                reservations: a.reservations,
                next_unread: a.next_unread,
            })
            .collect();
        Some(serde_json::json!({ "attempts": attempts, "refusal": self.refusal }))
    }
}
