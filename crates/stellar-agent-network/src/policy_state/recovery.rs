//! Bounded two-endpoint evidence for classic sequence availability.

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;
use sha2::{Digest, Sha256};
use stellar_agent_core::audit_log::AuditWriter;
use stellar_agent_core::error::WalletError;
use stellar_agent_core::policy::state_lock::WindowStoreLock;
use stellar_agent_core::profile::receipt::SequenceReleases;
use stellar_agent_core::profile::schema::Profile;
use stellar_rpc_client::{GetHealthResponse, GetLedgersResponse, LedgerStart};
use tokio::time::Instant;

use super::operations::{
    EvidenceAnswer, EvidenceEndpoint, EvidenceInput, EvidenceRowInput, ExposureIdentity,
    OperationId, OperationRecorder, OperationStatus, RecoveryAttempt, RecoveryUpdate,
    SequenceReleaseInput, WindowObservation,
};
use super::{PersistedWindowStore, WindowStoreError};
use crate::operational::OperationalReport;
use crate::{MainnetOracle, StellarRpcClient};

const ATTEMPT_REQUESTS: usize = 24;
const SHARED_REQUESTS: usize = 9;
const PASS_DURATION: Duration = Duration::from_secs(20);
const OBSERVATION_AGE: Duration = Duration::from_secs(5);
const PAGE_SIZE: usize = 200;

/// The primary endpoint and independent recovery oracle.
pub struct EndpointPair<'a> {
    primary: &'a StellarRpcClient,
    oracle: Option<&'a StellarRpcClient>,
}

impl std::fmt::Debug for EndpointPair<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EndpointPair")
            .field("oracle_configured", &self.oracle.is_some())
            .finish_non_exhaustive()
    }
}

impl<'a> EndpointPair<'a> {
    /// Pairs the primary client with the oracle the caller builds through
    /// [`crate::NetworkContext::oracle_client`] from the profile's oracle provider.
    /// Both stages receive the caller's clients, so construction sends no request.
    #[must_use]
    pub fn from_clients(
        primary: &'a StellarRpcClient,
        oracle: Option<&'a StellarRpcClient>,
    ) -> Self {
        Self { primary, oracle }
    }

    async fn verify(&self, budget: &mut Budget) -> Result<(), IdentityFailure> {
        let oracle = self
            .oracle
            .ok_or(IdentityFailure::Read(ReadFailure::Pending))?;
        let deadline = budget.deadline;
        budget
            .identity(self.primary.mainnet_endpoint_identity_once(deadline))
            .await?;
        budget
            .identity(MainnetOracle::verify_once(oracle, deadline))
            .await?;
        Ok(())
    }
}

/// Why a recovery pass refuses without committing.
#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    /// The window store refuses the snapshot or a commit.
    #[error(transparent)]
    Store(#[from] WindowStoreError),
    /// An endpoint reports another network or an unsupported protocol.
    #[error(transparent)]
    EndpointIdentity(WalletError),
}

impl RecoveryError {
    /// The stable error code of the refusal.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Store(error) => error.submission_code(),
            Self::EndpointIdentity(error) => error.code(),
        }
    }
}

#[derive(Debug)]
enum IdentityFailure {
    Read(ReadFailure),
    Refused(WalletError),
}

/// Whether an identity answer names another network or an unsupported protocol.
/// Transport failures stay retryable in a later pass.
fn identity_refusal(error: &WalletError) -> bool {
    use stellar_agent_core::error::{NetworkError, WitnessUnavailableReason};
    matches!(
        error,
        WalletError::Network(
            NetworkError::EndpointNetworkMismatch { .. }
                | NetworkError::UnsupportedProtocolVersion { .. }
                | NetworkError::WitnessUnavailable {
                    reason: WitnessUnavailableReason::IdentityNetworkMismatch { .. }
                        | WitnessUnavailableReason::IdentityProtocolUnsupported { .. }
                }
        )
    )
}

/// Request counts for the independent recovery allowances.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RecoveryRequests {
    /// Requests for attempt history, accounts and outcomes.
    pub attempt: usize,
    /// Identity, readiness and refresh requests shared across attempts.
    pub shared: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadFailure {
    Pending,
    Deadline,
}

struct Budget {
    used: RecoveryRequests,
    deadline: Instant,
}

impl Budget {
    fn new() -> Self {
        Self {
            used: RecoveryRequests::default(),
            deadline: Instant::now() + PASS_DURATION,
        }
    }

    /// Charges one request before its await.
    fn charge(&mut self, shared: bool) -> Result<(), ReadFailure> {
        if Instant::now() >= self.deadline {
            return Err(ReadFailure::Deadline);
        }
        let (used, capacity) = if shared {
            (&mut self.used.shared, SHARED_REQUESTS)
        } else {
            (&mut self.used.attempt, ATTEMPT_REQUESTS)
        };
        if *used >= capacity {
            return Err(ReadFailure::Pending);
        }
        *used += 1;
        Ok(())
    }

    async fn read<T, E>(
        &mut self,
        shared: bool,
        request: impl Future<Output = Result<T, E>>,
    ) -> Result<T, ReadFailure> {
        self.charge(shared)?;
        tokio::time::timeout_at(self.deadline, request)
            .await
            .map_err(|_| ReadFailure::Deadline)?
            .map_err(|_| ReadFailure::Pending)
    }

    async fn identity<T>(
        &mut self,
        request: impl Future<Output = Result<T, WalletError>>,
    ) -> Result<T, IdentityFailure> {
        self.charge(true).map_err(IdentityFailure::Read)?;
        match tokio::time::timeout_at(self.deadline, request).await {
            Err(_) => Err(IdentityFailure::Read(ReadFailure::Deadline)),
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) if identity_refusal(&error) => Err(IdentityFailure::Refused(error)),
            Ok(Err(_)) => Err(IdentityFailure::Read(ReadFailure::Pending)),
        }
    }
}

/// A canonical ledger answer, including explicit missing values.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct LedgerAnswer {
    /// The ledger that supplies the expiry observation.
    pub expiry_ledger: Option<u32>,
    /// Its close time in Unix seconds.
    pub close_time: Option<u64>,
    /// The endpoint's latest ledger.
    pub latest_ledger: Option<u32>,
}

impl LedgerAnswer {
    fn row(self, endpoint: EvidenceEndpoint, digest: [u8; 32]) -> Option<EvidenceRowInput> {
        Some(EvidenceRowInput {
            endpoint,
            observed_ledger: self.latest_ledger?,
            answer: EvidenceAnswer::Ledger {
                expiry_ledger: self.expiry_ledger?,
                close_time: self.close_time?,
                latest_ledger: self.latest_ledger?,
            },
            digest,
        })
    }
}

fn answer_digest(answers: &[LedgerAnswer; 2]) -> Result<[u8; 32], WindowStoreError> {
    serde_json::to_vec(answers)
        .map(|bytes| Sha256::digest(bytes).into())
        .map_err(|_| WindowStoreError::Invalid {
            detail: "ledger evidence cannot be serialized".to_owned(),
        })
}

struct SharedObservation {
    health: GetHealthResponse,
    report: OperationalReport,
    oldest: u32,
    read_at: Instant,
}

impl SharedObservation {
    fn stale(&self) -> bool {
        self.read_at.elapsed() > OBSERVATION_AGE
    }

    fn window(&self, now_ms: u64) -> WindowObservation {
        WindowObservation {
            ledger: self.report.latest_ledger,
            close_time_floor_ms: self.report.close_time_unix.saturating_mul(1_000),
            observed_at_ms: now_ms,
        }
    }
}

async fn shared_observation(
    client: &StellarRpcClient,
    budget: &mut Budget,
    now_ms: u64,
    health: Option<GetHealthResponse>,
) -> Result<SharedObservation, ReadFailure> {
    let read_at = Instant::now();
    let deadline = budget.deadline;
    let mut refused = None;
    let read = crate::operational::single_readiness(
        client,
        deadline,
        health,
        || Ok(now_ms / 1_000),
        &mut || match budget.charge(true) {
            Ok(()) => true,
            Err(failure) => {
                refused = Some(failure);
                false
            }
        },
    )
    .await;
    match read {
        Ok(read) => Ok(SharedObservation {
            health: read.health,
            report: read.report,
            oldest: read.oldest_ledger,
            read_at,
        }),
        Err(_) => Err(refused.unwrap_or(if Instant::now() >= deadline {
            ReadFailure::Deadline
        } else {
            ReadFailure::Pending
        })),
    }
}

#[derive(Debug)]
struct Scan {
    answer: LedgerAnswer,
    cursor: u32,
    upper: Option<u32>,
    incomplete: bool,
    entries: Vec<(u32, u64)>,
}

fn scan_page(page: &GetLedgersResponse, cursor: u32, max_time: u64) -> Option<Scan> {
    let start = cursor.max(page.oldest_ledger);
    let mut next = start;
    let mut last_close = 0;
    let mut entries = Vec::new();
    let mut boundary = None;
    if page.ledgers.is_empty() || page.ledgers.len() > PAGE_SIZE {
        return None;
    }
    for ledger in &page.ledgers {
        let close = ledger.ledger_close_time.parse::<u64>().ok()?;
        if ledger.sequence != next || close == 0 || close < last_close {
            return None;
        }
        entries.push((ledger.sequence, close));
        if max_time > 0 && close > max_time && boundary.is_none() {
            boundary = Some((ledger.sequence, close));
        }
        next = next.checked_add(1)?;
        last_close = close;
    }
    let last = *entries.last()?;
    if page.latest_ledger < last.0
        || (page.ledgers.len() < PAGE_SIZE && last.0 != page.latest_ledger)
    {
        return None;
    }
    let deciding = boundary.unwrap_or(last);
    Some(Scan {
        answer: LedgerAnswer {
            expiry_ledger: Some(deciding.0),
            close_time: Some(deciding.1),
            latest_ledger: Some(page.latest_ledger),
        },
        cursor: boundary.map_or(next, |entry| entry.0),
        upper: boundary.map(|entry| entry.0),
        incomplete: page.oldest_ledger > cursor,
        entries,
    })
}

async fn history(
    client: &StellarRpcClient,
    shared: &SharedObservation,
    budget: &mut Budget,
    attempt: &RecoveryAttempt,
    primary: bool,
) -> Result<Option<Scan>, ReadFailure> {
    let saved = &attempt.recovery;
    let (cursor, upper) = if primary {
        (saved.primary_cursor, saved.primary_upper)
    } else {
        (saved.witness_cursor, saved.witness_upper)
    };
    let cursor = upper
        .or(cursor)
        .or(attempt.pre_exposure_ledger)
        .unwrap_or(shared.report.latest_ledger);
    let start = cursor.max(shared.oldest);
    let ExposureIdentity::Classic { max_time, .. } = attempt.exposure else {
        return Ok(None);
    };
    let result = budget
        .read(false, async {
            Ok::<_, ()>(
                client
                    .inner
                    .get_ledgers(LedgerStart::Ledger(start), Some(PAGE_SIZE), None)
                    .await,
            )
        })
        .await?;
    match result {
        Ok(page) => Ok(scan_page(&page, cursor, max_time)),
        Err(stellar_rpc_client::Error::JsonRpc(jsonrpsee_core::ClientError::ParseError(_))) => {
            Ok(None)
        }
        Err(_) => Err(ReadFailure::Pending),
    }
}

fn pending(attempt: &RecoveryAttempt, now_ms: u64, class: &str, detail: &str) -> EvidenceInput {
    EvidenceInput {
        recovery: Some(RecoveryUpdate {
            last_pass_at_ms: Some(now_ms),
            last_outcome: Some(class.to_owned()),
            diagnostic: Some(detail.to_owned()),
            ..attempt.recovery.clone()
        }),
        ..EvidenceInput::default()
    }
}

fn evaluate(
    attempt: &RecoveryAttempt,
    primary: Option<&Scan>,
    oracle: Option<&Scan>,
    now_ms: u64,
    detail: &str,
) -> Result<EvidenceInput, WindowStoreError> {
    let mut input = pending(attempt, now_ms, "evidence_pending", detail);
    let mut update = input.recovery.take().unwrap_or_default();
    update.history_incomplete |= attempt.pre_exposure_ledger.is_none();
    for (scan, is_primary) in [(primary, true), (oracle, false)] {
        if let Some(scan) = scan {
            update.history_incomplete |= scan.incomplete;
            if is_primary {
                update.primary_cursor = Some(scan.cursor);
                update.primary_upper = scan.upper.or(update.primary_upper);
            } else {
                update.witness_cursor = Some(scan.cursor);
                update.witness_upper = scan.upper.or(update.witness_upper);
            }
        }
    }
    let mut answers = [
        primary.map_or_default(|scan| scan.answer),
        oracle.map_or_default(|scan| scan.answer),
    ];
    if let (Some(primary), Some(oracle)) = (primary, oracle) {
        let mismatch = primary.entries.iter().find_map(|&(ledger, close)| {
            oracle
                .entries
                .iter()
                .find(|entry| entry.0 == ledger && entry.1 != close)
                .map(|entry| (ledger, close, entry.1))
        });
        if let Some((ledger, left, right)) = mismatch {
            answers[0].expiry_ledger = Some(ledger);
            answers[0].close_time = Some(left);
            answers[1].expiry_ledger = Some(ledger);
            answers[1].close_time = Some(right);
            update.disagreements = update.disagreements.saturating_add(1);
            update.last_outcome = Some("disagreement".to_owned());
            update.diagnostic = Some("close_time_mismatch".to_owned());
        } else if let (Some(primary_ledger), Some(witness_ledger), Some(left), Some(right)) = (
            primary.upper,
            oracle.upper,
            primary.answer.close_time,
            oracle.answer.close_time,
        ) {
            input.sequence_released = Some(SequenceReleaseInput {
                primary_ledger,
                witness_ledger,
                min_close_time_ms: left.min(right).saturating_mul(1_000),
            });
            update.disagreements = 0;
            update.last_outcome = Some("concurring".to_owned());
            update.diagnostic = None;
        }
    }
    let digest = answer_digest(&answers)?;
    input.rows = [
        answers[0].row(EvidenceEndpoint::Primary, digest),
        answers[1].row(EvidenceEndpoint::Witness, digest),
    ]
    .into_iter()
    .flatten()
    .collect();
    input.recovery = Some(update);
    Ok(input)
}

/// Results of a bounded recovery pass, separate from legacy reconciliation counts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RecoveryReport {
    /// Requests issued under each allowance.
    pub requests: RecoveryRequests,
    /// Attempts whose evaluation commits.
    pub evaluated: usize,
}

#[derive(Default)]
struct Batch {
    inputs: Vec<(OperationId, u32, EvidenceInput)>,
    observation: Option<WindowObservation>,
    requests: RecoveryRequests,
}

async fn collect(
    pair: &EndpointPair<'_>,
    attempts: &[RecoveryAttempt],
    now_ms: u64,
) -> Result<Batch, RecoveryError> {
    let mut budget = Budget::new();
    let mut batch = Batch::default();
    let verified = match pair.verify(&mut budget).await {
        Ok(()) => true,
        Err(IdentityFailure::Refused(error)) => return Err(RecoveryError::EndpointIdentity(error)),
        Err(IdentityFailure::Read(ReadFailure::Deadline)) => {
            batch.requests = budget.used;
            return Ok(batch);
        }
        Err(IdentityFailure::Read(ReadFailure::Pending)) => false,
    };
    let mut primary = None;
    let mut oracle = None;
    if verified {
        match shared_observation(pair.primary, &mut budget, now_ms, None).await {
            Ok(observation) => {
                batch.observation = Some(observation.window(now_ms));
                primary = Some(observation);
            }
            Err(ReadFailure::Deadline) => {
                batch.requests = budget.used;
                return Ok(batch);
            }
            Err(ReadFailure::Pending) => {}
        }
        if let Some(client) = pair.oracle.filter(|_| primary.is_some()) {
            match shared_observation(client, &mut budget, now_ms, None).await {
                Ok(observation) => oracle = Some(observation),
                Err(ReadFailure::Deadline) => {
                    batch.requests = budget.used;
                    return Ok(batch);
                }
                Err(ReadFailure::Pending) => {}
            }
        }
    }
    let mut refreshed = false;
    for attempt in attempts.iter().take(4) {
        if Instant::now() >= budget.deadline {
            break;
        }
        let mut seeded = attempt.clone();
        for (shared, cursor) in [
            (&primary, &mut seeded.recovery.primary_cursor),
            (&oracle, &mut seeded.recovery.witness_cursor),
        ] {
            if let Some(shared) = shared {
                let start = *cursor.get_or_insert(
                    attempt
                        .pre_exposure_ledger
                        .unwrap_or(shared.report.latest_ledger),
                );
                seeded.recovery.history_incomplete |=
                    shared.oldest > start || attempt.pre_exposure_ledger.is_none();
            }
        }
        let expected_attempt = attempt.clone();
        let attempt = &seeded;
        let mut detail = "endpoint_unreachable";
        let mut scans = (None, None);
        if let (Some(left), Some(right), Some(client)) = (&primary, &oracle, pair.oracle)
            && (left.stale() || right.stale())
            && !refreshed
        {
            refreshed = true;
            let health = right.health.clone();
            match shared_observation(pair.primary, &mut budget, now_ms, None).await {
                Ok(observation) => {
                    batch.observation = Some(observation.window(now_ms));
                    primary = Some(observation);
                }
                Err(ReadFailure::Deadline) => break,
                Err(ReadFailure::Pending) => primary = None,
            }
            match shared_observation(client, &mut budget, now_ms, Some(health)).await {
                Ok(observation) => oracle = Some(observation),
                Err(ReadFailure::Deadline) => break,
                Err(ReadFailure::Pending) => oracle = None,
            }
        }
        if let (Some(left), Some(right), Some(client)) = (&primary, &oracle, pair.oracle) {
            if left.stale() || right.stale() {
                detail = "stale_observation";
            } else {
                let left = history(pair.primary, left, &mut budget, attempt, true).await;
                if matches!(left, Err(ReadFailure::Deadline)) {
                    break;
                }
                let right = history(client, right, &mut budget, attempt, false).await;
                if matches!(right, Err(ReadFailure::Deadline)) {
                    break;
                }
                detail = if matches!(left, Ok(None)) || matches!(right, Ok(None)) {
                    "malformed_history"
                } else if left.is_err() || right.is_err() {
                    "endpoint_unreachable"
                } else {
                    "expiry_boundary_pending"
                };
                scans = (left.ok().flatten(), right.ok().flatten());
            }
        }
        let mut input = if pair.oracle.is_none() {
            pending(
                attempt,
                now_ms,
                "witness_unconfigured",
                "witness_unconfigured",
            )
        } else {
            evaluate(attempt, scans.0.as_ref(), scans.1.as_ref(), now_ms, detail)?
        };
        input.expected_attempt = Some(expected_attempt);
        input.observation = batch.observation;
        batch
            .inputs
            .push((attempt.operation_id, attempt.attempt_index, input));
    }
    batch.requests = budget.used;
    Ok(batch)
}

/// Runs recovery from a verified snapshot and commits through the operation facade.
/// A hash limits evaluation to its matching classic attempt.
///
/// # Errors
/// Returns snapshot, audit and commit errors without releasing any unsupported sequence.
/// An endpoint on another network or protocol refuses the pass before any commit.
pub async fn recover_sequences(
    store: &PersistedWindowStore,
    profile: &Profile,
    pair: EndpointPair<'_>,
    writer: &Arc<Mutex<AuditWriter>>,
    tx_hash: Option<&[u8; 32]>,
) -> Result<RecoveryReport, RecoveryError> {
    let attempts = OperationStatus::new(store, profile).recovery_snapshot(tx_hash)?;
    // An idle stage sends no request and records no observation: the legacy
    // stage before it hands over none.
    if !profile.chain_id.is_mainnet() || attempts.is_empty() {
        return Ok(RecoveryReport::default());
    }
    let now_ms = super::store::now_ms()?;
    let batch = collect(&pair, &attempts, now_ms).await?;
    let mut writer = writer.lock().map_err(|_| WindowStoreError::Invalid {
        detail: "audit writer mutex is poisoned".to_owned(),
    })?;
    let mut recorder = OperationRecorder::new(
        store,
        profile,
        &mut *writer,
        uuid::Uuid::new_v4().to_string(),
    );
    Ok(commit_batch(&mut recorder, batch)?)
}

fn commit_batch(
    recorder: &mut OperationRecorder<'_>,
    mut batch: Batch,
) -> Result<RecoveryReport, WindowStoreError> {
    if let Some((_, _, input)) = batch.inputs.last_mut() {
        input.observation = batch.observation;
    }
    let report = RecoveryReport {
        requests: batch.requests,
        evaluated: batch.inputs.len(),
    };
    if batch.inputs.is_empty() {
        if let Some(observation) = batch.observation {
            recorder.record_observation(observation)?;
        }
    } else {
        for (id, index, input) in batch.inputs {
            recorder.record_evidence(id, index, &input)?;
        }
    }
    Ok(report)
}

/// Runs `claim` under the window lock with the committed sequence releases.
/// The `_writer` borrow proves the caller holds the audit writer guard, so
/// the order stays writer, window, then the receipt lock `claim` takes.
pub(crate) fn with_sequence_releases<T>(
    store: &PersistedWindowStore,
    profile: &Profile,
    _writer: &AuditWriter,
    claim: impl FnOnce(&dyn SequenceReleases) -> T,
) -> Result<T, WindowStoreError> {
    store.ensure_parent_dir()?;
    let _window =
        WindowStoreLock::acquire_for_with_retry(store.path(), &profile.policy_window_state_key_id)?;
    let status = OperationStatus::new(store, profile);
    Ok(claim(&status))
}

/// Independent submission provenance and the primary accounting observation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SubmissionObservation {
    /// The minimum latest ledger, absent when either endpoint read fails.
    pub pre_exposure_ledger: Option<u32>,
    /// The valid primary observation, independent of oracle availability.
    pub observation: Option<WindowObservation>,
}

/// Reuses primary readiness when supplied and reads one oracle ledger.
/// The oracle ledger read starts at the oracle's own latest ledger, so an
/// oracle behind the primary still yields its bound.
/// An unavailable read leaves its optional provenance absent.
pub async fn submission_observation(
    primary: &StellarRpcClient,
    oracle: Option<&StellarRpcClient>,
    report: Option<&OperationalReport>,
    deadline: Instant,
) -> SubmissionObservation {
    let primary = match report {
        Some(report) => Some(report.clone()),
        None => crate::operational::operational_check(primary, deadline)
            .await
            .ok(),
    };
    let Some(primary) = primary else {
        return SubmissionObservation::default();
    };
    let observation = super::store::now_ms()
        .ok()
        .map(|observed_at_ms| WindowObservation {
            ledger: primary.latest_ledger,
            close_time_floor_ms: primary.close_time_unix.saturating_mul(1_000),
            observed_at_ms,
        });
    let oracle = match oracle {
        Some(client) => oracle_latest_ledger(client, deadline).await,
        None => None,
    };
    SubmissionObservation {
        pre_exposure_ledger: oracle.map(|ledger| primary.latest_ledger.min(ledger)),
        observation,
    }
}

/// The deadline of the submission's oracle bound read.
///
/// The read takes at most half of `authorization`'s remaining lifetime and at
/// most the one-ledger read timeout, so a slow oracle leaves the
/// authorization the rest of its lifetime for signing and the send.
/// Without mainnet writes no authorization exists, so the read gets no time.
#[must_use]
pub fn bound_read_deadline(
    authorization: &crate::mainnet::authorization::MainnetTxSignAuthorization,
) -> Instant {
    #[cfg(feature = "mainnet-write")]
    {
        let remaining_ms = crate::mainnet::clock::now_ms().map_or(0, |now_ms| {
            authorization.0.header.expires_at_ms.saturating_sub(now_ms)
        });
        let share = Duration::from_millis(remaining_ms / 2);
        Instant::now() + share.min(crate::operational::LEDGER_READ_TIMEOUT)
    }
    #[cfg(not(feature = "mainnet-write"))]
    {
        let _ = authorization;
        Instant::now()
    }
}

/// Reads the oracle's latest ledger, then one ledger from it.
async fn oracle_latest_ledger(client: &StellarRpcClient, deadline: Instant) -> Option<u32> {
    let latest = tokio::time::timeout_at(deadline, client.inner.get_latest_ledger())
        .await
        .ok()?
        .ok()?;
    let answer = tokio::time::timeout_at(
        deadline,
        client
            .inner
            .get_ledgers(LedgerStart::Ledger(latest.sequence), Some(1), None),
    )
    .await
    .ok()?
    .ok()?;
    (answer.latest_ledger > 0 && answer.oldest_ledger <= answer.latest_ledger)
        .then_some(answer.latest_ledger)
}

/// Claims a fixture authorization through the store's normal validation.
///
/// # Errors
/// Returns the store's authorization refusal or persistence error.
#[cfg(all(feature = "mainnet-write", feature = "test-helpers"))]
#[doc(hidden)]
pub fn claim_fixture_authorization(
    store: &PersistedWindowStore,
    profile: &Profile,
    request: &super::MintRequest,
    minted: &super::MintedRecord,
) -> Result<(), WindowStoreError> {
    store
        .claim_authorization(
            profile,
            minted.id,
            &super::ClaimExpect {
                domain: request.binding.domain(),
                consumer: request.consumer,
                bindings_digest: minted.bindings_digest,
                policy_sequence: request.policy_sequence,
                policy_digest: request.policy_digest,
                authority: request.authority.clone(),
            },
        )
        .map(|_| ())
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test assertions"
    )]

    use super::super::operations::tests::{Fx, unknown_named};
    #[cfg(feature = "mainnet-write")]
    use super::super::operations::tests::{Sink, unknown_with};
    use super::*;
    use serde_json::json;
    use stellar_agent_core::audit_log::schema::EventKind;
    use stellar_agent_test_support::{EchoIdResponder, rpc_request_count};
    use wiremock::matchers::{body_partial_json, method};
    use wiremock::{Mock, MockServer};

    const NOW: u64 = 1_800_000_000_000;

    fn attempt(max_time: u64) -> RecoveryAttempt {
        RecoveryAttempt {
            operation_id: OperationId::from_bytes([1; 16]),
            attempt_index: 1,
            exposure: ExposureIdentity::Classic {
                envelope_sha256: [2; 32],
                tx_hash: [3; 32],
                sequence: 7,
                max_time,
                receipt: "02".repeat(32),
            },
            started_at_ms: NOW - 100_000,
            send_by_ms: NOW - 1,
            pre_exposure_ledger: Some(1),
            recovery: RecoveryUpdate::default(),
            sequence_released: false,
            reservation_present: false,
        }
    }

    fn page(start: u32, count: u32, latest: u32, close: u64) -> GetLedgersResponse {
        serde_json::from_value(page_json(start, count, latest, close)).unwrap()
    }

    fn page_json(start: u32, count: u32, latest: u32, close: u64) -> serde_json::Value {
        json!({
            "latestLedger": latest, "latestLedgerCloseTime": close.to_string(),
            "oldestLedger": 1, "oldestLedgerCloseTime": 1, "cursor": latest.to_string(),
            "ledgers": (start..start + count).map(|sequence| json!({
                "sequence": sequence, "ledgerCloseTime": close.to_string(),
                "hash": "00".repeat(32), "headerXdr": "", "metadataXdr": "",
            })).collect::<Vec<_>>(),
        })
    }

    fn deciding(ledger: u32, close: u64, max_time: u64) -> Scan {
        scan_page(&page(ledger, 1, ledger, close), ledger, max_time).unwrap()
    }

    #[test]
    fn recovery_equal_zero_and_host_clock_expiry_keep_the_sequence() {
        for (max_time, close, now) in [(10, 10, NOW), (0, 11, NOW), (20, 10, u64::MAX)] {
            let scan = deciding(1, close, max_time);
            let input =
                evaluate(&attempt(max_time), Some(&scan), Some(&scan), now, "pending").unwrap();
            assert!(input.sequence_released.is_none());
            assert_eq!(
                input.recovery.unwrap().last_outcome.as_deref(),
                Some("evidence_pending")
            );
        }
    }

    #[test]
    fn recovery_close_time_mismatch_is_disagreement_and_changes_nothing() {
        let mut attempt = attempt(10);
        for counter in [0, 254, 255] {
            attempt.recovery.disagreements = counter;
            let input = evaluate(
                &attempt,
                Some(&deciding(7, 11, 10)),
                Some(&deciding(7, 12, 10)),
                NOW,
                "pending",
            )
            .unwrap();
            assert!(input.sequence_released.is_none());
            assert_eq!(input.rows.len(), 2);
            let recovery = input.recovery.unwrap();
            assert_eq!(recovery.disagreements, counter.saturating_add(1));
            assert_eq!(recovery.last_outcome.as_deref(), Some("disagreement"));
            assert_eq!(recovery.diagnostic.as_deref(), Some("close_time_mismatch"));
        }
    }

    #[test]
    fn recovery_concurrence_resets_the_counter_and_releases_at_zero() {
        for counter in [0, 7] {
            let mut attempt = attempt(10);
            attempt.recovery.disagreements = counter;
            let input = evaluate(
                &attempt,
                Some(&deciding(7, 11, 10)),
                Some(&deciding(9, 12, 10)),
                NOW,
                "pending",
            )
            .unwrap();
            assert_eq!(
                input.sequence_released,
                Some(SequenceReleaseInput {
                    primary_ledger: 7,
                    witness_ledger: 9,
                    min_close_time_ms: 11_000
                })
            );
            assert_eq!(input.recovery.unwrap().disagreements, 0);
        }
    }

    #[test]
    fn recovery_non_disagreement_passes_leave_the_counter() {
        let mut attempt = attempt(10);
        attempt.recovery.disagreements = 7;
        let scan = deciding(7, 10, 10);
        for detail in [
            "expiry_boundary_pending",
            "malformed_history",
            "endpoint_unreachable",
            "stale_observation",
        ] {
            let input = evaluate(&attempt, Some(&scan), None, NOW, detail).unwrap();
            assert!(input.sequence_released.is_none());
            assert_eq!(input.recovery.unwrap().disagreements, 7);
        }
    }

    #[test]
    fn recovery_scan_continues_until_boundary() {
        for boundary in [199, 200, 201] {
            let mut first = page(1, 200, 201, 10);
            for ledger in &mut first.ledgers {
                if ledger.sequence >= boundary {
                    ledger.ledger_close_time = "11".to_owned();
                }
            }
            let scan = scan_page(&first, 1, 10).unwrap();
            if boundary <= 200 {
                assert_eq!(scan.upper, Some(boundary));
            } else {
                assert_eq!(scan.upper, None);
                assert_eq!(scan.cursor, 201);
                let next = scan_page(&page(201, 1, 201, 11), scan.cursor, 10).unwrap();
                assert_eq!(next.upper, Some(201));
            }
        }
    }

    #[test]
    fn recovery_history_page_malformed_keeps_cursor() {
        let mut attempt = attempt(10);
        attempt.recovery.primary_cursor = Some(1);
        attempt.recovery.disagreements = 9;
        for defect in 0..7 {
            let mut page = page(1, 3, 3, 11);
            match defect {
                0 => page.ledgers[1].sequence = 3,
                1 => page.ledgers[1].sequence = 1,
                2 => page.ledgers.swap(0, 1),
                3 => page.ledgers[0].ledger_close_time = "0".to_owned(),
                4 => page.ledgers[0].ledger_close_time.clear(),
                5 => page.latest_ledger = 4,
                _ => page.ledgers[2].ledger_close_time = "10".to_owned(),
            }
            assert!(scan_page(&page, 1, 10).is_none());
            let input = evaluate(&attempt, None, None, NOW, "malformed_history").unwrap();
            let recovery = input.recovery.unwrap();
            assert_eq!(recovery.primary_cursor, Some(1));
            assert_eq!(recovery.disagreements, 9);
        }
    }

    #[test]
    fn recovery_pruning_never_proves_expiry() {
        for close in [9, 10] {
            for oldest in [2, 10, 20] {
                let mut page = page(oldest, 1, oldest, close);
                page.oldest_ledger = oldest;
                let scan = scan_page(&page, 1, 10).unwrap();
                assert!(scan.incomplete);
                assert!(scan.upper.is_none());
                let input =
                    evaluate(&attempt(10), Some(&scan), Some(&scan), NOW, "pending").unwrap();
                assert!(input.sequence_released.is_none());
                assert!(input.recovery.unwrap().history_incomplete);
            }
        }
    }

    #[test]
    fn recovery_no_provenance_uses_the_first_observed_upper_bound() {
        let mut attempt = attempt(10);
        attempt.pre_exposure_ledger = None;
        let scan = deciding(70, 11, 10);
        let input = evaluate(&attempt, Some(&scan), Some(&scan), NOW, "pending").unwrap();
        let recovery = input.recovery.unwrap();
        assert!(recovery.history_incomplete);
        assert_eq!(recovery.primary_upper, Some(70));
        assert_eq!(input.sequence_released.unwrap().primary_ledger, 70);
    }

    #[test]
    fn recovery_ledger_answer_canonical_vectors() {
        let answers = [
            LedgerAnswer {
                expiry_ledger: Some(7),
                close_time: Some(10),
                latest_ledger: Some(9),
            },
            LedgerAnswer::default(),
        ];
        assert_eq!(
            serde_json::to_string(&answers).unwrap(),
            r#"[{"expiry_ledger":7,"close_time":10,"latest_ledger":9},{"expiry_ledger":null,"close_time":null,"latest_ledger":null}]"#
        );
        assert_eq!(
            stellar_agent_core::hex::encode(&answer_digest(&answers).unwrap()),
            "ffa0532326f701ffa57b975a57b00a02138e71e59ad2e606d148613b79bbfbd0"
        );
    }

    fn stored_attempt(fx: &mut Fx) -> RecoveryAttempt {
        unknown_named(fx, 1);
        OperationStatus::new(&fx.store, &fx.profile)
            .recovery_snapshot(None)
            .unwrap()
            .remove(0)
    }

    fn release_input(attempt: &RecoveryAttempt) -> EvidenceInput {
        evaluate(
            attempt,
            Some(&deciding(7, 11, 10)),
            Some(&deciding(9, 12, 10)),
            NOW,
            "pending",
        )
        .unwrap()
    }

    #[test]
    #[serial_test::serial]
    fn recovery_stale_snapshot_cannot_replace_a_newer_commit() {
        let mut fx = Fx::new();
        let original = stored_attempt(&mut fx);
        let mut diagnostic = pending(&original, NOW, "evidence_pending", &"x".repeat(1_000));
        diagnostic.expected_attempt = Some(original.clone());
        fx.recorder()
            .record_evidence(original.operation_id, 1, &diagnostic)
            .unwrap();
        let original = OperationStatus::new(&fx.store, &fx.profile)
            .recovery_snapshot(None)
            .unwrap()
            .remove(0);
        assert!(original.recovery.diagnostic.as_ref().unwrap().len() < 1_000);
        let mut mismatch = evaluate(
            &original,
            Some(&deciding(7, 11, 10)),
            Some(&deciding(7, 12, 10)),
            NOW,
            "pending",
        )
        .unwrap();
        mismatch.expected_attempt = Some(original.clone());
        fx.recorder()
            .record_evidence(original.operation_id, 1, &mismatch)
            .unwrap();
        let after = std::fs::read(fx.store.path()).unwrap();
        let rows = fx.sink.entries.len();
        assert!(
            fx.recorder()
                .record_evidence(original.operation_id, 1, &mismatch)
                .is_err()
        );
        assert_eq!(std::fs::read(fx.store.path()).unwrap(), after);
        assert_eq!(fx.sink.entries.len(), rows);
        let fresh = OperationStatus::new(&fx.store, &fx.profile)
            .recovery_snapshot(None)
            .unwrap()
            .remove(0);
        assert_eq!(fresh.recovery.disagreements, 1);
        let mut release = release_input(&fresh);
        release.expected_attempt = Some(fresh.clone());
        let mut stale = pending(&fresh, NOW, "evidence_pending", "endpoint_unreachable");
        stale.expected_attempt = Some(fresh);
        fx.recorder()
            .record_evidence(original.operation_id, 1, &release)
            .unwrap();
        let after = std::fs::read(fx.store.path()).unwrap();
        let rows = fx.sink.entries.len();
        assert!(
            fx.recorder()
                .record_evidence(original.operation_id, 1, &stale)
                .is_err()
        );
        assert_eq!(std::fs::read(fx.store.path()).unwrap(), after);
        assert_eq!(fx.sink.entries.len(), rows);
    }

    #[test]
    #[serial_test::serial]
    fn recovery_interrupted_batch_keeps_the_latest_observation() {
        let mut fx = Fx::new();
        let attempt = stored_attempt(&mut fx);
        let old = WindowObservation {
            ledger: 7,
            close_time_floor_ms: NOW,
            observed_at_ms: NOW,
        };
        let latest = WindowObservation {
            ledger: 9,
            close_time_floor_ms: NOW + 1_000,
            observed_at_ms: NOW,
        };
        let mut input = pending(&attempt, NOW, "evidence_pending", "expiry_boundary_pending");
        input.observation = Some(old);
        input.expected_attempt = Some(attempt.clone());
        fx.sink.entries.clear();
        let batch = Batch {
            inputs: vec![(attempt.operation_id, 1, input)],
            observation: Some(latest),
            ..Batch::default()
        };
        assert_eq!(
            commit_batch(&mut fx.recorder(), batch).unwrap().evaluated,
            1
        );
        assert_eq!(fx.wire().last_observation, Some(latest));
        assert!(fx.sink.entries.is_empty());
    }

    #[test]
    #[serial_test::serial]
    fn recovery_sequence_release_audited_without_new_rows() {
        let mut fx = Fx::new();
        let attempt = stored_attempt(&mut fx);
        let input = release_input(&attempt);
        let mut rows_only = input.clone();
        rows_only.sequence_released = None;
        fx.recorder()
            .record_evidence(attempt.operation_id, 1, &rows_only)
            .unwrap();
        fx.sink.entries.clear();
        let commit = fx
            .recorder()
            .record_evidence(attempt.operation_id, 1, &input)
            .unwrap()
            .unwrap();
        assert_eq!(fx.sink.entries.len(), 1);
        let EventKind::OperationEvidence {
            evidence_seqs,
            sequence_released,
            commit_id,
            primary_ledger,
            witness_ledger,
            min_close_time_ms,
            ..
        } = &fx.sink.entries[0].event_kind
        else {
            panic!("evidence audit required")
        };
        assert_eq!(*evidence_seqs, None);
        assert!(*sequence_released);
        assert_eq!(commit_id, &commit.to_hex());
        assert_eq!(
            (*primary_ledger, *witness_ledger, *min_close_time_ms),
            (Some(7), Some(9), Some(11_000))
        );
        let proof = fx.record(attempt.operation_id).attempts[0]
            .sequence_released
            .clone()
            .unwrap();
        assert_eq!(proof.commit_id, commit);
        assert_eq!(proof.released_at_ms, NOW);
        let mut replacement = input;
        replacement
            .sequence_released
            .as_mut()
            .unwrap()
            .primary_ledger = 99;
        fx.recorder()
            .record_evidence(attempt.operation_id, 1, &replacement)
            .unwrap();
        assert_eq!(
            fx.record(attempt.operation_id).attempts[0]
                .sequence_released
                .as_ref(),
            Some(&proof)
        );
        assert_eq!(fx.sink.entries.len(), 1);
    }

    #[test]
    #[serial_test::serial]
    fn recovery_state_only_update_appends_nothing() {
        let mut fx = Fx::new();
        let attempt = stored_attempt(&mut fx);
        fx.sink.entries.clear();
        let observation = WindowObservation {
            ledger: 10,
            close_time_floor_ms: NOW,
            observed_at_ms: NOW,
        };
        let input = EvidenceInput {
            recovery: Some(RecoveryUpdate {
                primary_cursor: Some(2),
                witness_cursor: Some(3),
                disagreements: 4,
                last_pass_at_ms: Some(NOW),
                last_outcome: Some("evidence_pending".to_owned()),
                ..RecoveryUpdate::default()
            }),
            observation: Some(observation),
            ..EvidenceInput::default()
        };
        assert_eq!(
            fx.recorder()
                .record_evidence(attempt.operation_id, 1, &input)
                .unwrap(),
            None
        );
        assert!(fx.sink.entries.is_empty());
        assert_eq!(fx.wire().last_observation, Some(observation));
        let snapshot = OperationStatus::new(&fx.store, &fx.profile)
            .recovery_snapshot(None)
            .unwrap();
        assert_eq!(snapshot[0].recovery, input.recovery.unwrap());
    }

    #[test]
    #[serial_test::serial]
    fn recovery_release_append_failure_commits_nothing() {
        let mut fx = Fx::new();
        let attempt = stored_attempt(&mut fx);
        let before = std::fs::read(fx.store.path()).unwrap();
        fx.sink.fail = true;
        let error = fx
            .recorder()
            .record_evidence(attempt.operation_id, 1, &release_input(&attempt))
            .unwrap_err();
        assert_eq!(error.submission_code(), "audit.append_failed");
        assert_eq!(std::fs::read(fx.store.path()).unwrap(), before);
    }

    #[test]
    #[serial_test::serial]
    fn recovery_outcome_classes_and_pass_time_survive_restart() {
        let mut fx = Fx::new();
        let attempt = stored_attempt(&mut fx);
        for (index, class) in [
            "concurring",
            "evidence_pending",
            "disagreement",
            "witness_unconfigured",
        ]
        .into_iter()
        .enumerate()
        {
            let now = NOW + index as u64;
            let mut input = pending(&attempt, now, class, "detail");
            input.recovery.as_mut().unwrap().history_incomplete = index == 0;
            fx.recorder()
                .record_evidence(attempt.operation_id, 1, &input)
                .unwrap();
            let reopened = PersistedWindowStore::at_path(fx.store.path().to_owned());
            let snapshot = OperationStatus::new(&reopened, &fx.profile)
                .recovery_snapshot(None)
                .unwrap();
            assert_eq!(snapshot[0].recovery.last_outcome.as_deref(), Some(class));
            assert_eq!(snapshot[0].recovery.last_pass_at_ms, Some(now));
            assert!(snapshot[0].recovery.history_incomplete);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn recovery_pass_respects_call_budget_and_deadline() {
        let mut budget = Budget::new();
        for _ in 0..9 {
            budget.read(true, async { Ok::<_, ()>(()) }).await.unwrap();
        }
        assert_eq!(
            budget.read(true, async { Ok::<_, ()>(()) }).await,
            Err(ReadFailure::Pending)
        );
        for _ in 0..24 {
            budget.read(false, async { Ok::<_, ()>(()) }).await.unwrap();
        }
        assert_eq!(
            budget.read(false, async { Ok::<_, ()>(()) }).await,
            Err(ReadFailure::Pending)
        );
        assert_eq!(
            budget.used,
            RecoveryRequests {
                shared: 9,
                attempt: 24
            }
        );
        let mut budget = Budget::new();
        let start = Instant::now();
        budget
            .read(true, async {
                tokio::time::sleep(Duration::from_secs(13)).await;
                Ok::<_, ()>(())
            })
            .await
            .unwrap();
        assert_eq!(
            budget.read::<(), ()>(false, std::future::pending()).await,
            Err(ReadFailure::Deadline)
        );
        assert_eq!(start.elapsed(), PASS_DURATION);
        assert_eq!(budget.used.attempt, 1);
    }

    #[cfg(feature = "mainnet-write")]
    async fn exposed_fixture(
        label: &str,
    ) -> (
        crate::mainnet::fixtures::LedgerFixture,
        crate::OperationAttempt,
        crate::SubmissionIntent,
    ) {
        use crate::mainnet::fixtures::{self, LedgerFixture};
        use crate::{MainnetSubmitGrant, SubmissionRecorder};
        let fx = LedgerFixture::new(label, NOW);
        let unsigned = fixtures::unsigned_envelope();
        let signed = fixtures::signed_envelope();
        let intent = fixtures::intent(&signed);
        let holds = vec![fixtures::hold(&fx.name, NOW, 100)];
        let (attempt, authorization) = fx.linked_attempt(
            fixtures::tx_binding(unsigned.envelope_xdr(), unsigned.tx_hash_hex()),
            &holds,
            "order-1",
        );
        let recorder = fx
            .recorder(holds, Some(Arc::clone(&fx.writer)))
            .with_operation(Some(attempt))
            .with_pre_exposure_ledger(Some(7))
            .with_observation(Some(WindowObservation {
                ledger: 9,
                close_time_floor_ms: NOW - 1_000,
                observed_at_ms: NOW,
            }));
        recorder
            .pre_send_authorized(&intent, MainnetSubmitGrant::Tx(authorization))
            .await
            .unwrap();
        recorder
            .outcome(
                &intent,
                &crate::SubmissionOutcome::Timeout {
                    tx_hash: intent.tx_hash.clone(),
                },
            )
            .await;
        drop(recorder);
        (fx, attempt, intent)
    }

    #[cfg(feature = "mainnet-write")]
    #[tokio::test]
    #[serial_test::serial]
    async fn recovery_submission_readiness_persists_last_observation() {
        use crate::SubmissionRecorder;
        use crate::mainnet::fixtures;
        let (fx, attempt, intent) = exposed_fixture("recovery-observation").await;
        let read = || {
            let bytes = std::fs::read(fx.window.path()).unwrap();
            serde_json::from_slice::<serde_json::Value>(&bytes[32..]).unwrap()
        };
        let before = read()["last_observation"].clone();
        assert_eq!(
            before,
            json!({"ledger":9,"close_time_floor_ms":NOW-1_000,"observed_at_ms":NOW})
        );
        assert_eq!(
            fx.operation_record(attempt)["attempts"][0]["pre_exposure_ledger"],
            7
        );
        let unsigned = fixtures::unsigned_envelope();
        let grant = fx.mint(
            fixtures::tx_binding(unsigned.envelope_xdr(), unsigned.tx_hash_hex()),
            &[],
            None,
            "approval-2",
        );
        assert!(
            fx.recorder(vec![], Some(Arc::clone(&fx.writer)))
                .with_observation(None)
                .pre_send_authorized(&intent, crate::MainnetSubmitGrant::Tx(grant))
                .await
                .is_err()
        );
        assert_eq!(read()["last_observation"], before);
    }

    #[cfg(feature = "mainnet-write")]
    #[tokio::test]
    #[serial_test::serial]
    async fn recovery_sequence_reuse_keeps_replay_approval_and_hold_guards() {
        use super::super::operations::{
            BusinessId, IntentSlot, OpenOutcome, OpenRequest, OperationKind, OperationTool,
        };
        use stellar_agent_core::profile::receipt::{BeginSubmissionOutcome, ReceiptStore};
        let (fx, attempt, intent) = exposed_fixture("recovery-guards").await;
        let before = std::fs::read(fx.window.path()).unwrap();
        let before: serde_json::Value = serde_json::from_slice(&before[32..]).unwrap();
        assert!(!before["entries"].as_array().unwrap().is_empty());
        let mut writer = fx.writer.lock().unwrap();
        let mut recorder =
            OperationRecorder::new(&fx.window, &fx.profile, &mut *writer, "recovery");
        recorder
            .record_evidence(
                attempt.operation_id,
                1,
                &EvidenceInput {
                    sequence_released: Some(SequenceReleaseInput {
                        primary_ledger: 10,
                        witness_ledger: 11,
                        min_close_time_ms: NOW + 121_000,
                    }),
                    ..EvidenceInput::default()
                },
            )
            .unwrap();
        let unsigned = crate::mainnet::fixtures::unsigned_envelope();
        let xdr = unsigned.envelope_xdr();
        let mut request = OpenRequest {
            business_id: BusinessId::parse("order-1").unwrap(),
            tool: OperationTool::CliPay,
            kind: OperationKind::Pay,
            intent: IntentSlot::Envelope {
                unsigned_envelope_sha256: crate::operation_entry::unsigned_envelope_sha256(xdr),
                intent_digest: [7; 32],
                max_time: crate::operation_entry::envelope_max_time(xdr).unwrap(),
            },
            envelope_xdr: Some(xdr.to_owned()),
            prepared_decision: None,
            rule_ttl_ms: None,
        };
        assert!(matches!(
            recorder.open(&request).unwrap(),
            OpenOutcome::Replay(_)
        ));
        request.intent = IntentSlot::Canonical {
            intent_digest: [8; 32],
            intent: json!({}),
        };
        assert!(matches!(
            recorder.open(&request).unwrap(),
            OpenOutcome::Conflict
        ));
        let _window =
            WindowStoreLock::acquire_for(fx.window.path(), &fx.profile.policy_window_state_key_id)
                .unwrap();
        let status = OperationStatus::new(&fx.window, &fx.profile);
        assert!(matches!(
            fx.receipts
                .begin_submission_releasing(
                    &intent.envelope_hash,
                    &intent.tx_hash,
                    &intent.source,
                    intent.sequence,
                    intent.max_time,
                    9,
                    None,
                    &status
                )
                .unwrap(),
            BeginSubmissionOutcome::AlreadyPresent(_)
        ));
        let nonce_store = ReceiptStore::open_at(fx.dir.path(), "nonce-guard").unwrap();
        nonce_store
            .begin_submission_with_approval(
                &intent.envelope_hash,
                &intent.tx_hash,
                &intent.source,
                intent.sequence,
                intent.max_time,
                9,
                Some("approval"),
            )
            .unwrap();
        assert!(matches!(
            nonce_store
                .begin_submission_releasing(
                    &"04".repeat(32),
                    &intent.tx_hash,
                    &intent.source,
                    intent.sequence,
                    intent.max_time,
                    9,
                    Some("approval"),
                    &status
                )
                .unwrap(),
            BeginSubmissionOutcome::DuplicateApproval(_)
        ));
        let after = std::fs::read(fx.window.path()).unwrap();
        let after: serde_json::Value = serde_json::from_slice(&after[32..]).unwrap();
        assert_eq!(after["holds"], before["holds"]);
        assert_eq!(after["entries"], before["entries"]);
        assert_eq!(after["authorizations"], before["authorizations"]);
        assert_eq!(
            fx.operation_record(attempt)["state"],
            "sent_outcome_unknown"
        );
    }

    #[cfg(feature = "mainnet-write")]
    #[tokio::test]
    #[serial_test::serial]
    async fn recovery_claim_takes_window_then_receipt_and_one_claim_wins() {
        use stellar_agent_core::profile::receipt::BeginSubmissionOutcome;
        let (fx, attempt, intent) = exposed_fixture("recovery-locks").await;
        {
            let mut writer = fx.writer.lock().unwrap();
            OperationRecorder::new(&fx.window, &fx.profile, &mut *writer, "recovery")
                .record_evidence(
                    attempt.operation_id,
                    1,
                    &EvidenceInput {
                        sequence_released: Some(SequenceReleaseInput {
                            primary_ledger: 10,
                            witness_ledger: 11,
                            min_close_time_ms: NOW + 121_000,
                        }),
                        ..EvidenceInput::default()
                    },
                )
                .unwrap();
        }
        let barrier = std::sync::Barrier::new(2);
        let results = std::thread::scope(|scope| {
            let handles: Vec<_> = [3_u8, 4]
                .into_iter()
                .map(|byte| {
                    let fx = &fx;
                    let intent = &intent;
                    let barrier = &barrier;
                    scope.spawn(move || {
                        barrier.wait();
                        let writer = fx.writer.lock().unwrap();
                        with_sequence_releases(&fx.window, &fx.profile, &writer, |releases| {
                            assert!(
                                WindowStoreLock::acquire_for(
                                    fx.window.path(),
                                    &fx.profile.policy_window_state_key_id
                                )
                                .is_err()
                            );
                            fx.receipts
                                .begin_submission_releasing(
                                    &stellar_agent_core::hex::encode(&[byte; 32]),
                                    &intent.tx_hash,
                                    &intent.source,
                                    intent.sequence,
                                    intent.max_time,
                                    9,
                                    None,
                                    releases,
                                )
                                .unwrap()
                        })
                        .unwrap()
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, BeginSubmissionOutcome::Recorded))
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, BeginSubmissionOutcome::DuplicateSequence(_)))
                .count(),
            1
        );
    }

    #[cfg(feature = "mainnet-write")]
    #[tokio::test]
    #[serial_test::serial]
    async fn recovery_pass_persists_last_observation() {
        let mut fx = Fx::new();
        let primary = endpoint(7, NOW / 1_000).await;
        let oracle = endpoint(8, NOW / 1_000).await;
        let primary_client = StellarRpcClient::new(&primary.uri()).unwrap();
        let oracle_client = StellarRpcClient::new(&oracle.uri()).unwrap();
        let (writer, _) = crate::mainnet::fixtures::keyed_writer(&fx.profile.audit_log_path);
        macro_rules! pass {
            ($fx:expr) => {
                recover_sequences(
                    &$fx.store,
                    &$fx.profile,
                    EndpointPair::from_clients(&primary_client, Some(&oracle_client)),
                    &writer,
                    None,
                )
            };
        }
        // A pass without an attempt to evaluate reads and writes nothing.
        assert!(!fx.store.path().exists());
        assert_eq!(pass!(fx).await.unwrap(), RecoveryReport::default());
        assert!(methods(&primary).await.is_empty() && methods(&oracle).await.is_empty());
        assert!(!fx.store.path().exists());
        // An evaluated pass persists the primary observation.
        unknown_named(&mut fx, 1);
        assert_eq!(pass!(fx).await.unwrap().evaluated, 1);
        let stored = fx
            .wire()
            .last_observation
            .expect("the pass observes the primary");
        assert_eq!(stored.ledger, 7);
        // A failure before any observation keeps the stored value.
        primary.reset().await;
        pass!(fx).await.unwrap();
        assert_eq!(fx.wire().last_observation, Some(stored));
    }

    #[cfg(feature = "mainnet-write")]
    #[tokio::test]
    #[serial_test::serial]
    async fn recovery_legacy_stage_runs_unchanged_before_recovery() {
        use crate::mainnet::fixtures::{self, LedgerFixture};
        let fx = LedgerFixture::new("recovery-nonempty-stages", NOW);
        let primary = endpoint(7, NOW / 1_000).await;
        let oracle = endpoint(8, NOW / 1_000).await;
        for server in [&primary, &oracle] {
            mount(
                server,
                "getTransaction",
                json!({
                    "status":"NOT_FOUND", "latestLedger":8, "oldestLedger":1,
                    "latestLedgerCloseTime":(NOW/1_000).to_string(), "oldestLedgerCloseTime":"1"
                }),
            )
            .await;
        }
        let client = StellarRpcClient::new(&primary.uri()).unwrap();
        let oracle_client = StellarRpcClient::new(&oracle.uri()).unwrap();
        let hold = super::super::SubmissionHold {
            chain_scope: super::super::ChainScope::for_chain(fx.profile.chain_id),
            id: "b5".repeat(32),
            tx_hash: "b5".repeat(32),
            source: fixtures::account([1; 32]),
            sequence: 5,
            max_time: NOW / 1_000 - 10,
            pending_since_ms: NOW - super::super::RECONCILE_MIN_AGE_MS,
            submission_ledger: 1,
            submission_anchor: None,
            operator_required: false,
        };
        fx.window
            .record_pending(&fx.profile, &[fixtures::hold(&fx.name, NOW, 500)], &hold)
            .unwrap();
        fx.receipts
            .try_begin(
                &hold.id,
                &hold.tx_hash,
                &hold.source,
                hold.sequence,
                hold.max_time,
                hold.submission_ledger,
            )
            .unwrap();
        fx.receipts.mark_submitted(&hold.id).unwrap();
        let reservations = fx.window.pending_reservations(&fx.profile).unwrap();
        let receipt = fx.receipts.get(&hold.id).unwrap();
        let expected = fx
            .window
            .reconcile_due(
                &fx.profile,
                &client,
                Some(&oracle_client),
                Some(&fx.receipts),
                NOW,
                super::super::RECONCILE_BUDGET,
            )
            .await
            .unwrap();
        assert_eq!(expected.rpc_calls, 6);
        let primary_before = primary.received_requests().await.unwrap().len();
        let oracle_before = oracle.received_requests().await.unwrap().len();
        assert_eq!(primary_before + oracle_before, 6);
        crate::submission_flow::RECOVERY_STAGE_TRACE.with_borrow_mut(Vec::clear);
        let calls = std::cell::Cell::new(0);
        let result = crate::submission_flow::reconcile_pass(
            &fx.profile,
            &fx.window,
            &client,
            Some(&oracle_client),
            Some(&fx.receipts),
            NOW,
            || {
                calls.set(calls.get() + 1);
                Ok(Arc::clone(&fx.writer))
            },
        )
        .await;
        let crate::submission_flow::ReconcilePass::Completed(actual) = result else {
            panic!("completed pass required");
        };
        assert_eq!(actual, expected);
        assert_eq!(calls.get(), 1);
        let total = primary.received_requests().await.unwrap().len() - primary_before
            + oracle.received_requests().await.unwrap().len()
            - oracle_before;
        // No attempt is due, so the recovery stage sends nothing.
        assert_eq!(total - actual.rpc_calls, 0);
        assert_eq!(total, 6);
        assert_eq!(
            fx.window.pending_reservations(&fx.profile).unwrap(),
            reservations
        );
        assert_eq!(fx.receipts.get(&hold.id).unwrap(), receipt);
        crate::submission_flow::RECOVERY_STAGE_TRACE
            .with_borrow(|trace| assert_eq!(trace, &["expire", "legacy", "recovery"]));
    }

    /// The methods `server` receives, in order.
    #[cfg(feature = "mainnet-write")]
    async fn methods(server: &MockServer) -> Vec<String> {
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|request| {
                let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
                body["method"].as_str().unwrap().to_owned()
            })
            .collect()
    }

    #[cfg(feature = "mainnet-write")]
    #[tokio::test]
    #[serial_test::serial]
    async fn recovery_idle_stage_sends_no_request() {
        // No operation record exists, so the recovery snapshot is empty.
        let fx = crate::mainnet::fixtures::LedgerFixture::new("recovery-idle", NOW);
        assert!(
            OperationStatus::new(&fx.window, &fx.profile)
                .recovery_snapshot(None)
                .unwrap()
                .is_empty()
        );
        let primary = endpoint(7, NOW / 1_000).await;
        let oracle = endpoint(8, NOW / 1_000).await;
        let client = StellarRpcClient::new(&primary.uri()).unwrap();
        let oracle_client = StellarRpcClient::new(&oracle.uri()).unwrap();
        fx.window
            .reconcile_due(
                &fx.profile,
                &client,
                Some(&oracle_client),
                Some(&fx.receipts),
                NOW,
                super::super::RECONCILE_BUDGET,
            )
            .await
            .unwrap();
        let legacy = (methods(&primary).await, methods(&oracle).await);
        let bytes = std::fs::read(fx.window.path()).ok();
        let result = crate::submission_flow::reconcile_pass(
            &fx.profile,
            &fx.window,
            &client,
            Some(&oracle_client),
            Some(&fx.receipts),
            NOW,
            || Ok(Arc::clone(&fx.writer)),
        )
        .await;
        assert!(
            matches!(result, crate::submission_flow::ReconcilePass::Completed(_)),
            "{result:?}"
        );
        let both = (methods(&primary).await, methods(&oracle).await);
        let pass = (
            both.0[legacy.0.len()..].to_vec(),
            both.1[legacy.1.len()..].to_vec(),
        );
        assert_eq!(pass, legacy);
        assert_eq!(std::fs::read(fx.window.path()).ok(), bytes);
    }

    #[cfg(feature = "mainnet-write")]
    #[tokio::test]
    #[serial_test::serial]
    async fn recovery_refused_stage_keeps_the_legacy_report() {
        use stellar_agent_core::policy::v1::criteria::state_store::{
            StateKey, WindowEntry, WindowLimit,
        };
        let (fx, attempt, _) = exposed_fixture("recovery-refused-stage").await;
        // A reservation past its accounting horizon and older than the legacy
        // age threshold, whose receipt cannot be written while its lock is held.
        let hold = super::super::SubmissionHold {
            chain_scope: super::super::ChainScope::for_chain(fx.profile.chain_id),
            id: "c6".repeat(32),
            tx_hash: "c7".repeat(32),
            source: crate::mainnet::fixtures::account([3; 32]),
            sequence: 9,
            max_time: NOW / 1_000 - 120,
            pending_since_ms: NOW,
            submission_ledger: 1,
            submission_anchor: None,
            operator_required: false,
        };
        let entry = WindowEntry::new(
            StateKey::new(&fx.name, 1, "native", 60),
            hold.pending_since_ms,
            300,
            WindowLimit::Amount {
                asset: "native".to_owned(),
                window: "1d".to_owned(),
                max_stroops: 1_000_000,
            },
        );
        fx.window
            .record_pending(&fx.profile, &[entry], &hold)
            .unwrap();
        fx.receipts
            .try_begin(
                &hold.id,
                &hold.tx_hash,
                &hold.source,
                hold.sequence,
                hold.max_time,
                hold.submission_ledger,
            )
            .unwrap();
        fx.receipts.mark_submitted(&hold.id).unwrap();
        let held_receipt = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(fx.receipts.lock_file_path().unwrap())
            .unwrap();
        held_receipt.try_lock().unwrap();
        // The pass runs past the legacy age threshold. The legacy expiry asks
        // no endpoint; the recovery identity read names another network.
        let later = NOW + 2 * super::super::RECONCILE_MIN_AGE_MS;
        fx.clock.set(later);
        let primary = endpoint(7, later / 1_000).await;
        let oracle = endpoint(8, later / 1_000).await;
        Mock::given(method("POST"))
            .and(body_partial_json(json!({"method":"getNetwork"})))
            .respond_with(EchoIdResponder::new(
                stellar_agent_test_support::signed_envelope::get_network_result("wrong"),
            ))
            .with_priority(1)
            .mount(&oracle)
            .await;
        let client = StellarRpcClient::new(&primary.uri()).unwrap();
        let oracle_client = StellarRpcClient::new(&oracle.uri()).unwrap();
        let before = fx.operation_record(attempt);
        let result = crate::submission_flow::reconcile_pass(
            &fx.profile,
            &fx.window,
            &client,
            Some(&oracle_client),
            Some(&fx.receipts),
            later,
            || Ok(Arc::clone(&fx.writer)),
        )
        .await;
        let crate::submission_flow::ReconcilePass::RecoveryFailed { legacy, error } = &result
        else {
            panic!("a refused recovery stage keeps the legacy report: {result:?}");
        };
        assert_eq!(
            (legacy.released, legacy.receipt_write_failed),
            (1, 1),
            "{legacy:?}"
        );
        assert_eq!(legacy.settled.len(), 1);
        assert_eq!(error.code(), "network.witness_unavailable");
        assert_eq!(fx.operation_record(attempt), before);
        let (warnings, _guard) = stellar_agent_test_support::WarningCapture::capture(None);
        let _ = crate::submission_flow::finish_reconciliation(
            &fx.profile,
            &fx.name,
            &fx.window,
            Some(&fx.receipts),
            &result,
            || Ok(Arc::clone(&fx.writer)),
        );
        let messages: Vec<String> = warnings
            .seen()
            .iter()
            .filter_map(|fields| fields.get("message").cloned())
            .collect();
        for expected in [
            "window reconcile: receipt writes stay owed",
            "recovery: the stage refused; every sequence stays held",
        ] {
            assert!(
                messages.iter().any(|message| message.contains(expected)),
                "{expected}: {messages:?}"
            );
        }
        drop(held_receipt);
    }

    #[cfg(feature = "mainnet-write")]
    #[tokio::test]
    #[serial_test::serial]
    async fn recovery_empty_pass_acquires_one_writer() {
        let fx = crate::mainnet::fixtures::LedgerFixture::new("recovery-stages", NOW);
        let client = StellarRpcClient::new("http://127.0.0.1:1").unwrap();
        let expected = fx
            .window
            .reconcile_due(
                &fx.profile,
                &client,
                None,
                None,
                NOW,
                super::super::RECONCILE_BUDGET,
            )
            .await
            .unwrap();
        crate::submission_flow::RECOVERY_STAGE_TRACE.with_borrow_mut(Vec::clear);
        let calls = std::cell::Cell::new(0);
        let result = crate::submission_flow::reconcile_pass(
            &fx.profile,
            &fx.window,
            &client,
            None,
            None,
            NOW,
            || {
                calls.set(calls.get() + 1);
                Ok(Arc::clone(&fx.writer))
            },
        )
        .await;
        let crate::submission_flow::ReconcilePass::Completed(actual) = result else {
            panic!("completed pass required")
        };
        assert_eq!(actual, expected);
        assert_eq!(actual.rpc_calls, 0);
        assert_eq!(calls.get(), 1);
        crate::submission_flow::RECOVERY_STAGE_TRACE
            .with_borrow(|trace| assert_eq!(trace, &["expire", "legacy", "recovery"]));
    }

    #[cfg(feature = "mainnet-write")]
    #[tokio::test]
    #[serial_test::serial]
    async fn recovery_targeted_status_evaluates_only_the_requested_attempt() {
        let mut fx = Fx::new();
        unknown_named(&mut fx, 1);
        unknown_named(&mut fx, 2);
        let snapshots = OperationStatus::new(&fx.store, &fx.profile)
            .recovery_snapshot(None)
            .unwrap();
        let untouched = fx.record(snapshots[1].operation_id);
        let ExposureIdentity::Classic { tx_hash, .. } = snapshots[0].exposure else {
            panic!("classic attempt required")
        };
        let primary = endpoint(7, NOW / 1_000).await;
        let oracle = endpoint(8, NOW / 1_000).await;
        mount(&primary, "getTransaction", json!({"status":"NOT_FOUND","latestLedger":7,"oldestLedger":1,"latestLedgerCloseTime":(NOW/1000).to_string(),"oldestLedgerCloseTime":"1"})).await;
        let primary_client = StellarRpcClient::new(&primary.uri()).unwrap();
        let oracle_client = StellarRpcClient::new(&oracle.uri()).unwrap();
        let (writer, _) = crate::mainnet::fixtures::keyed_writer(&fx.profile.audit_log_path);
        let home = tempfile::tempdir().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
        let result = crate::submission_flow::transaction_status(
            crate::submission_flow::StatusRequest {
                profile: &fx.profile,
                profile_name: "ops",
                tx_hash: &stellar_agent_core::hex::encode(&tx_hash),
                window: &fx.store,
                client: &primary_client,
                oracle: Some(&oracle_client),
            },
            || Ok(home.path().join("approvals")),
            || Ok(Arc::clone(&writer)),
        )
        .await
        .unwrap();
        assert_eq!(result.chain_status, "NOT_FOUND");
        assert!(result.record.is_none());
        assert!(result.reservation.is_none());
        assert!(!result.reservation_open);
        assert_eq!(
            serde_json::to_value(fx.record(snapshots[1].operation_id)).unwrap(),
            serde_json::to_value(untouched).unwrap()
        );
        assert_eq!(
            fx.record(snapshots[0].operation_id).attempts[0]
                .recovery
                .as_ref()
                .unwrap()
                .last_pass_at_ms,
            Some(NOW)
        );
        assert_eq!(rpc_request_count(&primary, "getLedgers").await, 2);
        assert_eq!(rpc_request_count(&oracle, "getLedgers").await, 2);
    }

    #[tokio::test]
    async fn recovery_malformed_history_charges_one_request() {
        let server = MockServer::start().await;
        let client = StellarRpcClient::new(&server.uri()).unwrap();
        let shared = SharedObservation {
            health: serde_json::from_value(json!({"status":"healthy", "latestLedger":3, "oldestLedger":1, "ledgerRetentionWindow":3})).unwrap(),
            report: OperationalReport { latest_ledger: 3, close_time_unix: NOW / 1_000, close_lag_seconds: 0 },
            oldest: 1, read_at: Instant::now(),
        };
        let mut attempt = attempt(10);
        attempt.recovery.primary_cursor = Some(1);
        attempt.recovery.disagreements = 9;
        for defect in 0..6 {
            server.reset().await;
            let mut page = page_json(1, 3, 3, 11);
            match defect {
                0 => page["ledgers"][1]["sequence"] = json!(3),
                1 => page["ledgers"][1]["sequence"] = json!(1),
                2 => page["ledgers"].as_array_mut().unwrap().swap(0, 1),
                3 => page["ledgers"][0]["ledgerCloseTime"] = json!("0"),
                4 => {
                    page["ledgers"][0]
                        .as_object_mut()
                        .unwrap()
                        .remove("ledgerCloseTime");
                }
                _ => page["latestLedger"] = json!(4),
            }
            mount(&server, "getLedgers", page).await;
            let mut budget = Budget::new();
            assert!(
                history(&client, &shared, &mut budget, &attempt, true)
                    .await
                    .unwrap()
                    .is_none()
            );
            assert_eq!(
                budget.used,
                RecoveryRequests {
                    attempt: 1,
                    shared: 0
                }
            );
            assert_eq!(rpc_request_count(&server, "getLedgers").await, 1);
            let input = evaluate(&attempt, None, None, NOW, "malformed_history").unwrap();
            let recovery = input.recovery.unwrap();
            assert_eq!(recovery.primary_cursor, Some(1));
            assert_eq!(recovery.disagreements, 9);
        }
    }

    #[cfg(feature = "mainnet-write")]
    #[tokio::test]
    #[serial_test::serial]
    async fn recovery_interrupted_attempt_keeps_its_state() {
        let mut fx = Fx::new();
        let attempt = stored_attempt(&mut fx);
        fx.recorder()
            .record_evidence(
                attempt.operation_id,
                1,
                &EvidenceInput {
                    recovery: Some(RecoveryUpdate {
                        disagreements: 9,
                        ..RecoveryUpdate::default()
                    }),
                    ..EvidenceInput::default()
                },
            )
            .unwrap();
        let before = serde_json::to_value(fx.record(attempt.operation_id)).unwrap();
        let primary = endpoint(7, NOW / 1_000).await;
        let oracle = endpoint(8, NOW / 1_000).await;
        Mock::given(method("POST"))
            .and(body_partial_json(
                json!({"method":"getLedgers", "params":{"pagination":{"limit":200}}}),
            ))
            .respond_with(move |request: &wiremock::Request| {
                wiremock::Respond::respond(
                    &EchoIdResponder::new(page_json(7, 1, 7, NOW / 1_000)),
                    request,
                )
                .set_delay(PASS_DURATION + Duration::from_secs(1))
            })
            .with_priority(1)
            .mount(&primary)
            .await;
        let primary_client = StellarRpcClient::new(&primary.uri()).unwrap();
        let oracle_client = StellarRpcClient::new(&oracle.uri()).unwrap();
        let (writer, _) = crate::mainnet::fixtures::keyed_writer(&fx.profile.audit_log_path);
        let report = recover_sequences(
            &fx.store,
            &fx.profile,
            EndpointPair::from_clients(&primary_client, Some(&oracle_client)),
            &writer,
            None,
        )
        .await
        .unwrap();
        assert_eq!(report.evaluated, 0);
        assert_eq!(
            report.requests,
            RecoveryRequests {
                attempt: 1,
                shared: 6
            }
        );
        assert_eq!(
            serde_json::to_value(fx.record(attempt.operation_id)).unwrap(),
            before
        );
    }

    async fn mount(server: &MockServer, name: &str, answer: serde_json::Value) {
        Mock::given(method("POST"))
            .and(body_partial_json(json!({"method": name})))
            .respond_with(EchoIdResponder::new(answer))
            .mount(server)
            .await;
    }

    async fn endpoint(ledger: u32, close: u64) -> MockServer {
        let server = MockServer::start().await;
        mount(
            &server,
            "getNetwork",
            stellar_agent_test_support::signed_envelope::get_network_result(
                stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE,
            ),
        )
        .await;
        mount(&server, "getHealth", json!({"status":"healthy", "latestLedger":ledger, "oldestLedger":1, "ledgerRetentionWindow":ledger})).await;
        mount(
            &server,
            "getLatestLedger",
            json!({"id":"00".repeat(32), "protocolVersion":23, "sequence":ledger}),
        )
        .await;
        Mock::given(method("POST"))
            .and(body_partial_json(json!({"method":"getLedgers"})))
            .respond_with(ledgers_responder(ledger, close))
            .mount(&server)
            .await;
        server
    }

    /// Answers `getLedgers` from the requested start ledger and refuses a
    /// start beyond `latest`, as an RPC endpoint does.
    fn ledgers_responder(
        latest: u32,
        close: u64,
    ) -> impl Fn(&wiremock::Request) -> wiremock::ResponseTemplate + Send + Sync {
        move |request: &wiremock::Request| {
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            let start = body["params"]["startLedger"]
                .as_u64()
                .map_or(latest, |start| u32::try_from(start).unwrap());
            let limit = body["params"]["pagination"]["limit"]
                .as_u64()
                .map_or(1, |limit| u32::try_from(limit).unwrap());
            let answer = if start == 0 || start > latest {
                json!({"jsonrpc":"2.0", "id":body["id"], "error":{
                    "code":-32600, "message":"startLedger must be at most the latest ledger"}})
            } else {
                json!({"jsonrpc":"2.0", "id":body["id"],
                    "result":page_json(start, limit.min(latest - start + 1), latest, close)})
            };
            wiremock::ResponseTemplate::new(200).set_body_json(answer)
        }
    }

    /// The `startLedger` of every `getLedgers` request `server` receives.
    async fn requested_starts(server: &MockServer) -> Vec<u64> {
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter_map(|request| {
                let body: serde_json::Value = serde_json::from_slice(&request.body).ok()?;
                (body["method"] == "getLedgers")
                    .then(|| body["params"]["startLedger"].as_u64())
                    .flatten()
            })
            .collect()
    }

    #[tokio::test]
    async fn recovery_pair_construction_sends_nothing_and_verifies_each_identity_once() {
        let primary = endpoint(7, NOW / 1_000).await;
        let oracle = endpoint(8, NOW / 1_000).await;
        let secondary = endpoint(9, NOW / 1_000).await;
        let client = StellarRpcClient::new(&primary.uri()).unwrap();
        let mut profile = Profile::builder_mainnet_named(
            "recovery",
            "https://primary.example",
            "signer",
            "account",
            "nonce",
            "account",
        )
        .build();
        profile.oracle_provider_url = Some("https://oracle.example".parse().unwrap());
        let context = crate::NetworkContext::from_profile(&profile)
            .with_secondary(Some("https://secondary.example".to_owned()))
            .with_test_transport_routes(&[
                ("oracle.example", &oracle.uri()),
                ("secondary.example", &secondary.uri()),
            ]);
        // Both stages pair the caller's primary with this oracle source.
        let oracle_client = context.oracle_client(&profile).unwrap();
        let pair = EndpointPair::from_clients(&client, oracle_client.as_ref());
        assert!(primary.received_requests().await.unwrap().is_empty());
        assert!(oracle.received_requests().await.unwrap().is_empty());
        let mut budget = Budget::new();
        pair.verify(&mut budget).await.unwrap();
        assert_eq!(budget.used.shared, 2);
        assert_eq!(rpc_request_count(&primary, "getNetwork").await, 1);
        assert_eq!(rpc_request_count(&oracle, "getNetwork").await, 1);
        assert!(secondary.received_requests().await.unwrap().is_empty());
        for identity in [
            json!({"passphrase":"wrong", "protocolVersion":29}),
            json!({"passphrase":stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE, "protocolVersion":1}),
        ] {
            oracle.reset().await;
            mount(&oracle, "getNetwork", identity).await;
            assert!(pair.verify(&mut Budget::new()).await.is_err());
            assert_eq!(rpc_request_count(&oracle, "getNetwork").await, 1);
        }
        oracle.reset().await;
        let calls = std::sync::atomic::AtomicUsize::new(0);
        Mock::given(method("POST"))
            .respond_with(move |request: &wiremock::Request| {
                if calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                    wiremock::ResponseTemplate::new(500)
                } else {
                    wiremock::Respond::respond(
                        &EchoIdResponder::new(
                            stellar_agent_test_support::signed_envelope::get_network_result(
                                stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE,
                            ),
                        ),
                        request,
                    )
                }
            })
            .mount(&oracle)
            .await;
        let batch = collect(&pair, &[attempt(10)], NOW).await.unwrap();
        assert_eq!(
            batch.requests,
            RecoveryRequests {
                attempt: 0,
                shared: 2
            }
        );
        assert!(batch.inputs[0].2.sequence_released.is_none());
        assert_eq!(rpc_request_count(&oracle, "getNetwork").await, 1);
    }

    #[tokio::test]
    async fn recovery_transient_health_failure_charges_one_request() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(wiremock::ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let client = StellarRpcClient::new(&server.uri()).unwrap();
        let mut budget = Budget::new();
        assert!(
            shared_observation(&client, &mut budget, NOW, None)
                .await
                .is_err()
        );
        assert_eq!(budget.used.shared, 1);
        assert_eq!(rpc_request_count(&server, "getHealth").await, 1);
        assert!(
            crate::operational::operational_check_single(
                &client,
                Instant::now() + Duration::from_millis(100)
            )
            .await
            .is_err()
        );
        assert_eq!(rpc_request_count(&server, "getHealth").await, 2);
    }

    #[tokio::test]
    async fn recovery_four_attempts_use_eight_history_requests() {
        let primary = endpoint(7, NOW / 1_000).await;
        let oracle = endpoint(8, NOW / 1_000).await;
        let calls = std::sync::atomic::AtomicUsize::new(0);
        Mock::given(method("POST"))
            .and(body_partial_json(
                json!({"method":"getLedgers", "params":{"pagination":{"limit":200}}}),
            ))
            .respond_with(move |request: &wiremock::Request| {
                let delay = if calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                    6
                } else {
                    0
                };
                wiremock::Respond::respond(
                    &EchoIdResponder::new(page_json(7, 1, 7, NOW / 1_000)),
                    request,
                )
                .set_delay(Duration::from_secs(delay))
            })
            .with_priority(1)
            .mount(&primary)
            .await;
        let primary_client = StellarRpcClient::new(&primary.uri()).unwrap();
        let oracle_client = StellarRpcClient::new(&oracle.uri()).unwrap();
        let mut attempts = vec![attempt(NOW / 1_000 - 1); 5];
        for attempt in &mut attempts {
            attempt.pre_exposure_ledger = None;
        }
        let start = Instant::now();
        let batch = collect(
            &EndpointPair::from_clients(&primary_client, Some(&oracle_client)),
            &attempts,
            NOW,
        )
        .await
        .unwrap();
        assert_eq!(batch.inputs.len(), 4);
        assert_eq!(
            batch.requests,
            RecoveryRequests {
                attempt: 8,
                shared: 9
            }
        );
        assert_eq!(
            primary.received_requests().await.unwrap().len()
                + oracle.received_requests().await.unwrap().len(),
            17
        );
        assert!(start.elapsed() < PASS_DURATION);
    }

    #[tokio::test]
    async fn recovery_stale_after_refresh_is_pending() {
        let primary = endpoint(7, NOW / 1_000).await;
        let oracle = endpoint(8, NOW / 1_000).await;
        for (server, ledger) in [(&primary, 7), (&oracle, 8)] {
            Mock::given(method("POST"))
                .and(body_partial_json(
                    json!({"method":"getLedgers", "params":{"pagination":{"limit":200}}}),
                ))
                .respond_with(move |request: &wiremock::Request| {
                    wiremock::Respond::respond(
                        &EchoIdResponder::new(page_json(ledger, 1, ledger, NOW / 1_000)),
                        request,
                    )
                    .set_delay(Duration::from_secs(3))
                })
                .with_priority(1)
                .mount(server)
                .await;
        }
        let primary_client = StellarRpcClient::new(&primary.uri()).unwrap();
        let oracle_client = StellarRpcClient::new(&oracle.uri()).unwrap();
        let pair = EndpointPair::from_clients(&primary_client, Some(&oracle_client));
        let mut attempts = vec![attempt(NOW / 1_000 - 1); 4];
        for attempt in &mut attempts {
            attempt.pre_exposure_ledger = None;
        }
        let batch = collect(&pair, &attempts, NOW).await.unwrap();
        assert_eq!(
            batch.requests,
            RecoveryRequests {
                attempt: 4,
                shared: 9
            }
        );
        assert_eq!(batch.inputs.len(), 4);
        for (_, _, input) in &batch.inputs[2..] {
            assert!(input.sequence_released.is_none());
            assert_eq!(
                input.recovery.as_ref().unwrap().diagnostic.as_deref(),
                Some("stale_observation")
            );
        }
    }

    /// The release proof of `id`'s first attempt, as the window holds it.
    #[cfg(feature = "mainnet-write")]
    fn proof_of(fx: &Fx, id: OperationId) -> Option<serde_json::Value> {
        fx.record(id).attempts[0]
            .sequence_released
            .as_ref()
            .map(|proof| serde_json::to_value(proof).unwrap())
    }

    #[cfg(feature = "mainnet-write")]
    #[tokio::test]
    #[serial_test::serial]
    async fn recovery_released_attempts_free_their_slots() {
        let mut fx = Fx::new();
        let mut ids = Vec::new();
        for n in 1..=5 {
            fx.clock.set(NOW + u64::from(n));
            ids.push(unknown_with(&mut fx, n, NOW / 1_000 - 10, vec![]).id());
        }
        for id in &ids[..4] {
            fx.recorder()
                .record_evidence(
                    *id,
                    1,
                    &EvidenceInput {
                        sequence_released: Some(SequenceReleaseInput {
                            primary_ledger: 7,
                            witness_ledger: 8,
                            min_close_time_ms: NOW,
                        }),
                        ..EvidenceInput::default()
                    },
                )
                .unwrap();
        }
        let primary = endpoint(7, NOW / 1_000).await;
        let oracle = endpoint(8, NOW / 1_000).await;
        let primary_client = StellarRpcClient::new(&primary.uri()).unwrap();
        let oracle_client = StellarRpcClient::new(&oracle.uri()).unwrap();
        let (writer, _) = crate::mainnet::fixtures::keyed_writer(&fx.profile.audit_log_path);
        let report = recover_sequences(
            &fx.store,
            &fx.profile,
            EndpointPair::from_clients(&primary_client, Some(&oracle_client)),
            &writer,
            None,
        )
        .await
        .unwrap();
        assert_eq!(report.evaluated, 1);
        let proof = proof_of(&fx, ids[4]).expect("the fifth attempt releases");
        assert_eq!(proof["primary_ledger"], 7);
        assert_eq!(proof["witness_ledger"], 8);
    }

    #[cfg(feature = "mainnet-write")]
    #[tokio::test]
    #[serial_test::serial]
    async fn recovery_endpoint_identity_refusal_refuses_the_pass() {
        let mut fx = Fx::new();
        let id = unknown_with(&mut fx, 1, NOW / 1_000 - 10, vec![]).id();
        let (writer, _) = crate::mainnet::fixtures::keyed_writer(&fx.profile.audit_log_path);
        for refuse_primary in [true, false] {
            for identity in [
                json!({"passphrase":"wrong", "protocolVersion":23}),
                json!({"passphrase":stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE, "protocolVersion":1}),
            ] {
                let primary = endpoint(7, NOW / 1_000).await;
                let oracle = endpoint(8, NOW / 1_000).await;
                Mock::given(method("POST"))
                    .and(body_partial_json(json!({"method":"getNetwork"})))
                    .respond_with(EchoIdResponder::new(identity))
                    .with_priority(1)
                    .mount(if refuse_primary { &primary } else { &oracle })
                    .await;
                let primary_client = StellarRpcClient::new(&primary.uri()).unwrap();
                let oracle_client = StellarRpcClient::new(&oracle.uri()).unwrap();
                let before = std::fs::read(fx.store.path()).unwrap();
                let error = recover_sequences(
                    &fx.store,
                    &fx.profile,
                    EndpointPair::from_clients(&primary_client, Some(&oracle_client)),
                    &writer,
                    None,
                )
                .await
                .unwrap_err();
                assert!(
                    matches!(error, RecoveryError::EndpointIdentity(_)),
                    "{error:?}"
                );
                assert_eq!(std::fs::read(fx.store.path()).unwrap(), before);
                assert!(fx.record(id).attempts[0].recovery.is_none());
            }
        }
    }

    #[tokio::test]
    async fn recovery_oracle_behind_the_primary_keeps_its_bound() {
        let primary = endpoint(8, NOW / 1_000).await;
        let oracle = endpoint(7, NOW / 1_000).await;
        let primary_client = StellarRpcClient::new(&primary.uri()).unwrap();
        let oracle_client = StellarRpcClient::new(&oracle.uri()).unwrap();
        let report = OperationalReport {
            latest_ledger: 8,
            close_time_unix: NOW / 1_000,
            close_lag_seconds: 0,
        };
        let observation = submission_observation(
            &primary_client,
            Some(&oracle_client),
            Some(&report),
            Instant::now() + Duration::from_secs(2),
        )
        .await;
        assert_eq!(observation.pre_exposure_ledger, Some(7));
        assert_eq!(requested_starts(&oracle).await, [7]);
        let mut attempt = attempt(NOW / 1_000 - 1);
        attempt.pre_exposure_ledger = observation.pre_exposure_ledger;
        let batch = collect(
            &EndpointPair::from_clients(&primary_client, Some(&oracle_client)),
            &[attempt],
            NOW,
        )
        .await
        .unwrap();
        let input = &batch.inputs[0].2;
        assert!(!input.recovery.as_ref().unwrap().history_incomplete);
        assert!(input.sequence_released.is_some());
    }

    #[cfg(feature = "mainnet-write")]
    #[tokio::test]
    #[serial_test::serial]
    async fn recovery_release_admits_a_second_envelope_through_the_recorder() {
        use crate::SubmissionRecorder;
        use crate::mainnet::fixtures;
        let (fx, attempt, first) = exposed_fixture("recovery-reuse").await;
        let later = NOW + 200_000;
        fx.clock.set(later);
        // Another envelope at the first envelope's source and sequence.
        let envelope = |offset: u64, signed: bool| {
            let builder = stellar_agent_test_support::signed_envelope::SignedTestEnvelope::builder(
                fixtures::SIGNER_SEED,
            )
            .network_passphrase(stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE)
            .time_bounds(0, later / 1_000 + 120 + offset)
            .sequence(fixtures::SEQUENCE);
            if signed {
                builder.build()
            } else {
                builder.unsigned().build()
            }
        };
        let submit = |offset: u64, nonce: &'static str| {
            let unsigned = envelope(offset, false);
            let intent = fixtures::intent(&envelope(offset, true));
            assert_eq!(
                (intent.source.as_str(), intent.sequence),
                (first.source.as_str(), first.sequence)
            );
            let grant = fx.mint(
                fixtures::tx_binding(unsigned.envelope_xdr(), unsigned.tx_hash_hex()),
                &[],
                None,
                nonce,
            );
            let recorder = fx.recorder(vec![], Some(Arc::clone(&fx.writer)));
            async move {
                let result = recorder
                    .pre_send_authorized(&intent, crate::MainnetSubmitGrant::Tx(grant))
                    .await;
                (intent, result)
            }
        };
        let (unreleased, refused) = submit(1, "approval-unreleased").await;
        let refused = refused.unwrap_err();
        assert!(
            format!("{refused:?}").contains(&first.tx_hash),
            "{refused:?}"
        );
        assert!(
            fx.receipts
                .get(&unreleased.envelope_hash)
                .unwrap()
                .is_none()
        );
        let primary = endpoint(9, later / 1_000).await;
        let oracle = endpoint(10, later / 1_000).await;
        let primary_client = StellarRpcClient::new(&primary.uri()).unwrap();
        let oracle_client = StellarRpcClient::new(&oracle.uri()).unwrap();
        recover_sequences(
            &fx.window,
            &fx.profile,
            EndpointPair::from_clients(&primary_client, Some(&oracle_client)),
            &fx.writer,
            None,
        )
        .await
        .unwrap();
        assert!(fx.operation_record(attempt)["attempts"][0]["sequence_released"].is_object());
        let (released, admitted) = submit(2, "approval-released").await;
        assert!(
            !format!("{admitted:?}").contains(&first.tx_hash),
            "{admitted:?}"
        );
        assert!(fx.receipts.get(&released.envelope_hash).unwrap().is_some());
    }

    #[cfg(feature = "mainnet-write")]
    #[tokio::test]
    #[serial_test::serial]
    async fn recovery_status_keeps_its_answer_when_recovery_refuses() {
        let mut fx = Fx::new();
        let id = unknown_with(&mut fx, 1, NOW / 1_000 - 10, vec![]).id();
        let snapshot = OperationStatus::new(&fx.store, &fx.profile)
            .recovery_snapshot(None)
            .unwrap();
        let ExposureIdentity::Classic {
            tx_hash,
            envelope_sha256,
            sequence,
            max_time,
            ..
        } = snapshot[0].exposure.clone()
        else {
            panic!("classic attempt required")
        };
        let primary = endpoint(7, NOW / 1_000).await;
        let oracle = endpoint(8, NOW / 1_000).await;
        for server in [&primary, &oracle] {
            mount(server, "getTransaction", json!({"status":"NOT_FOUND","latestLedger":7,"oldestLedger":1,"latestLedgerCloseTime":(NOW/1000).to_string(),"oldestLedgerCloseTime":"1"})).await;
        }
        Mock::given(method("POST"))
            .and(body_partial_json(
                json!({"method":"getLedgers", "params":{"pagination":{"limit":200}}}),
            ))
            .respond_with(move |request: &wiremock::Request| {
                ledgers_responder(7, NOW / 1_000)(request).set_delay(Duration::from_millis(800))
            })
            .with_priority(1)
            .mount(&primary)
            .await;
        let primary_client = StellarRpcClient::new(&primary.uri()).unwrap();
        let oracle_client = StellarRpcClient::new(&oracle.uri()).unwrap();
        let (writer, _) = crate::mainnet::fixtures::keyed_writer(&fx.profile.audit_log_path);
        let home = tempfile::tempdir().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
        // The requested transaction has a pending receipt.
        let receipts = crate::submission_flow::open_receipts("ops").unwrap();
        receipts
            .try_begin(
                &stellar_agent_core::hex::encode(&envelope_sha256),
                &stellar_agent_core::hex::encode(&tx_hash),
                &crate::mainnet::fixtures::account([1; 32]),
                sequence,
                max_time,
                1,
            )
            .unwrap();
        receipts
            .mark_submitted(&stellar_agent_core::hex::encode(&envelope_sha256))
            .unwrap();
        let tx_hash = stellar_agent_core::hex::encode(&tx_hash);
        let lookup = || {
            crate::submission_flow::transaction_status(
                crate::submission_flow::StatusRequest {
                    profile: &fx.profile,
                    profile_name: "ops",
                    tx_hash: &tx_hash,
                    window: &fx.store,
                    client: &primary_client,
                    oracle: Some(&oracle_client),
                },
                || Ok(home.path().join("approvals")),
                || Ok(Arc::clone(&writer)),
            )
        };
        // The control lookup runs without the recovery stage.
        crate::submission_flow::STATUS_RECOVERY_DISABLED.set(true);
        let control = lookup().await.unwrap();
        crate::submission_flow::STATUS_RECOVERY_DISABLED.set(false);
        assert!(control.record.is_some(), "{control:?}");
        assert_eq!(fx.record(id).attempts[0].recovery, None);
        // An owed accounting expiry, so the drain has a row to deliver.
        let expired = super::super::SubmissionHold {
            chain_scope: super::super::ChainScope::for_chain(fx.profile.chain_id),
            id: "e1".repeat(32),
            tx_hash: "e2".repeat(32),
            source: crate::mainnet::fixtures::account([1; 32]),
            sequence: 9,
            max_time: NOW / 1_000 - 120,
            pending_since_ms: NOW - 200_000,
            submission_ledger: 1,
            submission_anchor: None,
            operator_required: false,
        };
        fx.store
            .record_pending(
                &fx.profile,
                &[stellar_agent_core::policy::v1::criteria::state_store::WindowEntry::new(
                    stellar_agent_core::policy::v1::criteria::state_store::StateKey::new(
                        "ops", 1, "native", 60,
                    ),
                    NOW - 200_000,
                    300,
                    stellar_agent_core::policy::v1::criteria::state_store::WindowLimit::Amount {
                        asset: "native".to_owned(),
                        window: "1d".to_owned(),
                        max_stroops: 1_000_000,
                    },
                )],
                &expired,
            )
            .unwrap();
        fx.store
            .expire_accounting(&fx.profile, None, &expired, NOW)
            .unwrap();
        let owed = fx.store.owed_accounting_expiries(&fx.profile).unwrap();
        let [decision_id] = owed.unacknowledged.as_slice() else {
            panic!("one owed decision required: {owed:?}")
        };
        let audit_log = || std::fs::read_to_string(&fx.profile.audit_log_path).unwrap_or_default();
        assert!(!audit_log().contains(decision_id.as_str()));
        let mut sink = Sink::default();
        let (refused, ()) = tokio::join!(lookup(), async {
            tokio::time::sleep(Duration::from_millis(200)).await;
            OperationRecorder::new(&fx.store, &fx.profile, &mut sink, "concurrent")
                .record_evidence(
                    id,
                    1,
                    &EvidenceInput {
                        recovery: Some(RecoveryUpdate {
                            disagreements: 3,
                            ..RecoveryUpdate::default()
                        }),
                        ..EvidenceInput::default()
                    },
                )
                .unwrap();
        });
        let refused = refused.unwrap();
        // The stale snapshot commits nothing: the concurrent update stands.
        let recovery = fx.record(id).attempts[0].recovery.clone().unwrap();
        assert_eq!(recovery.disagreements, 3);
        assert_eq!(recovery.last_pass_at_ms, None);
        // The status values equal the control's, field by field.
        assert_eq!(refused.chain_status, control.chain_status);
        assert_eq!(refused.ledger, control.ledger);
        assert_eq!(refused.record, control.record);
        assert_eq!(refused.reservation, control.reservation);
        assert_eq!(refused.reservation_open, control.reservation_open);
        // The drain delivered the owed row through the writer.
        assert!(audit_log().contains(decision_id.as_str()));
        assert!(
            fx.store
                .owed_accounting_expiries(&fx.profile)
                .unwrap()
                .unacknowledged
                .is_empty()
        );
    }
}
