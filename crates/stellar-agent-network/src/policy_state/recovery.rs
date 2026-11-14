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
use stellar_rpc_client::{GetLedgersResponse, LedgerStart};
use tokio::time::Instant;

use super::operations::{
    AgreedOutcome, EvidenceAnswer, EvidenceEndpoint, EvidenceInput, EvidenceRowInput,
    ExposureIdentity, NotIncludedProof, OperationId, OperationRecorder, OperationStatus,
    RecoveryAttempt, RecoveryUpdate, SequenceReleaseInput, WindowObservation,
};
use super::{PersistedWindowStore, WindowStoreError};
use crate::operational::OperationalReport;
use crate::{MainnetOracle, StellarRpcClient};

const ATTEMPT_REQUESTS: usize = 24;
const SHARED_REQUESTS: usize = 9;
const PASS_DURATION: Duration = Duration::from_secs(20);
const OBSERVATION_AGE: Duration = Duration::from_secs(5);
const PAGE_SIZE: usize = 1;

/// The evidence a bounded recovery read cannot obtain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum RecoveryReason {
    /// A response exceeds the 10 MiB transport limit.
    ResponseTooLarge,
    /// The endpoint rejects work because it is overloaded.
    RateLimited,
    /// The transport cannot deliver the response.
    Transport,
    /// The response omits a required field or has an invalid shape.
    MissingField,
    /// The endpoint or observation is too old for this pass.
    Lagging,
    /// The absolute pass deadline expires.
    Deadline,
    /// The request allowance is exhausted.
    RequestBudget,
    /// The account response cannot support recovery.
    AccountUnavailable,
    /// The paired interval proof is unavailable.
    CoverageRequired,
}

/// An endpoint role from the configured recovery pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum RecoveryEndpoint {
    /// The submission endpoint.
    Primary,
    /// The independent oracle.
    Oracle,
}

/// A recovery RPC method, without endpoint URLs or server text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum RecoveryMethod {
    /// Network and protocol identity.
    GetNetwork,
    /// Compact endpoint readiness.
    GetHealth,
    /// Transaction lookup by hash.
    GetTransaction,
    /// Ledger close-time evidence.
    GetLedgers,
    /// Source account evidence.
    GetLedgerEntries,
}

/// Bounded context for a missing recovery observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct RecoveryFailure {
    /// The typed cause, without raw provider error text.
    pub reason: RecoveryReason,
    /// The configured endpoint role.
    pub endpoint: RecoveryEndpoint,
    /// The method whose evidence is missing.
    pub method: RecoveryMethod,
    /// The requested ledger when the method names one.
    pub ledger: Option<u32>,
}

fn stream_is_length_limit(error: &(dyn std::error::Error + Send + Sync + 'static)) -> bool {
    error.is::<http_body_util::LengthLimitError>()
}

fn rpc_failure(error: &stellar_rpc_client::Error) -> RecoveryReason {
    use jsonrpsee_core::{ClientError, http_helpers::HttpError};
    use jsonrpsee_http_client::transport::Error as HttpTransportError;
    match error {
        stellar_rpc_client::Error::JsonRpc(ClientError::Transport(error)) => {
            match error.downcast_ref::<HttpTransportError>() {
                Some(HttpTransportError::Http(HttpError::TooLarge)) => {
                    RecoveryReason::ResponseTooLarge
                }
                Some(HttpTransportError::Http(HttpError::Stream(error)))
                    if stream_is_length_limit(error.as_ref()) =>
                {
                    RecoveryReason::ResponseTooLarge
                }
                Some(HttpTransportError::Rejected {
                    status_code: 429 | 503,
                }) => RecoveryReason::RateLimited,
                _ => RecoveryReason::Transport,
            }
        }
        stellar_rpc_client::Error::JsonRpc(ClientError::Call(error)) if error.code() == -32001 => {
            RecoveryReason::RateLimited
        }
        stellar_rpc_client::Error::JsonRpc(ClientError::ParseError(_)) => {
            RecoveryReason::MissingField
        }
        stellar_rpc_client::Error::JsonRpc(ClientError::RequestTimeout) => RecoveryReason::Deadline,
        _ => RecoveryReason::Transport,
    }
}

fn read_failure(error: &dyn std::any::Any) -> RecoveryReason {
    use crate::client::RecoveryReadError;
    use stellar_agent_core::error::{NetworkError, ProtocolError};
    if let Some(error) = error.downcast_ref::<stellar_rpc_client::Error>() {
        return rpc_failure(error);
    }
    match error.downcast_ref::<RecoveryReadError>() {
        Some(RecoveryReadError::Rpc(error)) => rpc_failure(error),
        Some(RecoveryReadError::Shape) => RecoveryReason::MissingField,
        Some(RecoveryReadError::Validation(WalletError::Network(
            NetworkError::AccountNotFound { .. },
        ))) => RecoveryReason::CoverageRequired,
        Some(RecoveryReadError::Validation(WalletError::Protocol(
            ProtocolError::XdrCodecFailed { .. },
        ))) => RecoveryReason::MissingField,
        Some(RecoveryReadError::Validation(_)) => RecoveryReason::AccountUnavailable,
        None => RecoveryReason::Transport,
    }
}

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
        let oracle = self.oracle.ok_or_else(|| {
            budget.context(RecoveryEndpoint::Oracle, RecoveryMethod::GetNetwork, None);
            budget.failed(RecoveryReason::MissingField);
            IdentityFailure::Read(ReadFailure::Pending)
        })?;
        budget.context(RecoveryEndpoint::Primary, RecoveryMethod::GetNetwork, None);
        budget.identity(self.primary.recovery_identity()).await?;
        budget.context(RecoveryEndpoint::Oracle, RecoveryMethod::GetNetwork, None);
        budget
            .identity(MainnetOracle::verify_once(oracle, budget.deadline))
            .await?;
        Ok(())
    }
}

/// Why recovery cannot supply all requested evidence, including durable partial progress.
#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    /// The window store refuses the snapshot or a commit.
    #[error(transparent)]
    Store(#[from] WindowStoreError),
    /// An endpoint reports another network or an unsupported protocol.
    #[error(transparent)]
    EndpointIdentity(WalletError),
    /// A bounded read cannot obtain required evidence.
    #[error("recovery needs evidence: {0:?}")]
    NeedsEvidence(RecoveryFailure),
    /// A refusal with diagnostic context from the remaining recovery work.
    #[error("{source}; {detail}")]
    Context {
        /// The refusal whose stable code remains authoritative.
        #[source]
        source: Box<RecoveryError>,
        /// Verified progress or a bounded receipt repair report.
        /// Repair counts include every decision. Entries name the first
        /// `REPAIR_DECISION_DETAIL_LIMIT` (16) decisions in stored order,
        /// followed by one item stating how many more decisions exist.
        detail: String,
    },
}

impl RecoveryError {
    /// The stable error code of the refusal.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Store(error) => error.submission_code(),
            Self::EndpointIdentity(error) => error.code(),
            Self::NeedsEvidence(_) => "recovery.needs_evidence",
            Self::Context { source, .. } => source.code(),
        }
    }

    pub(crate) fn with_context(self, detail: String) -> Self {
        Self::Context {
            source: Box::new(self),
            detail,
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
    Failed(RecoveryReason),
    Deadline,
}

struct Budget {
    used: RecoveryRequests,
    deadline: Instant,
    context: (RecoveryEndpoint, RecoveryMethod, Option<u32>),
    failure: Option<RecoveryFailure>,
}

impl Budget {
    fn new() -> Self {
        Self {
            used: RecoveryRequests::default(),
            deadline: Instant::now() + PASS_DURATION,
            context: (RecoveryEndpoint::Primary, RecoveryMethod::GetNetwork, None),
            failure: None,
        }
    }

    fn context(&mut self, endpoint: RecoveryEndpoint, method: RecoveryMethod, ledger: Option<u32>) {
        self.context = (endpoint, method, ledger);
    }

    fn failed(&mut self, reason: RecoveryReason) {
        self.failure.get_or_insert(RecoveryFailure {
            reason,
            endpoint: self.context.0,
            method: self.context.1,
            ledger: self.context.2,
        });
    }

    /// Charges one request before its await.
    fn charge(&mut self, shared: bool) -> Result<(), ReadFailure> {
        if Instant::now() >= self.deadline {
            self.failed(RecoveryReason::Deadline);
            return Err(ReadFailure::Deadline);
        }
        let (used, capacity) = if shared {
            (&mut self.used.shared, SHARED_REQUESTS)
        } else {
            (&mut self.used.attempt, ATTEMPT_REQUESTS)
        };
        if *used >= capacity {
            self.failed(RecoveryReason::RequestBudget);
            return Err(ReadFailure::Pending);
        }
        *used += 1;
        Ok(())
    }

    async fn read<T, E: 'static>(
        &mut self,
        shared: bool,
        request: impl Future<Output = Result<T, E>>,
    ) -> Result<T, ReadFailure> {
        self.charge(shared)?;
        match tokio::time::timeout_at(self.deadline, request).await {
            Err(_) => {
                self.failed(RecoveryReason::Deadline);
                Err(ReadFailure::Deadline)
            }
            Ok(Err(error)) => {
                let reason = read_failure(&error);
                self.failed(reason);
                Err(ReadFailure::Failed(reason))
            }
            Ok(Ok(value)) => Ok(value),
        }
    }

    async fn identity<T>(
        &mut self,
        request: impl Future<Output = Result<T, crate::client::RecoveryReadError>>,
    ) -> Result<T, IdentityFailure> {
        self.charge(true).map_err(IdentityFailure::Read)?;
        match tokio::time::timeout_at(self.deadline, request).await {
            Err(_) => {
                self.failed(RecoveryReason::Deadline);
                Err(IdentityFailure::Read(ReadFailure::Deadline))
            }
            Ok(Ok(value)) => Ok(value),
            Ok(Err(crate::client::RecoveryReadError::Validation(error)))
                if identity_refusal(&error) =>
            {
                Err(IdentityFailure::Refused(error))
            }
            Ok(Err(error)) => {
                self.failed(read_failure(&error));
                Err(IdentityFailure::Read(ReadFailure::Pending))
            }
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
    ordered_digest(answers)
}

/// The SHA-256 of the ordered `[primary, oracle]` JSON bytes.
fn ordered_digest<T: Serialize>(answers: &[T; 2]) -> Result<[u8; 32], WindowStoreError> {
    serde_json::to_vec(answers)
        .map(|bytes| Sha256::digest(bytes).into())
        .map_err(|_| WindowStoreError::Invalid {
            detail: "recovery evidence cannot be serialized".to_owned(),
        })
}

/// The detail of an answer whose deciding field is absent.
const MISSING_FIELD: &str = "missing_field";

/// The detail of a creation time that is negative or does not parse.
const INVALID_TIME: &str = "invalid_time";

/// Encodes a raw `createdAt` value as canonical Unix seconds.
///
/// An absent value is `None`. A non-negative JSON integer, or a string of
/// decimal digits that fits a `u64`, is valid. Every other value, a
/// negative or fractional number included, is [`INVALID_TIME`].
///
/// # Errors
///
/// [`INVALID_TIME`] for a present value that is not a valid time.
fn canonical_time(raw: Option<&serde_json::Value>) -> Result<Option<u64>, &'static str> {
    match raw {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::Number(number)) => number.as_u64().map(Some).ok_or(INVALID_TIME),
        Some(serde_json::Value::String(text))
            if !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) =>
        {
            text.parse::<u64>().map(Some).map_err(|_| INVALID_TIME)
        }
        Some(_) => Err(INVALID_TIME),
    }
}

/// A canonical transaction answer, in its fixed field order.
///
/// Missing values serialize as `null` and integers as JSON numbers. String
/// fields keep the endpoint's text byte for byte. A creation time that is
/// not valid serializes as `null` and sets [`Self::time_defect`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct OutcomeAnswer {
    /// The status text.
    pub status: Option<String>,
    /// The including ledger.
    pub ledger: Option<u32>,
    /// The canonical creation time in Unix seconds.
    pub created_at: Option<u64>,
    /// The transaction hash text.
    pub tx_hash: Option<String>,
    /// The envelope XDR text.
    pub envelope_xdr: Option<String>,
    /// The result XDR text.
    pub result_xdr: Option<String>,
    /// The endpoint's latest ledger.
    pub latest_ledger: Option<u32>,
    /// The endpoint's oldest retained ledger.
    pub oldest_ledger: Option<u32>,
    /// `invalid_time` when the raw creation time is present and invalid.
    #[serde(skip)]
    pub time_defect: Option<&'static str>,
}

impl OutcomeAnswer {
    /// The canonical answer of one observed `getTransaction` read.
    #[must_use]
    fn from_observed(observed: &crate::ObservedTransaction) -> Self {
        let (created_at, time_defect) = match canonical_time(observed.created_at.as_ref()) {
            Ok(time) => (time, None),
            Err(defect) => (None, Some(defect)),
        };
        Self {
            status: observed.status.clone(),
            ledger: observed.ledger,
            created_at,
            tx_hash: observed.tx_hash.clone(),
            envelope_xdr: observed.envelope_xdr.clone(),
            result_xdr: observed.result_xdr.clone(),
            latest_ledger: observed.latest_ledger,
            oldest_ledger: observed.oldest_ledger,
            time_defect,
        }
    }

    /// The first defect that keeps the answer from deciding: an invalid
    /// time, then a missing field. An inclusion needs every field; an
    /// absence needs its status and both coverage ledgers.
    #[must_use]
    fn defect(&self) -> Option<&'static str> {
        if let Some(defect) = self.time_defect {
            return Some(defect);
        }
        let coverage = self.latest_ledger.is_some() && self.oldest_ledger.is_some();
        let complete = match self.status.as_deref() {
            None => false,
            Some("SUCCESS" | "FAILED") => {
                coverage
                    && self.ledger.is_some()
                    && self.created_at.is_some()
                    && self.tx_hash.is_some()
                    && self.envelope_xdr.is_some()
                    && self.result_xdr.is_some()
            }
            Some(_) => coverage,
        };
        (!complete).then_some(MISSING_FIELD)
    }

    /// The persisted evidence row: XDR texts become their SHA-256 digests.
    /// The observed ledger is the answer's latest ledger, otherwise
    /// `fallback`, the endpoint's shared observation; with neither, no row.
    #[must_use]
    pub fn row(
        &self,
        endpoint: EvidenceEndpoint,
        digest: [u8; 32],
        fallback: Option<u32>,
    ) -> Option<EvidenceRowInput> {
        let xdr_digest =
            |text: &Option<String>| text.as_deref().map(|xdr| Sha256::digest(xdr).into());
        Some(EvidenceRowInput {
            endpoint,
            observed_ledger: self.latest_ledger.or(fallback)?,
            answer: EvidenceAnswer::Outcome {
                status: self.status.clone(),
                ledger: self.ledger,
                created_at: self.created_at,
                tx_hash: self.tx_hash.clone(),
                envelope_xdr: xdr_digest(&self.envelope_xdr),
                result_xdr: xdr_digest(&self.result_xdr),
                latest_ledger: self.latest_ledger,
                oldest_ledger: self.oldest_ledger,
            },
            digest,
        })
    }
}

/// A canonical account answer, in its fixed field order.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct AccountAnswer {
    /// The account's sequence.
    pub sequence: Option<i64>,
    /// The endpoint's latest ledger.
    pub latest_ledger: Option<u32>,
}

impl AccountAnswer {
    /// The persisted evidence row, observed at the answer's latest ledger,
    /// otherwise at `fallback`; with neither, no row.
    #[must_use]
    pub fn row(
        self,
        endpoint: EvidenceEndpoint,
        digest: [u8; 32],
        fallback: Option<u32>,
    ) -> Option<EvidenceRowInput> {
        Some(EvidenceRowInput {
            endpoint,
            observed_ledger: self.latest_ledger.or(fallback)?,
            answer: EvidenceAnswer::Account {
                sequence: self.sequence,
                latest_ledger: self.latest_ledger,
            },
            digest,
        })
    }
}

/// The digest of ordered `[primary, oracle]` outcome answers.
///
/// # Errors
///
/// [`WindowStoreError::Invalid`] when the answers cannot be serialized.
fn outcome_digest(answers: &[OutcomeAnswer; 2]) -> Result<[u8; 32], WindowStoreError> {
    ordered_digest(answers)
}

/// The digest of ordered `[primary, oracle]` account answers.
///
/// # Errors
///
/// [`WindowStoreError::Invalid`] when the answers cannot be serialized.
fn account_digest(answers: &[AccountAnswer; 2]) -> Result<[u8; 32], WindowStoreError> {
    ordered_digest(answers)
}

struct SharedObservation {
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
) -> Result<SharedObservation, ReadFailure> {
    let read_at = Instant::now();
    budget.context(budget.context.0, RecoveryMethod::GetHealth, None);
    let observed = budget.read(true, client.recovery_health()).await?;
    let report =
        OperationalReport::from_health_observation(&observed, now_ms / 1_000).map_err(|_| {
            budget.failed(RecoveryReason::Lagging);
            ReadFailure::Pending
        })?;
    Ok(SharedObservation {
        oldest: observed.health.oldest_ledger,
        report,
        read_at,
    })
}

#[derive(Debug)]
struct Scan {
    answer: LedgerAnswer,
    cursor: u32,
    upper: Option<u32>,
    incomplete: bool,
    entries: Vec<(u32, u64)>,
}

fn scan_page(
    page: &GetLedgersResponse,
    cursor: u32,
    max_time: u64,
    requested: usize,
) -> Option<Scan> {
    let start = cursor.max(page.oldest_ledger);
    let mut next = start;
    let mut last_close = 0;
    let mut entries = Vec::new();
    let mut boundary = None;
    if page.ledgers.is_empty() || page.ledgers.len() > requested {
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
        || (page.ledgers.len() < requested && last.0 != page.latest_ledger)
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
    target: u32,
) -> Result<Option<Scan>, ReadFailure> {
    let saved = &attempt.recovery;
    let upper = if primary {
        saved.primary_upper
    } else {
        saved.witness_upper
    };
    let ExposureIdentity::Classic { max_time, .. } = attempt.exposure else {
        return Ok(None);
    };
    budget.context(
        if primary {
            RecoveryEndpoint::Primary
        } else {
            RecoveryEndpoint::Oracle
        },
        RecoveryMethod::GetLedgers,
        Some(target),
    );
    if target < shared.oldest || upper.is_some_and(|ledger| ledger > target) {
        budget.failed(RecoveryReason::CoverageRequired);
        return Err(ReadFailure::Failed(RecoveryReason::CoverageRequired));
    }
    let page = budget
        .read(
            false,
            client
                .inner
                .get_ledgers(LedgerStart::Ledger(target), Some(PAGE_SIZE), None),
        )
        .await;
    let page = match page {
        Err(ReadFailure::Failed(RecoveryReason::MissingField)) => {
            return Ok(None);
        }
        other => other?,
    };
    if target < page.oldest_ledger {
        budget.failed(RecoveryReason::CoverageRequired);
        return Err(ReadFailure::Failed(RecoveryReason::CoverageRequired));
    }
    let scan = scan_page(&page, target, max_time, PAGE_SIZE);
    if scan.is_none() {
        budget.failed(RecoveryReason::MissingField);
    }
    Ok(scan)
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
        ) && primary_ledger == witness_ledger
            && left == right
        {
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

/// The transition a checked recovery decision commits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecidedTransition {
    /// Both endpoints report the same successful inclusion of the envelope.
    Succeeded(AgreedOutcome),
    /// Both endpoints report the same failed inclusion of the envelope.
    Failed {
        /// The agreed outcome.
        outcome: AgreedOutcome,
        /// The fee the chain charged, between zero and the envelope's cap.
        fee_charged: i64,
    },
    /// Both endpoints prove the envelope can never apply.
    NotIncluded(NotIncludedProof),
}

/// A recovery transition decided from one pass's two-endpoint evidence.
///
/// Only this module constructs one, from a verified recovery snapshot. It
/// binds the operation, the attempt, the exposed envelope digest, the
/// snapshot generation and the evidence digest. The operation facade
/// rechecks the generation and identity before any accounting, so a
/// decision from a stale snapshot or for another attempt commits nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedRecoveryDecision {
    operation_id: OperationId,
    attempt_index: u32,
    envelope_sha256: [u8; 32],
    generation: u64,
    evidence_digest: [u8; 32],
    ledgers: (u32, u32),
    transition: DecidedTransition,
    recovery: RecoveryUpdate,
}

impl CheckedRecoveryDecision {
    /// A decision about `attempt`'s classic exposure, from evidence whose
    /// ordered answers hash to `evidence_digest` and whose deciding primary
    /// and oracle ledgers are `ledgers`.
    pub(super) fn new(
        attempt: &RecoveryAttempt,
        evidence_digest: [u8; 32],
        ledgers: (u32, u32),
        transition: DecidedTransition,
        recovery: RecoveryUpdate,
    ) -> Option<Self> {
        let ExposureIdentity::Classic {
            envelope_sha256, ..
        } = attempt.exposure
        else {
            return None;
        };
        Some(Self {
            operation_id: attempt.operation_id,
            attempt_index: attempt.attempt_index,
            envelope_sha256,
            generation: attempt.generation,
            evidence_digest,
            ledgers,
            transition,
            recovery,
        })
    }

    pub(super) fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    pub(super) fn attempt_index(&self) -> u32 {
        self.attempt_index
    }

    pub(super) fn envelope_sha256(&self) -> [u8; 32] {
        self.envelope_sha256
    }

    pub(super) fn generation(&self) -> u64 {
        self.generation
    }

    pub(super) fn evidence_digest(&self) -> [u8; 32] {
        self.evidence_digest
    }

    pub(super) fn ledgers(&self) -> (u32, u32) {
        self.ledgers
    }

    pub(super) fn transition(&self) -> &DecidedTransition {
        &self.transition
    }

    pub(super) fn recovery(&self) -> &RecoveryUpdate {
        &self.recovery
    }
}

/// The detail of an envelope or result XDR that does not decode.
const XDR_MALFORMED: &str = "xdr_malformed";
/// The detail of a status its result code contradicts.
const STATUS_RESULT_MISMATCH: &str = "status_result_mismatch";
/// The detail of a charged fee below zero or above the envelope's cap.
const FEE_INVALID: &str = "fee_invalid";
/// The detail of differing inclusion close times.
const CLOSE_TIME_MISMATCH: &str = "close_time_mismatch";
/// The detail of differing statuses, or one inclusion beside a covered absence.
const STATUS_MISMATCH: &str = "status_mismatch";
/// The detail of differing inclusion ledgers.
const LEDGER_MISMATCH: &str = "ledger_mismatch";
/// The detail of a transaction hash other than the exposed one.
const HASH_MISMATCH: &str = "hash_mismatch";
/// The detail of an envelope other than the exposed one, or differing texts.
const ENVELOPE_MISMATCH: &str = "envelope_mismatch";
/// The detail of differing result texts.
const RESULT_MISMATCH: &str = "result_mismatch";

/// What one pass's two transaction answers say about an attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
enum OutcomeClass {
    /// Both endpoints report the same valid inclusion of the exposed envelope.
    Decided(DecidedTransition),
    /// Both endpoints report the transaction missing, with coverage.
    Absent,
    /// The answers differ or are invalid; the detail names why.
    Disagreement(&'static str),
    /// The answers decide nothing yet; the detail names why.
    Pending(&'static str),
}

/// Classifies the ordered `[primary, oracle]` transaction answers against
/// `attempt`'s exposure.
///
/// An inclusion decides only when both endpoints report the same status,
/// ledger, close time and the exposed transaction hash, and byte-equal
/// envelope and result texts. The envelope text must hash to the exposed
/// digest, and both XDRs must decode. The result code must agree with the
/// status, and the charged fee must lie between zero and the envelope's cap.
#[must_use]
fn classify_outcome(attempt: &RecoveryAttempt, answers: &[OutcomeAnswer; 2]) -> OutcomeClass {
    use OutcomeClass as C;
    let ExposureIdentity::Classic {
        envelope_sha256,
        tx_hash,
        ..
    } = &attempt.exposure
    else {
        return C::Pending(MISSING_FIELD);
    };
    if answers.iter().any(|answer| answer.time_defect.is_some()) {
        return C::Disagreement(INVALID_TIME);
    }
    let included = |status: Option<&str>| matches!(status, Some("SUCCESS" | "FAILED"));
    let [primary, oracle] = answers;
    let statuses = (primary.status.as_deref(), oracle.status.as_deref());
    match statuses {
        (Some("NOT_FOUND"), Some("NOT_FOUND")) => {
            return match answers.iter().find_map(OutcomeAnswer::defect) {
                Some(defect) => C::Pending(defect),
                None => C::Absent,
            };
        }
        (left, right) if included(left) && included(right) => {
            if left != right {
                return C::Disagreement(STATUS_MISMATCH);
            }
        }
        (left, right) if included(left) || included(right) => {
            // One inclusion beside an absence that covers its ledger disagrees;
            // an absence that does not reach it yet is pending.
            let (inclusion, absence) = if included(left) {
                (primary, oracle)
            } else {
                (oracle, primary)
            };
            return match (inclusion.ledger, absence.latest_ledger) {
                (Some(ledger), Some(latest)) if latest >= ledger => {
                    C::Disagreement(STATUS_MISMATCH)
                }
                _ => C::Pending(MISSING_FIELD),
            };
        }
        _ => return C::Pending(MISSING_FIELD),
    }
    if let Some(defect) = answers.iter().find_map(OutcomeAnswer::defect) {
        return C::Pending(defect);
    }
    if primary.ledger != oracle.ledger {
        return C::Disagreement(LEDGER_MISMATCH);
    }
    if primary.created_at != oracle.created_at {
        return C::Disagreement(CLOSE_TIME_MISMATCH);
    }
    let local = stellar_agent_core::hex::encode(tx_hash);
    if answers
        .iter()
        .any(|answer| answer.tx_hash.as_deref() != Some(local.as_str()))
    {
        return C::Disagreement(HASH_MISMATCH);
    }
    if primary.envelope_xdr != oracle.envelope_xdr {
        return C::Disagreement(ENVELOPE_MISMATCH);
    }
    if primary.result_xdr != oracle.result_xdr {
        return C::Disagreement(RESULT_MISMATCH);
    }
    let (Some(status), Some(ledger), Some(created_at), Some(envelope), Some(result)) = (
        primary.status.as_deref(),
        primary.ledger,
        primary.created_at,
        primary.envelope_xdr.as_deref(),
        primary.result_xdr.as_deref(),
    ) else {
        return C::Pending(MISSING_FIELD);
    };
    if <[u8; 32]>::from(Sha256::digest(envelope)) != *envelope_sha256 {
        return C::Disagreement(ENVELOPE_MISMATCH);
    }
    let limits = |text: &str| stellar_agent_xdr_limits::untrusted_decode_limits(text.len());
    let (Ok(decoded), Ok(decoded_result)) = (
        <stellar_xdr::TransactionEnvelope as stellar_xdr::ReadXdr>::from_xdr_base64(
            envelope,
            limits(envelope),
        ),
        <stellar_xdr::TransactionResult as stellar_xdr::ReadXdr>::from_xdr_base64(
            result,
            limits(result),
        ),
    ) else {
        return C::Disagreement(XDR_MALFORMED);
    };
    let success = matches!(
        decoded_result.result,
        stellar_xdr::TransactionResultResult::TxSuccess(_)
            | stellar_xdr::TransactionResultResult::TxFeeBumpInnerSuccess(_)
    );
    if success != (status == "SUCCESS") {
        return C::Disagreement(STATUS_RESULT_MISMATCH);
    }
    let cap = match &decoded {
        stellar_xdr::TransactionEnvelope::TxV0(envelope) => i64::from(envelope.tx.fee),
        stellar_xdr::TransactionEnvelope::Tx(envelope) => i64::from(envelope.tx.fee),
        stellar_xdr::TransactionEnvelope::TxFeeBump(envelope) => envelope.tx.fee,
    };
    let fee_charged = decoded_result.fee_charged;
    if !(0..=cap).contains(&fee_charged) {
        return C::Disagreement(FEE_INVALID);
    }
    let outcome = AgreedOutcome {
        status: status.to_owned(),
        ledger,
        created_at,
        result_xdr: result.to_owned(),
        envelope_xdr_sha256: *envelope_sha256,
    };
    C::Decided(if success {
        DecidedTransition::Succeeded(outcome)
    } else {
        DecidedTransition::Failed {
            outcome,
            fee_charged,
        }
    })
}

/// The account answers of one pass: both endpoints', or the defect that
/// keeps them from deciding.
type AccountRead = Result<[AccountAnswer; 2], &'static str>;

/// The detail of an account answer below its endpoint's readiness ledger.
const ACCOUNT_LEDGER_REGRESSED: &str = "account.ledger_regressed";

fn matched_sequence_release(attempt: &RecoveryAttempt) -> Option<SequenceReleaseInput> {
    attempt
        .sequence_release
        .filter(|release| release.primary_ledger == release.witness_ledger)
}

/// Proves `attempt` not included, from a recorded sequence release and a
/// positive finite `max_time`, by one of two branches.
///
/// The account branch needs both account sequences strictly below the
/// attempt's and each account ledger at or past that endpoint's expiry
/// ledger. The complete-history branch needs two covered absences whose
/// oldest ledgers reach back to the pre-exposure ledger and whose latest
/// ledgers reach each expiry ledger, with intact history. A regressed or
/// failed account read decides nothing and falls back to nothing.
///
/// # Errors
///
/// The pending detail when neither branch proves non-inclusion.
fn classify_non_inclusion(
    attempt: &RecoveryAttempt,
    outcome: &[OutcomeAnswer; 2],
    accounts: Option<&AccountRead>,
) -> Result<NotIncludedProof, &'static str> {
    use super::operations::EndpointCoverage;
    let ExposureIdentity::Classic {
        sequence, max_time, ..
    } = attempt.exposure
    else {
        return Err(MISSING_FIELD);
    };
    let Some(release) = matched_sequence_release(attempt) else {
        return Err("sequence_pending");
    };
    if max_time == 0 || max_time == u64::MAX {
        return Err("untimed");
    }
    let bounds = [release.primary_ledger, release.witness_ledger];
    match accounts {
        Some(Err(defect)) => return Err(defect),
        Some(Ok(answers)) => {
            let covered = answers.iter().zip(bounds).all(|(answer, bound)| {
                answer.sequence.is_some_and(|seen| seen < sequence)
                    && answer.latest_ledger.is_some_and(|latest| latest >= bound)
            });
            if covered {
                let coverage = |index: usize| {
                    let latest = answers[index].latest_ledger.unwrap_or(bounds[index]);
                    EndpointCoverage {
                        first_ledger: attempt.pre_exposure_ledger.unwrap_or(bounds[index]),
                        last_ledger: latest,
                        latest_ledger: latest,
                        oldest_ledger: outcome[index].oldest_ledger.unwrap_or(latest),
                    }
                };
                return Ok(NotIncludedProof::AccountSequence {
                    primary: coverage(0),
                    witness: coverage(1),
                });
            }
        }
        None => {}
    }
    let Some(pre_exposure) = attempt.pre_exposure_ledger else {
        return Err("history_incomplete");
    };
    if attempt.recovery.history_incomplete {
        return Err("history_incomplete");
    }
    let mut coverage = [None, None];
    for (index, answer) in outcome.iter().enumerate() {
        match (
            answer.status.as_deref(),
            answer.oldest_ledger,
            answer.latest_ledger,
            answer.time_defect,
        ) {
            (Some("NOT_FOUND"), Some(oldest), Some(latest), None)
                if oldest <= pre_exposure && latest >= bounds[index] =>
            {
                coverage[index] = Some(EndpointCoverage {
                    first_ledger: pre_exposure,
                    last_ledger: latest,
                    latest_ledger: latest,
                    oldest_ledger: oldest,
                });
            }
            _ => return Err("coverage_pending"),
        }
    }
    match coverage {
        [Some(primary), Some(witness)] => {
            Ok(NotIncludedProof::CompleteHistory { primary, witness })
        }
        _ => Err("coverage_pending"),
    }
}

/// The one transition a pass's evidence yields for an attempt, by priority.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Observed {
    /// An outcome or a non-inclusion decides the attempt.
    Decided(DecidedTransition),
    /// The first sequence release, from the ledger scans.
    SequenceReleased(SequenceReleaseInput),
    /// An outcome disagreement, which blocks every lower transition.
    Disagreement(&'static str),
    /// Nothing decides yet.
    Pending(&'static str),
}

/// Selects at most one transition for `attempt`: an outcome first, then the
/// first sequence release from `sequence`, then non-inclusion. An outcome
/// disagreement blocks the sequence release and non-inclusion. An already
/// recorded matched sequence release is skipped and its proof kept.
#[must_use]
fn observe(
    attempt: &RecoveryAttempt,
    outcome: Option<&[OutcomeAnswer; 2]>,
    sequence: Option<SequenceReleaseInput>,
    accounts: Option<&AccountRead>,
) -> Observed {
    let class = outcome.map(|answers| classify_outcome(attempt, answers));
    match &class {
        Some(OutcomeClass::Decided(transition)) => return Observed::Decided(transition.clone()),
        Some(OutcomeClass::Disagreement(detail)) => return Observed::Disagreement(detail),
        _ => {}
    }
    if matched_sequence_release(attempt).is_none() {
        return match sequence {
            Some(release) => Observed::SequenceReleased(release),
            None => Observed::Pending(match class {
                Some(OutcomeClass::Pending(detail)) => detail,
                _ => "sequence_pending",
            }),
        };
    }
    match (class, outcome) {
        (Some(OutcomeClass::Absent), Some(answers)) => {
            match classify_non_inclusion(attempt, answers, accounts) {
                Ok(proof) => Observed::Decided(DecidedTransition::NotIncluded(proof)),
                Err(detail) => Observed::Pending(detail),
            }
        }
        (Some(OutcomeClass::Pending(detail)), _) => Observed::Pending(detail),
        _ => Observed::Pending(MISSING_FIELD),
    }
}

/// Results of a bounded recovery pass, separate from legacy reconciliation counts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RecoveryReport {
    /// Requests issued under each allowance.
    pub requests: RecoveryRequests,
    /// Attempts whose evaluation commits.
    pub evaluated: usize,
    /// The first evidence this pass could not obtain or use.
    pub missing: Option<RecoveryFailure>,
}

impl RecoveryReport {
    pub(crate) fn require_evidence(self) -> Result<Self, RecoveryError> {
        match self.missing {
            Some(failure) => Err(RecoveryError::NeedsEvidence(failure)),
            None => Ok(self),
        }
    }
}

#[derive(Default)]
struct Batch {
    inputs: Vec<(OperationId, u32, EvidenceInput)>,
    observation: Option<WindowObservation>,
    requests: RecoveryRequests,
    missing: Option<RecoveryFailure>,
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
            batch.missing = budget.failure;
            return Ok(batch);
        }
        Err(IdentityFailure::Read(ReadFailure::Pending | ReadFailure::Failed(_))) => false,
    };
    let mut primary = None;
    let mut oracle = None;
    if verified {
        budget.context(RecoveryEndpoint::Primary, RecoveryMethod::GetHealth, None);
        match shared_observation(pair.primary, &mut budget, now_ms).await {
            Ok(observation) => {
                batch.observation = Some(observation.window(now_ms));
                primary = Some(observation);
            }
            Err(ReadFailure::Deadline) => {
                batch.requests = budget.used;
                batch.missing = budget.failure;
                return Ok(batch);
            }
            Err(ReadFailure::Pending | ReadFailure::Failed(_)) => {}
        }
        if let Some(client) = pair.oracle.filter(|_| primary.is_some()) {
            budget.context(RecoveryEndpoint::Oracle, RecoveryMethod::GetHealth, None);
            match shared_observation(client, &mut budget, now_ms).await {
                Ok(observation) => oracle = Some(observation),
                Err(ReadFailure::Deadline) => {
                    batch.requests = budget.used;
                    batch.missing = budget.failure;
                    return Ok(batch);
                }
                Err(ReadFailure::Pending | ReadFailure::Failed(_)) => {}
            }
        }
    }
    let mut refreshed = false;
    for attempt in attempts.iter().take(4) {
        if Instant::now() >= budget.deadline {
            budget.failed(RecoveryReason::Deadline);
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
            budget.context(RecoveryEndpoint::Primary, RecoveryMethod::GetHealth, None);
            match shared_observation(pair.primary, &mut budget, now_ms).await {
                Ok(observation) => {
                    batch.observation = Some(observation.window(now_ms));
                    primary = Some(observation);
                }
                Err(ReadFailure::Deadline) => break,
                Err(ReadFailure::Pending | ReadFailure::Failed(_)) => primary = None,
            }
            budget.context(RecoveryEndpoint::Oracle, RecoveryMethod::GetHealth, None);
            match shared_observation(client, &mut budget, now_ms).await {
                Ok(observation) => oracle = Some(observation),
                Err(ReadFailure::Deadline) => break,
                Err(ReadFailure::Pending | ReadFailure::Failed(_)) => oracle = None,
            }
        }
        if let (Some(left), Some(right), Some(client)) = (&primary, &oracle, pair.oracle) {
            if left.stale() || right.stale() {
                budget.context(
                    if left.stale() {
                        RecoveryEndpoint::Primary
                    } else {
                        RecoveryEndpoint::Oracle
                    },
                    RecoveryMethod::GetHealth,
                    None,
                );
                budget.failed(RecoveryReason::Lagging);
                detail = "stale_observation";
            } else {
                let target = left.report.latest_ledger.min(right.report.latest_ledger);
                let left = history(pair.primary, left, &mut budget, attempt, true, target).await;
                if matches!(left, Err(ReadFailure::Deadline)) {
                    break;
                }
                let right = history(client, right, &mut budget, attempt, false, target).await;
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
    batch.missing = budget.failure;
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
    commit_sequence_batch(
        &mut recorder,
        batch,
        &OperationStatus::new(store, profile),
        &attempts,
    )
}

/// A failed commit can select either durable image. One verified read
/// describes all selected sequences while the caller still holds the writer.
fn commit_sequence_batch(
    recorder: &mut OperationRecorder<'_>,
    batch: Batch,
    status: &OperationStatus<'_>,
    attempts: &[RecoveryAttempt],
) -> Result<RecoveryReport, RecoveryError> {
    commit_batch(recorder, batch).map_err(|error| {
        RecoveryError::from(error).with_context(sequence_failure_detail(status, attempts))
    })
}

fn sequence_failure_detail(status: &OperationStatus<'_>, attempts: &[RecoveryAttempt]) -> String {
    let (states, refusal) = match status.sequence_release_states(attempts) {
        Ok(states) => (states, String::new()),
        Err(error) => (
            vec![None; attempts.len()],
            format!("; progress read refused with {}", error.submission_code()),
        ),
    };
    let released = states.iter().filter(|state| **state == Some(true)).count();
    let held = states.iter().filter(|state| **state == Some(false)).count();
    let unavailable = states.iter().filter(|state| state.is_none()).count();
    format!(
        "selected sequences: {released} released, {held} held, {unavailable} unavailable{refusal}"
    )
}

/// One attempt's evaluated pass: its evidence commit and, when the evidence
/// decides it, the decided transition with its digest and deciding ledgers.
struct Evaluated {
    attempt: RecoveryAttempt,
    input: EvidenceInput,
    decision: Option<(DecidedTransition, [u8; 32], (u32, u32))>,
}

/// Reads one account through the attempt allowance. The inner error is
/// the pending detail, with the regression code apart from every other
/// failure; the outer error is the pass deadline.
async fn account_read(
    client: &StellarRpcClient,
    account: &str,
    shared: &SharedObservation,
    budget: &mut Budget,
) -> Result<Result<AccountAnswer, &'static str>, ReadFailure> {
    if let Err(failure) = budget.charge(false) {
        return match failure {
            ReadFailure::Deadline => Err(failure),
            ReadFailure::Pending | ReadFailure::Failed(_) => Ok(Err("request_allowance")),
        };
    }
    budget.context(budget.context.0, RecoveryMethod::GetLedgerEntries, None);
    match tokio::time::timeout_at(
        budget.deadline,
        crate::account::fetch_account_recovery(client, account, &shared.report),
    )
    .await
    {
        Err(_) => {
            budget.failed(RecoveryReason::Deadline);
            Err(ReadFailure::Deadline)
        }
        Ok(Ok(observed)) => {
            use stellar_agent_core::policy::v1::AccountReservesView;
            Ok(Ok(AccountAnswer {
                sequence: Some(observed.view().sequence_number),
                latest_ledger: observed.observation().map(|seen| seen.ledger_sequence),
            }))
        }
        Ok(Err(crate::client::RecoveryReadError::Validation(WalletError::Network(
            stellar_agent_core::error::NetworkError::AccountLedgerRegressed { .. },
        )))) => {
            budget.failed(RecoveryReason::AccountUnavailable);
            Ok(Err(ACCOUNT_LEDGER_REGRESSED))
        }
        Ok(Err(error)) => {
            budget.failed(read_failure(&error));
            Ok(Err("endpoint_unreachable"))
        }
    }
}

/// The evidence rows of the answers that `read` marks as read when the
/// other endpoint's read failed. The missing side hashes as an all-null
/// answer, so the digest names the pair as read. No decision follows from
/// these rows.
fn partial_rows(
    answers: &[OutcomeAnswer; 2],
    read: [bool; 2],
    shared_ledgers: (Option<u32>, Option<u32>),
) -> Result<Vec<EvidenceRowInput>, WindowStoreError> {
    let digest = outcome_digest(answers)?;
    Ok([
        (
            read[0],
            &answers[0],
            EvidenceEndpoint::Primary,
            shared_ledgers.0,
        ),
        (
            read[1],
            &answers[1],
            EvidenceEndpoint::Witness,
            shared_ledgers.1,
        ),
    ]
    .into_iter()
    .filter(|(done, ..)| *done)
    .filter_map(|(_, answer, endpoint, fallback)| answer.row(endpoint, digest, fallback))
    .collect())
}

/// The evidence row of the one account answer read when the other endpoint's
/// account read failed. The failed side hashes as an all-null answer. A
/// complete or empty pair yields no rows, and no decision follows from them.
fn partial_account_rows(
    reads: [Result<AccountAnswer, &'static str>; 2],
    shared_ledgers: (Option<u32>, Option<u32>),
) -> Result<Vec<EvidenceRowInput>, WindowStoreError> {
    if reads[0].is_ok() == reads[1].is_ok() {
        return Ok(Vec::new());
    }
    let answers = reads.map(Result::unwrap_or_default);
    let digest = account_digest(&answers)?;
    Ok([
        (&reads[0], EvidenceEndpoint::Primary, shared_ledgers.0),
        (&reads[1], EvidenceEndpoint::Witness, shared_ledgers.1),
    ]
    .into_iter()
    .filter_map(|(read, endpoint, fallback)| {
        read.as_ref()
            .ok()
            .and_then(|answer| answer.row(endpoint, digest, fallback))
    })
    .collect())
}

/// Evaluates one attempt from its transaction answers, the sequence scans
/// and, after a recorded release, the account answers.
fn evaluate_outcome(
    attempt: &RecoveryAttempt,
    outcome: Option<[OutcomeAnswer; 2]>,
    scans: (Option<&Scan>, Option<&Scan>),
    accounts: Option<AccountRead>,
    shared_ledgers: (Option<u32>, Option<u32>),
    now_ms: u64,
    detail: &str,
) -> Result<Evaluated, WindowStoreError> {
    // A transaction answer whose retention starts after the pre-exposure
    // ledger proves history loss. The sticky flag is set before
    // classification and persists with the pass state, also for an attempt
    // whose sequence release is already recorded.
    let mut seen = attempt.clone();
    if let Some(answers) = &outcome
        && answers.iter().any(|answer| {
            answer.oldest_ledger.is_some_and(|oldest| {
                attempt
                    .pre_exposure_ledger
                    .is_none_or(|pre_exposure| oldest > pre_exposure)
            })
        })
    {
        seen.recovery.history_incomplete = true;
    }
    let attempt = &seen;
    let outcome_read = outcome.is_some();
    let mut input = evaluate(attempt, scans.0, scans.1, now_ms, detail)?;
    let sequence = input.sequence_released.take();
    let observed = observe(attempt, outcome.as_ref(), sequence, accounts.as_ref());
    let mut update = input.recovery.take().unwrap_or_default();
    let mut decision = None;
    if let Some(answers) = &outcome {
        let digest = outcome_digest(answers)?;
        input.rows.extend(
            [
                answers[0].row(EvidenceEndpoint::Primary, digest, shared_ledgers.0),
                answers[1].row(EvidenceEndpoint::Witness, digest, shared_ledgers.1),
            ]
            .into_iter()
            .flatten(),
        );
    }
    let account_answers = accounts.as_ref().and_then(|read| read.as_ref().ok());
    if let Some(answers) = account_answers {
        let digest = account_digest(answers)?;
        input.rows.extend(
            [
                answers[0].row(EvidenceEndpoint::Primary, digest, shared_ledgers.0),
                answers[1].row(EvidenceEndpoint::Witness, digest, shared_ledgers.1),
            ]
            .into_iter()
            .flatten(),
        );
    }
    input.rows.truncate(super::operations::MAX_EVIDENCE_ROWS);
    match observed {
        Observed::Decided(transition) => {
            let answers = outcome.unwrap_or_default();
            let mut digest = outcome_digest(&answers)?;
            let mut ledgers = (
                answers[0].latest_ledger.unwrap_or_default(),
                answers[1].latest_ledger.unwrap_or_default(),
            );
            if let (
                DecidedTransition::NotIncluded(NotIncludedProof::AccountSequence { .. }),
                Some(accounts),
            ) = (&transition, account_answers)
            {
                let mut hasher = Sha256::new();
                hasher.update(digest);
                hasher.update(account_digest(accounts)?);
                digest = hasher.finalize().into();
                ledgers = (
                    accounts[0].latest_ledger.unwrap_or_default(),
                    accounts[1].latest_ledger.unwrap_or_default(),
                );
            }
            update.disagreements = 0;
            update.last_outcome = Some("concurring".to_owned());
            update.diagnostic = None;
            decision = Some((transition, digest, ledgers));
        }
        Observed::SequenceReleased(release) => input.sequence_released = Some(release),
        Observed::Disagreement(detail) => {
            update.disagreements = attempt.recovery.disagreements.saturating_add(1);
            update.last_outcome = Some("disagreement".to_owned());
            update.diagnostic = Some(detail.to_owned());
        }
        Observed::Pending(observed) => {
            if update.last_outcome.as_deref() == Some("disagreement") {
                update.disagreements = attempt.recovery.disagreements.saturating_add(1);
            } else {
                update.disagreements = attempt.recovery.disagreements;
                update.last_outcome = Some("evidence_pending".to_owned());
                // Without an answer pair, the pass's own detail, such as an
                // unreachable endpoint, names why nothing decides.
                update.diagnostic = Some(if outcome_read {
                    observed.to_owned()
                } else {
                    detail.to_owned()
                });
            }
        }
    }
    input.recovery = Some(update);
    Ok(Evaluated {
        attempt: attempt.clone(),
        input,
        decision,
    })
}

/// Collects the outcome-capable pass over `attempts`, at most four, within
/// the attempt and shared allowances and the pass deadline.
async fn collect_outcomes(
    pair: &EndpointPair<'_>,
    attempts: &[RecoveryAttempt],
    now_ms: u64,
) -> Result<
    (
        Vec<Evaluated>,
        Option<WindowObservation>,
        RecoveryRequests,
        Option<RecoveryFailure>,
    ),
    RecoveryError,
> {
    let mut budget = Budget::new();
    let mut evaluated = Vec::new();
    let mut observation = None;
    match pair.verify(&mut budget).await {
        Ok(()) => {}
        Err(IdentityFailure::Refused(error)) => return Err(RecoveryError::EndpointIdentity(error)),
        Err(IdentityFailure::Read(_)) => {
            return Ok((evaluated, observation, budget.used, budget.failure));
        }
    }
    let Some(oracle_client) = pair.oracle else {
        return Ok((evaluated, observation, budget.used, budget.failure));
    };
    budget.context(RecoveryEndpoint::Primary, RecoveryMethod::GetHealth, None);
    let mut primary = match shared_observation(pair.primary, &mut budget, now_ms).await {
        Ok(shared) => shared,
        Err(_) => return Ok((evaluated, observation, budget.used, budget.failure)),
    };
    observation = Some(primary.window(now_ms));
    budget.context(RecoveryEndpoint::Oracle, RecoveryMethod::GetHealth, None);
    let mut oracle = match shared_observation(oracle_client, &mut budget, now_ms).await {
        Ok(shared) => shared,
        Err(_) => return Ok((evaluated, observation, budget.used, budget.failure)),
    };
    let mut refreshed = false;
    for attempt in attempts.iter().take(4) {
        if Instant::now() >= budget.deadline {
            budget.failed(RecoveryReason::Deadline);
            break;
        }
        if (primary.stale() || oracle.stale()) && !refreshed {
            refreshed = true;
            budget.context(RecoveryEndpoint::Primary, RecoveryMethod::GetHealth, None);
            match shared_observation(pair.primary, &mut budget, now_ms).await {
                Ok(shared) => {
                    observation = Some(shared.window(now_ms));
                    primary = shared;
                }
                Err(_) => break,
            }
            budget.context(RecoveryEndpoint::Oracle, RecoveryMethod::GetHealth, None);
            match shared_observation(oracle_client, &mut budget, now_ms).await {
                Ok(shared) => oracle = shared,
                Err(_) => break,
            }
        }
        if primary.stale() || oracle.stale() {
            budget.context(
                if primary.stale() {
                    RecoveryEndpoint::Primary
                } else {
                    RecoveryEndpoint::Oracle
                },
                RecoveryMethod::GetHealth,
                None,
            );
            budget.failed(RecoveryReason::Lagging);
            break;
        }
        let ExposureIdentity::Classic { tx_hash, .. } = attempt.exposure else {
            continue;
        };
        let hash = stellar_xdr::Hash(tx_hash);
        let mut answers = [OutcomeAnswer::default(), OutcomeAnswer::default()];
        let mut interrupted = false;
        let mut read = [false, false];
        for (index, ((slot, client), done)) in answers
            .iter_mut()
            .zip([pair.primary, oracle_client])
            .zip(&mut read)
            .enumerate()
        {
            budget.context(
                if index == 0 {
                    RecoveryEndpoint::Primary
                } else {
                    RecoveryEndpoint::Oracle
                },
                RecoveryMethod::GetTransaction,
                None,
            );
            match budget.read(false, client.recovery_transaction(&hash)).await {
                Ok(observed) => {
                    *slot = OutcomeAnswer::from_observed(&observed);
                    *done = true;
                }
                Err(ReadFailure::Deadline) => interrupted = true,
                Err(_) => {}
            }
            if interrupted {
                break;
            }
        }
        let read_all = read == [true, true];
        if interrupted {
            break;
        }
        let mut seeded = attempt.clone();
        let mut scans = (None, None);
        if matched_sequence_release(attempt).is_none() {
            seeded.recovery.primary_cursor.get_or_insert(
                attempt
                    .pre_exposure_ledger
                    .unwrap_or(primary.report.latest_ledger),
            );
            seeded.recovery.witness_cursor.get_or_insert(
                attempt
                    .pre_exposure_ledger
                    .unwrap_or(oracle.report.latest_ledger),
            );
            let target = primary
                .report
                .latest_ledger
                .min(oracle.report.latest_ledger);
            let left = history(pair.primary, &primary, &mut budget, &seeded, true, target).await;
            let right = history(oracle_client, &oracle, &mut budget, &seeded, false, target).await;
            if matches!(left, Err(ReadFailure::Deadline))
                || matches!(right, Err(ReadFailure::Deadline))
            {
                break;
            }
            scans = (left.ok().flatten(), right.ok().flatten());
        }
        let absent = answers
            .iter()
            .all(|answer| answer.status.as_deref() == Some("NOT_FOUND"));
        let mut accounts = None;
        let mut account_partial = Vec::new();
        if read_all
            && absent
            && matched_sequence_release(attempt).is_some()
            && let Some(account) = &attempt.account
        {
            budget.context(
                RecoveryEndpoint::Primary,
                RecoveryMethod::GetLedgerEntries,
                None,
            );
            let left = account_read(pair.primary, account, &primary, &mut budget).await;
            budget.context(
                RecoveryEndpoint::Oracle,
                RecoveryMethod::GetLedgerEntries,
                None,
            );
            let right = account_read(oracle_client, account, &oracle, &mut budget).await;
            let (Ok(left), Ok(right)) = (left, right) else {
                break;
            };
            account_partial = partial_account_rows(
                [left, right],
                (
                    Some(primary.report.latest_ledger),
                    Some(oracle.report.latest_ledger),
                ),
            )?;
            accounts = Some(match (left, right) {
                (Ok(left), Ok(right)) => Ok([left, right]),
                (Err(ACCOUNT_LEDGER_REGRESSED), _) | (_, Err(ACCOUNT_LEDGER_REGRESSED)) => {
                    Err(ACCOUNT_LEDGER_REGRESSED)
                }
                (Err(detail), _) | (_, Err(detail)) => Err(detail),
            });
        }
        let partial = if read_all {
            Vec::new()
        } else {
            partial_rows(
                &answers,
                read,
                (
                    Some(primary.report.latest_ledger),
                    Some(oracle.report.latest_ledger),
                ),
            )?
        };
        let missing_endpoint = read_all
            .then(|| classify_outcome(attempt, &answers))
            .filter(|class| matches!(class, OutcomeClass::Pending(MISSING_FIELD)))
            .and_then(|_| {
                answers
                    .iter()
                    .zip([RecoveryEndpoint::Primary, RecoveryEndpoint::Oracle])
                    .find(|(answer, _)| answer.defect() == Some(MISSING_FIELD))
                    .map(|(_, endpoint)| endpoint)
            });
        let mut evaluation = evaluate_outcome(
            &seeded,
            read_all.then_some(answers),
            (scans.0.as_ref(), scans.1.as_ref()),
            accounts,
            (
                Some(primary.report.latest_ledger),
                Some(oracle.report.latest_ledger),
            ),
            now_ms,
            if read_all {
                "expiry_boundary_pending"
            } else {
                "endpoint_unreachable"
            },
        )?;
        if let Some(endpoint) = missing_endpoint {
            budget.context(endpoint, RecoveryMethod::GetTransaction, None);
            budget.failed(RecoveryReason::MissingField);
        }
        if matches!(
            evaluation.decision,
            Some((
                DecidedTransition::NotIncluded(NotIncludedProof::CompleteHistory { .. }),
                _,
                _
            ))
        ) {
            evaluation.decision = None;
            if let Some(recovery) = &mut evaluation.input.recovery {
                recovery.last_outcome = Some("evidence_pending".to_owned());
                recovery.diagnostic = Some("coverage_required".to_owned());
            }
            budget.failed(RecoveryReason::CoverageRequired);
        }
        evaluation.input.rows.extend(partial);
        evaluation.input.rows.extend(account_partial);
        evaluation
            .input
            .rows
            .truncate(super::operations::MAX_EVIDENCE_ROWS);
        evaluation.input.expected_attempt = Some(attempt.clone());
        evaluation.input.observation = observation;
        evaluation.attempt = attempt.clone();
        evaluated.push(evaluation);
    }
    Ok((evaluated, observation, budget.used, budget.failure))
}

/// Runs the outcome-capable recovery pass: one bounded two-endpoint pass
/// over the four oldest unknown classic attempts, released ones included,
/// or the attempt `tx_hash` names. Each attempt commits its evidence and at
/// most one transition: an agreed outcome, its first sequence release, or a
/// proven non-inclusion, through checked decisions.
///
/// The submission flow can call this pass from dispatch and targeted status,
/// after the sequence stage of [`recover_sequences`].
///
/// # Errors
/// Returns snapshot, audit and commit errors. An endpoint on another network
/// or protocol refuses the pass before any commit.
pub async fn recover_outcomes(
    store: &PersistedWindowStore,
    profile: &Profile,
    pair: EndpointPair<'_>,
    writer: &Arc<Mutex<AuditWriter>>,
    tx_hash: Option<&[u8; 32]>,
) -> Result<RecoveryReport, RecoveryError> {
    let status = OperationStatus::new(store, profile);
    let attempts = status.outcome_snapshot(tx_hash)?;
    if !profile.chain_id.is_mainnet() || attempts.is_empty() {
        return Ok(RecoveryReport::default());
    }
    let now_ms = super::store::now_ms()?;
    let (evaluated, observation, requests, missing) =
        collect_outcomes(&pair, &attempts, now_ms).await?;
    let mut writer = writer.lock().map_err(|_| WindowStoreError::Invalid {
        detail: "audit writer mutex is poisoned".to_owned(),
    })?;
    let mut recorder = OperationRecorder::new(
        store,
        profile,
        &mut *writer,
        uuid::Uuid::new_v4().to_string(),
    );
    let report = RecoveryReport {
        requests,
        evaluated: evaluated.len(),
        missing,
    };
    if evaluated.is_empty() {
        if let Some(observation) = observation {
            recorder.record_observation(observation)?;
        }
        return Ok(report);
    }
    for Evaluated {
        attempt,
        input,
        decision,
    } in evaluated
    {
        recorder.record_evidence(attempt.operation_id, attempt.attempt_index, &input)?;
        let Some((transition, digest, ledgers)) = decision else {
            continue;
        };
        // Each decision binds the generation of a fresh verified read, so
        // no snapshot generation serves two commits.
        let ExposureIdentity::Classic { tx_hash, .. } = attempt.exposure else {
            continue;
        };
        let fresh = OperationStatus::new(store, profile)
            .outcome_snapshot(Some(&tx_hash))?
            .into_iter()
            .find(|fresh| {
                fresh.operation_id == attempt.operation_id
                    && fresh.attempt_index == attempt.attempt_index
                    && fresh.exposure == attempt.exposure
            });
        let Some(fresh) = fresh else {
            continue;
        };
        let recovery = input.recovery.clone().unwrap_or_default();
        if let Some(decision) =
            CheckedRecoveryDecision::new(&fresh, digest, ledgers, transition, recovery)
        {
            recorder.commit_decision(&decision)?;
        }
    }
    Ok(report)
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
        missing: batch.missing,
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

    use super::super::operations::OperationState;
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
            generation: 1,
            account: None,
            sequence_release: None,
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
        scan_page(&page(ledger, 1, ledger, close), ledger, max_time, 1).unwrap()
    }

    /// Success confirms every record with its amount and time. Failure keeps
    /// every count, debits the native record by the agreed fee at the agreed
    /// close time and zeroes the other amount. Both write a settled row at
    /// the inclusion ledger and keep the stored observation's clock out.
    #[test]
    #[serial_test::serial]
    fn recovery_success_keeps_debit_and_failure_keeps_only_fee_and_counts() {
        use super::super::operations::tests::{agreed, bucket_rows, decide, decided_attempt};
        use super::super::store::RecordStatus;
        let mut fx = Fx::new();
        let (success, one) = decided_attempt(&mut fx, 1);
        let (failure, _) = decided_attempt(&mut fx, 2);
        let one = OperationStatus::new(&fx.store, &fx.profile)
            .outcome_snapshot(Some(&[1 ^ 0x80; 32]))
            .unwrap()
            .pop()
            .unwrap_or(one);
        fx.clock.set(NOW);
        fx.recorder()
            .commit_decision(&decide(
                &one,
                DecidedTransition::Succeeded(agreed(1, "SUCCESS")),
            ))
            .unwrap();
        let two = OperationStatus::new(&fx.store, &fx.profile)
            .outcome_snapshot(Some(&[2 ^ 0x80; 32]))
            .unwrap()
            .pop()
            .unwrap();
        let outcome = agreed(2, "FAILED");
        let close_ms = outcome.created_at * 1_000;
        fx.recorder()
            .commit_decision(&decide(
                &two,
                DecidedTransition::Failed {
                    outcome,
                    fee_charged: 100,
                },
            ))
            .unwrap();
        let t0 = one.started_at_ms;
        assert_eq!(
            bucket_rows(&fx, 1),
            vec![
                ("native".to_owned(), RecordStatus::Confirmed, 25, t0),
                ("usdc".to_owned(), RecordStatus::Confirmed, 40, t0),
            ]
        );
        assert_eq!(
            bucket_rows(&fx, 2),
            vec![
                ("native".to_owned(), RecordStatus::Confirmed, 100, close_ms),
                ("usdc".to_owned(), RecordStatus::Confirmed, 0, close_ms),
            ]
        );
        assert_ne!(close_ms, NOW);
        for (handle, state) in [
            (&success, OperationState::Succeeded),
            (&failure, OperationState::Failed),
        ] {
            let record = fx.record(handle.id());
            assert_eq!(record.state, state);
            assert_eq!(
                record.attempts[0].recovery.as_ref().unwrap().disagreements,
                0
            );
            let auth = fx
                .wire()
                .authorizations
                .into_iter()
                .find(|auth| auth.id == record.attempts[0].authorization_id)
                .unwrap();
            let row = auth.native_release.unwrap();
            assert_eq!(row.class, super::super::operations::ReleaseClass::Settled);
            assert_eq!(
                row.bound,
                super::super::operations::ReleaseBound::Ledger(120)
            );
            assert_eq!(row.observed_ledger, Some(131));
        }
    }

    /// Both non-inclusion proofs release every record of the reservation
    /// and write a `proved_unspent` row released `Always`. They leave no
    /// native amount counted and name the evidenced release code on the
    /// audit row.
    #[test]
    #[serial_test::serial]
    fn recovery_non_inclusion_releases_all_holds_and_native_amounts() {
        use super::super::operations::tests::{
            bucket_rows, decide, decided_attempt, not_included_proof,
        };
        use super::super::operations::{EndpointCoverage, ReleaseBound, ReleaseClass};
        let history = NotIncludedProof::CompleteHistory {
            primary: EndpointCoverage {
                first_ledger: 10,
                last_ledger: 140,
                latest_ledger: 140,
                oldest_ledger: 5,
            },
            witness: EndpointCoverage {
                first_ledger: 10,
                last_ledger: 141,
                latest_ledger: 141,
                oldest_ledger: 5,
            },
        };
        for proof in [not_included_proof(), history] {
            let mut fx = Fx::new();
            let (handle, attempt) = decided_attempt(&mut fx, 1);
            let status = OperationStatus::new(&fx.store, &fx.profile);
            assert_eq!(status.native_reserved_stroops(None).unwrap(), 125);
            assert_eq!(bucket_rows(&fx, 1).len(), 2);
            let commit = fx
                .recorder()
                .commit_decision(&decide(&attempt, DecidedTransition::NotIncluded(proof)))
                .unwrap();
            assert!(bucket_rows(&fx, 1).is_empty(), "{proof:?}");
            let record = fx.record(handle.id());
            assert_eq!(record.state, OperationState::NotIncluded);
            assert_eq!(record.attempts[0].not_included, Some(proof));
            let auth = fx
                .wire()
                .authorizations
                .into_iter()
                .find(|auth| auth.id == record.attempts[0].authorization_id)
                .unwrap();
            let row = auth.native_release.unwrap();
            assert_eq!(
                (row.class, row.bound, row.commit_id),
                (ReleaseClass::ProvedUnspent, ReleaseBound::Always, commit)
            );
            let status = OperationStatus::new(&fx.store, &fx.profile);
            assert_eq!(status.native_reserved_stroops(None).unwrap(), 0);
            let EventKind::OperationTransition { release_code, .. } =
                &fx.sink.entries.last().unwrap().event_kind
            else {
                panic!("a transition row");
            };
            assert_eq!(
                release_code.as_deref(),
                Some(
                    stellar_agent_core::profile::receipt::ReleaseEvidence::ReleasedOnEvidence
                        .code()
                )
            );
        }
    }

    /// A classic envelope with fee cap `fee`, as base64 XDR.
    fn envelope_text(fee: u32) -> String {
        use stellar_xdr::WriteXdr;
        stellar_xdr::TransactionEnvelope::Tx(stellar_xdr::TransactionV1Envelope {
            tx: stellar_xdr::Transaction {
                source_account: stellar_xdr::MuxedAccount::Ed25519(stellar_xdr::Uint256([1; 32])),
                fee,
                seq_num: stellar_xdr::SequenceNumber(7),
                cond: stellar_xdr::Preconditions::None,
                memo: stellar_xdr::Memo::None,
                operations: stellar_xdr::VecM::default(),
                ext: stellar_xdr::TransactionExt::V0,
            },
            signatures: stellar_xdr::VecM::default(),
        })
        .to_xdr_base64(stellar_xdr::Limits::none())
        .unwrap()
    }

    /// A transaction result charging `fee`, successful or failed.
    fn result_text(success: bool, fee: i64) -> String {
        use stellar_xdr::WriteXdr;
        stellar_xdr::TransactionResult {
            fee_charged: fee,
            result: if success {
                stellar_xdr::TransactionResultResult::TxSuccess(stellar_xdr::VecM::default())
            } else {
                stellar_xdr::TransactionResultResult::TxFailed(stellar_xdr::VecM::default())
            },
            ext: stellar_xdr::TransactionResultExt::V0,
        }
        .to_xdr_base64(stellar_xdr::Limits::none())
        .unwrap()
    }

    const CAP: u32 = 100;

    /// An exposed attempt of the fee-100 envelope, released at ledger 50
    /// on both endpoints when `released`, with `max_time` 10 and sequence 7.
    fn exposed(released: bool) -> RecoveryAttempt {
        let mut attempt = attempt(10);
        if let ExposureIdentity::Classic {
            envelope_sha256, ..
        } = &mut attempt.exposure
        {
            *envelope_sha256 = Sha256::digest(envelope_text(CAP)).into();
        }
        attempt.pre_exposure_ledger = Some(20);
        attempt.sequence_release = released.then_some(SequenceReleaseInput {
            primary_ledger: 50,
            witness_ledger: 50,
            min_close_time_ms: 11_000,
        });
        attempt.sequence_released = released;
        attempt
    }

    fn included(status: &str, result: String) -> OutcomeAnswer {
        OutcomeAnswer {
            status: Some(status.to_owned()),
            ledger: Some(40),
            created_at: Some(1_000),
            tx_hash: Some("03".repeat(32)),
            envelope_xdr: Some(envelope_text(CAP)),
            result_xdr: Some(result),
            latest_ledger: Some(60),
            oldest_ledger: Some(5),
            time_defect: None,
        }
    }

    fn absent(oldest: u32, latest: u32) -> OutcomeAnswer {
        OutcomeAnswer {
            status: Some("NOT_FOUND".to_owned()),
            latest_ledger: Some(latest),
            oldest_ledger: Some(oldest),
            ..OutcomeAnswer::default()
        }
    }

    fn accounts(left: i64, right: i64, ledgers: (u32, u32)) -> AccountRead {
        Ok([
            AccountAnswer {
                sequence: Some(left),
                latest_ledger: Some(ledgers.0),
            },
            AccountAnswer {
                sequence: Some(right),
                latest_ledger: Some(ledgers.1),
            },
        ])
    }

    /// Each mismatch between otherwise agreeing inclusions disagrees with its
    /// own detail, counts once, and releases neither outcome nor sequence.
    #[test]
    fn recovery_outcome_rejects_each_mismatch() {
        let attempt = exposed(false);
        let good = included("SUCCESS", result_text(true, 50));
        assert!(matches!(
            classify_outcome(&attempt, &[good.clone(), good.clone()]),
            OutcomeClass::Decided(DecidedTransition::Succeeded(_))
        ));
        type Change = fn(&mut OutcomeAnswer);
        let cases: Vec<(Change, &str)> = vec![
            (
                |answer| {
                    answer.status = Some("FAILED".to_owned());
                    answer.result_xdr = Some(result_text(false, 50));
                },
                STATUS_MISMATCH,
            ),
            (|answer| answer.ledger = Some(41), LEDGER_MISMATCH),
            (
                |answer| answer.created_at = Some(1_001),
                CLOSE_TIME_MISMATCH,
            ),
            (
                |answer| answer.tx_hash = Some("04".repeat(32)),
                HASH_MISMATCH,
            ),
            (
                |answer| answer.envelope_xdr = Some(envelope_text(CAP + 1)),
                ENVELOPE_MISMATCH,
            ),
            (
                |answer| answer.result_xdr = Some(result_text(true, 51)),
                RESULT_MISMATCH,
            ),
        ];
        let release = deciding(7, 11, 10);
        for (change, detail) in cases {
            let mut oracle = good.clone();
            change(&mut oracle);
            let answers = [good.clone(), oracle];
            assert_eq!(
                classify_outcome(&attempt, &answers),
                OutcomeClass::Disagreement(detail)
            );
            let mut counted = attempt.clone();
            counted.recovery.disagreements = 254;
            let evaluated = evaluate_outcome(
                &counted,
                Some(answers),
                (Some(&release), Some(&release)),
                None,
                (Some(60), Some(60)),
                NOW,
                "pending",
            )
            .unwrap();
            assert!(evaluated.decision.is_none(), "{detail}");
            assert!(evaluated.input.sequence_released.is_none(), "{detail}");
            let update = evaluated.input.recovery.unwrap();
            assert_eq!(update.disagreements, 255, "{detail}");
            assert_eq!(update.diagnostic.as_deref(), Some(detail));
        }
        // Another envelope agreed on by both endpoints closes nothing.
        let mut other = good.clone();
        other.envelope_xdr = Some(envelope_text(CAP + 1));
        assert_eq!(
            classify_outcome(&attempt, &[other.clone(), other]),
            OutcomeClass::Disagreement(ENVELOPE_MISMATCH)
        );
    }

    /// Malformed XDR, a status its result contradicts, and fees outside
    /// zero and the cap never settle; zero and the cap themselves settle.
    #[test]
    fn recovery_invalid_result_or_fee_never_settles() {
        let attempt = exposed(false);
        let pair = |answer: OutcomeAnswer| [answer.clone(), answer];
        let mut bad_result = included("SUCCESS", "AAAA".to_owned());
        assert_eq!(
            classify_outcome(&attempt, &pair(bad_result.clone())),
            OutcomeClass::Disagreement(XDR_MALFORMED)
        );
        bad_result.result_xdr = Some("not base64".to_owned());
        assert_eq!(
            classify_outcome(&attempt, &pair(bad_result)),
            OutcomeClass::Disagreement(XDR_MALFORMED)
        );
        for (status, success) in [("SUCCESS", false), ("FAILED", true)] {
            assert_eq!(
                classify_outcome(&attempt, &pair(included(status, result_text(success, 5)))),
                OutcomeClass::Disagreement(STATUS_RESULT_MISMATCH)
            );
        }
        for fee in [-1, i64::from(CAP) + 1] {
            assert_eq!(
                classify_outcome(&attempt, &pair(included("FAILED", result_text(false, fee)))),
                OutcomeClass::Disagreement(FEE_INVALID),
                "{fee}"
            );
        }
        for fee in [0, i64::from(CAP)] {
            match classify_outcome(&attempt, &pair(included("FAILED", result_text(false, fee)))) {
                OutcomeClass::Decided(DecidedTransition::Failed {
                    outcome,
                    fee_charged,
                }) => {
                    assert_eq!(fee_charged, fee);
                    assert_eq!(outcome.ledger, 40);
                    assert_eq!(outcome.created_at, 1_000);
                }
                other => panic!("{fee}: {other:?}"),
            }
        }
    }

    /// One transition per pass, outcome first, then the sequence release,
    /// then non-inclusion; a disagreement blocks the release.
    #[test]
    fn recovery_pass_selects_one_transition_in_outcome_sequence_non_inclusion_order() {
        let release = SequenceReleaseInput {
            primary_ledger: 50,
            witness_ledger: 50,
            min_close_time_ms: 11_000,
        };
        let good = included("SUCCESS", result_text(true, 50));
        let unreleased = exposed(false);
        assert!(matches!(
            observe(
                &unreleased,
                Some(&[good.clone(), good.clone()]),
                Some(release),
                None
            ),
            Observed::Decided(DecidedTransition::Succeeded(_))
        ));
        let gone = [absent(5, 60), absent(5, 61)];
        assert_eq!(
            observe(&unreleased, Some(&gone), Some(release), None),
            Observed::SequenceReleased(release)
        );
        let mut late = good.clone();
        late.ledger = Some(41);
        assert_eq!(
            observe(
                &unreleased,
                Some(&[good.clone(), late]),
                Some(release),
                None
            ),
            Observed::Disagreement(LEDGER_MISMATCH)
        );
        let released = exposed(true);
        let read = accounts(6, 6, (60, 61));
        assert!(matches!(
            observe(&released, Some(&gone), Some(release), Some(&read)),
            Observed::Decided(DecidedTransition::NotIncluded(
                NotIncludedProof::AccountSequence { .. }
            ))
        ));
        assert!(matches!(
            observe(&released, Some(&[good.clone(), good]), None, Some(&read)),
            Observed::Decided(DecidedTransition::Succeeded(_))
        ));
        let evaluated = evaluate_outcome(
            &unreleased,
            Some(gone),
            (Some(&deciding(50, 11, 10)), Some(&deciding(50, 11, 10))),
            None,
            (Some(60), Some(61)),
            NOW,
            "pending",
        )
        .unwrap();
        assert!(evaluated.decision.is_none());
        assert!(evaluated.input.sequence_released.is_some());
    }

    /// Account non-inclusion needs a recorded release, a positive time
    /// bound, both sequences strictly lower and each endpoint's own expiry
    /// coverage.
    #[test]
    fn recovery_account_non_inclusion_requires_both_lower_sequences_and_expiry_coverage() {
        let gone = [absent(30, 60), absent(30, 61)];
        let released = exposed(true);
        let proof = classify_non_inclusion(&released, &gone, Some(&accounts(6, 6, (50, 51))));
        assert!(
            matches!(proof, Ok(NotIncludedProof::AccountSequence { primary, witness })
                if primary.latest_ledger == 50 && witness.latest_ledger == 51),
            "{proof:?}"
        );
        let refused = [
            (exposed(false), accounts(6, 6, (60, 61))),
            (released.clone(), accounts(7, 6, (60, 61))),
            (released.clone(), accounts(6, 7, (60, 61))),
            (released.clone(), accounts(6, 6, (49, 61))),
            (released.clone(), accounts(6, 6, (60, 49))),
        ];
        for (attempt, read) in &refused {
            assert!(
                !matches!(
                    classify_non_inclusion(attempt, &gone, Some(read)),
                    Ok(NotIncludedProof::AccountSequence { .. })
                ),
                "{read:?}"
            );
        }
        let mut untimed = released.clone();
        if let ExposureIdentity::Classic { max_time, .. } = &mut untimed.exposure {
            *max_time = 0;
        }
        assert!(classify_non_inclusion(&untimed, &gone, Some(&accounts(6, 6, (60, 61)))).is_err());
    }

    /// A regressed account read keeps the attempt pending: no decision, no
    /// disagreement and no fallback to the history branch.
    #[test]
    fn recovery_ledger_regressed_keeps_pending() {
        let released = exposed(true);
        let gone = [absent(5, 60), absent(5, 61)];
        assert!(classify_non_inclusion(&released, &gone, None).is_ok());
        let regressed: AccountRead = Err(ACCOUNT_LEDGER_REGRESSED);
        assert_eq!(
            classify_non_inclusion(&released, &gone, Some(&regressed)),
            Err(ACCOUNT_LEDGER_REGRESSED)
        );
        let mut counted = released.clone();
        counted.recovery.disagreements = 3;
        let evaluated = evaluate_outcome(
            &counted,
            Some(gone),
            (None, None),
            Some(regressed),
            (Some(60), Some(61)),
            NOW,
            "pending",
        )
        .unwrap();
        assert!(evaluated.decision.is_none());
        let update = evaluated.input.recovery.unwrap();
        assert_eq!(update.disagreements, 3);
        assert_eq!(update.diagnostic.as_deref(), Some(ACCOUNT_LEDGER_REGRESSED));
    }

    /// Complete-history non-inclusion needs two covered absences reaching
    /// back to the pre-exposure ledger and forward to each expiry ledger.
    #[test]
    fn recovery_complete_history_requires_both_transaction_coverages_and_continuity() {
        let released = exposed(true);
        let proof = classify_non_inclusion(&released, &[absent(20, 50), absent(19, 51)], None);
        assert!(
            matches!(proof, Ok(NotIncludedProof::CompleteHistory { primary, witness })
                if primary.oldest_ledger == 20 && witness.first_ledger == 20),
            "{proof:?}"
        );
        for answers in [
            [absent(21, 60), absent(5, 61)],
            [absent(5, 60), absent(21, 61)],
            [absent(5, 49), absent(5, 61)],
            [absent(5, 60), absent(5, 49)],
            [
                OutcomeAnswer {
                    oldest_ledger: None,
                    ..absent(5, 60)
                },
                absent(5, 61),
            ],
        ] {
            assert!(
                classify_non_inclusion(&released, &answers, None).is_err(),
                "{answers:?}"
            );
        }
        let good = [absent(5, 60), absent(5, 61)];
        assert!(classify_non_inclusion(&exposed(false), &good, None).is_err());
        let mut no_provenance = released.clone();
        no_provenance.pre_exposure_ledger = None;
        assert!(classify_non_inclusion(&no_provenance, &good, None).is_err());
        let mut untimed = released;
        if let ExposureIdentity::Classic { max_time, .. } = &mut untimed.exposure {
            *max_time = 0;
        }
        assert!(classify_non_inclusion(&untimed, &good, None).is_err());
    }

    /// Recorded history loss disables complete history across restart and
    /// eviction, and account non-inclusion still decides.
    #[test]
    #[serial_test::serial]
    fn recovery_history_loss_disables_only_complete_history() {
        let mut fx = Fx::new();
        let original = stored_attempt(&mut fx);
        let mut input = pending(&original, NOW, "evidence_pending", "history");
        if let Some(update) = &mut input.recovery {
            update.history_incomplete = true;
        }
        input.expected_attempt = Some(original.clone());
        fx.recorder()
            .record_evidence(original.operation_id, original.attempt_index, &input)
            .unwrap();
        let mut clear = pending(&original, NOW, "evidence_pending", "later");
        if let Some(update) = &mut clear.recovery {
            update.history_incomplete = false;
        }
        fx.recorder()
            .record_evidence(original.operation_id, original.attempt_index, &clear)
            .unwrap();
        let reopened = PersistedWindowStore::at_path(fx.store.path().to_owned());
        let stored = OperationStatus::new(&reopened, &fx.profile)
            .outcome_snapshot(None)
            .unwrap()
            .remove(0);
        assert!(stored.recovery.history_incomplete);
        let mut released = exposed(true);
        released.recovery = stored.recovery;
        let good = [absent(5, 60), absent(5, 61)];
        assert!(classify_non_inclusion(&released, &good, None).is_err());
        assert!(matches!(
            classify_non_inclusion(&released, &good, Some(&accounts(6, 6, (60, 61)))),
            Ok(NotIncludedProof::AccountSequence { .. })
        ));
    }

    fn observed(answer: impl Into<serde_json::Value>) -> crate::ObservedTransaction {
        crate::ObservedTransaction::from_json(&answer.into()).unwrap()
    }

    const PRIMARY_CANONICAL: &str = r#"{"status":"SUCCESS","ledger":120,"created_at":1700000000,"tx_hash":"AB07","envelope_xdr":"AAAA+/==","result_xdr":"AAAB","latest_ledger":130,"oldest_ledger":10}"#;
    const ABSENT_CANONICAL: &str = r#"{"status":"NOT_FOUND","ledger":null,"created_at":null,"tx_hash":null,"envelope_xdr":null,"result_xdr":null,"latest_ledger":null,"oldest_ledger":null}"#;

    /// Fixed vectors: the canonical bytes keep the field order, raw texts,
    /// JSON integers and explicit nulls, and the digest hashes the ordered
    /// pair. Swapping the pair or the time's encoding changes the digest.
    #[test]
    fn recovery_answer_digest_uses_ordered_raw_fields() {
        let primary = OutcomeAnswer::from_observed(&observed(json!({
            "status": "SUCCESS", "ledger": 120, "createdAt": "1700000000",
            "txHash": "AB07", "envelopeXdr": "AAAA+/==", "resultXdr": "AAAB",
            "latestLedger": 130, "oldestLedger": 10,
        })));
        let numeric_time = OutcomeAnswer::from_observed(&observed(json!({
            "status": "SUCCESS", "ledger": 120, "createdAt": 1_700_000_000_u64,
            "txHash": "AB07", "envelopeXdr": "AAAA+/==", "resultXdr": "AAAB",
            "latestLedger": 130, "oldestLedger": 10,
        })));
        assert_eq!(primary, numeric_time);
        let absent = OutcomeAnswer::from_observed(&observed(json!({"status": "NOT_FOUND"})));
        assert_eq!(serde_json::to_string(&primary).unwrap(), PRIMARY_CANONICAL);
        assert_eq!(serde_json::to_string(&absent).unwrap(), ABSENT_CANONICAL);
        let pair = [primary.clone(), absent.clone()];
        assert_eq!(
            serde_json::to_string(&pair).unwrap(),
            format!("[{PRIMARY_CANONICAL},{ABSENT_CANONICAL}]")
        );
        assert_eq!(
            stellar_agent_core::hex::encode(&outcome_digest(&pair).unwrap()),
            "46a7cd3b0a095f42bf61bdd40b8531d77e914e7d3794f6f794b08c61b8774ce1"
        );
        assert_ne!(
            outcome_digest(&[absent.clone(), primary.clone()]).unwrap(),
            outcome_digest(&pair).unwrap()
        );
        let mut normalized = primary.clone();
        normalized.envelope_xdr = Some("AAAA+/".to_owned());
        assert_ne!(
            outcome_digest(&[normalized, absent.clone()]).unwrap(),
            outcome_digest(&pair).unwrap()
        );

        let accounts = [
            AccountAnswer {
                sequence: Some(41),
                latest_ledger: Some(300),
            },
            AccountAnswer::default(),
        ];
        assert_eq!(
            serde_json::to_string(&accounts).unwrap(),
            r#"[{"sequence":41,"latest_ledger":300},{"sequence":null,"latest_ledger":null}]"#
        );
        assert_eq!(
            stellar_agent_core::hex::encode(&account_digest(&accounts).unwrap()),
            "59f9d2ea076db89a3a8c35542aec7a245e6c718c0e75e7edced338c982e4cbba"
        );

        let digest = outcome_digest(&pair).unwrap();
        let row = primary
            .row(EvidenceEndpoint::Primary, digest, Some(999))
            .unwrap();
        assert_eq!(row.observed_ledger, 130);
        let EvidenceAnswer::Outcome {
            envelope_xdr,
            result_xdr,
            created_at,
            ..
        } = &row.answer
        else {
            panic!("an outcome row: {row:?}");
        };
        assert_eq!(
            envelope_xdr.map(|digest| stellar_agent_core::hex::encode(&digest)),
            Some("e640c604417959de2d64dc1f1069a89fc45a678b508fbbc28a19635b94fba897".to_owned())
        );
        assert_eq!(*result_xdr, Some(Sha256::digest("AAAB").into()));
        assert_eq!(*created_at, Some(1_700_000_000));
        let fallback = absent
            .row(EvidenceEndpoint::Witness, digest, Some(140))
            .unwrap();
        assert_eq!(fallback.observed_ledger, 140);
        assert!(
            absent
                .row(EvidenceEndpoint::Witness, digest, None)
                .is_none()
        );
        let account = accounts[1]
            .row(EvidenceEndpoint::Witness, digest, Some(77))
            .unwrap();
        assert_eq!(account.observed_ledger, 77);
    }

    /// The counter rises by one per disagreement, saturates at 255, resets
    /// on concurrence, never suppresses concurrence at zero, and pending
    /// answers leave it. The committed state survives restart, and an
    /// evaluation that is never committed changes nothing.
    #[test]
    #[serial_test::serial]
    fn recovery_counter_and_pass_state_follow_evidence_classification() {
        let good = included("SUCCESS", result_text(true, 50));
        let mut late = good.clone();
        late.ledger = Some(41);
        let cases = [
            (0, [good.clone(), late.clone()], 1, None),
            (254, [good.clone(), late.clone()], 255, None),
            (255, [good.clone(), late], 255, None),
            (7, [good.clone(), good.clone()], 0, Some(())),
            (0, [good.clone(), good.clone()], 0, Some(())),
            (
                9,
                [
                    OutcomeAnswer {
                        oldest_ledger: None,
                        ..good.clone()
                    },
                    good.clone(),
                ],
                9,
                None,
            ),
        ];
        for (before, answers, after, decided) in cases {
            let mut attempt = exposed(false);
            attempt.recovery.disagreements = before;
            let evaluated = evaluate_outcome(
                &attempt,
                Some(answers),
                (None, None),
                None,
                (Some(60), Some(61)),
                NOW,
                "pending",
            )
            .unwrap();
            assert_eq!(
                evaluated.input.recovery.as_ref().unwrap().disagreements,
                after,
                "{before}"
            );
            assert_eq!(evaluated.decision.is_some(), decided.is_some(), "{before}");
            assert_eq!(evaluated.input.recovery.unwrap().last_pass_at_ms, Some(NOW));
        }

        let mut fx = Fx::new();
        let original = stored_attempt(&mut fx);
        let mut disagreeing = exposed(false);
        disagreeing.recovery = original.recovery.clone();
        let mut late = good.clone();
        late.ledger = Some(41);
        let mut evaluated = evaluate_outcome(
            &disagreeing,
            Some([good.clone(), late]),
            (None, None),
            None,
            (Some(60), Some(61)),
            NOW,
            "pending",
        )
        .unwrap();
        evaluated.input.expected_attempt = Some(original.clone());
        evaluated.input.rows.clear();
        fx.recorder()
            .record_evidence(
                original.operation_id,
                original.attempt_index,
                &evaluated.input,
            )
            .unwrap();
        let reopened = PersistedWindowStore::at_path(fx.store.path().to_owned());
        let stored = OperationStatus::new(&reopened, &fx.profile)
            .outcome_snapshot(None)
            .unwrap()
            .remove(0);
        assert_eq!(stored.recovery.disagreements, 1);
        assert_eq!(
            stored.recovery.last_outcome.as_deref(),
            Some("disagreement")
        );
        assert_eq!(stored.recovery.last_pass_at_ms, Some(NOW));

        let bytes = std::fs::read(fx.store.path()).unwrap();
        let _uncommitted = evaluate_outcome(
            &stored,
            Some([good.clone(), good]),
            (None, None),
            None,
            (Some(60), Some(61)),
            NOW + 1,
            "pending",
        )
        .unwrap();
        assert_eq!(std::fs::read(fx.store.path()).unwrap(), bytes);
    }

    /// Transaction retention that starts after the pre-exposure ledger sets
    /// the sticky history loss before classification. The flag persists
    /// across restart for an attempt whose sequence release is already
    /// recorded, and complete-history non-inclusion stays undecided.
    #[test]
    #[serial_test::serial]
    fn recovery_transaction_pruning_sets_sticky_history_loss() {
        use super::super::operations::tests::decided_attempt;
        let pruned = [absent(21, 60), absent(5, 61)];
        let evaluated = evaluate_outcome(
            &exposed(true),
            Some(pruned.clone()),
            (None, None),
            None,
            (Some(60), Some(61)),
            NOW,
            "pending",
        )
        .unwrap();
        assert!(evaluated.decision.is_none());
        assert!(evaluated.input.recovery.unwrap().history_incomplete);

        let mut fx = Fx::new();
        let (_handle, attempt) = decided_attempt(&mut fx, 1);
        assert!(attempt.sequence_release.is_some());
        assert!(!attempt.recovery.history_incomplete);
        let mut retained = pruned;
        for answer in &mut retained {
            answer.oldest_ledger = Some(11);
        }
        let mut evaluated = evaluate_outcome(
            &attempt,
            Some(retained),
            (None, None),
            None,
            (Some(60), Some(61)),
            NOW,
            "pending",
        )
        .unwrap();
        evaluated.input.expected_attempt = Some(attempt.clone());
        fx.recorder()
            .record_evidence(
                attempt.operation_id,
                attempt.attempt_index,
                &evaluated.input,
            )
            .unwrap();
        let reopened = PersistedWindowStore::at_path(fx.store.path().to_owned());
        let stored = OperationStatus::new(&reopened, &fx.profile)
            .outcome_snapshot(None)
            .unwrap()
            .remove(0);
        assert!(stored.recovery.history_incomplete);
        assert!(evaluated.decision.is_none());
    }

    /// A pruned transaction answer read from one endpoint persists the
    /// sticky history loss when the other endpoint's read fails.
    #[test]
    #[serial_test::serial]
    fn recovery_partial_pruned_answer_sets_sticky_history_loss() {
        use super::super::operations::tests::decided_attempt;
        let mut fx = Fx::new();
        let (_, attempt) = decided_attempt(&mut fx, 1);
        let answers = [absent(11, 140), OutcomeAnswer::default()];
        // The collector's partial-read path after the witness's transport failure.
        let mut evaluated = evaluate_outcome(
            &attempt,
            None,
            (None, None),
            None,
            (Some(140), Some(141)),
            NOW,
            "endpoint_unreachable",
        )
        .unwrap();
        evaluated
            .input
            .rows
            .extend(partial_rows(&answers, [true, false], (Some(140), Some(141))).unwrap());
        evaluated.input.expected_attempt = Some(attempt.clone());
        fx.recorder()
            .record_evidence(
                attempt.operation_id,
                attempt.attempt_index,
                &evaluated.input,
            )
            .unwrap();
        let stored = OperationStatus::new(&fx.store, &fx.profile)
            .outcome_snapshot(None)
            .unwrap()
            .remove(0);
        assert!(
            stored.recovery.history_incomplete,
            "a successfully read pruned transaction answer must persist history loss"
        );
    }

    /// A transport failure of one account read decides nothing, not even a
    /// complete-history non-inclusion, and names the failure.
    #[test]
    fn recovery_account_transport_failure_decides_nothing() {
        let evaluated = evaluate_outcome(
            &exposed(true),
            Some([absent(5, 60), absent(5, 61)]),
            (None, None),
            Some(Err("endpoint_unreachable")),
            (Some(60), Some(61)),
            NOW,
            "endpoint_unreachable",
        )
        .unwrap();
        assert!(
            evaluated.decision.is_none(),
            "account read transport failure must keep the pass undecided"
        );
        assert_eq!(
            evaluated.input.recovery.unwrap().diagnostic.as_deref(),
            Some("endpoint_unreachable")
        );
    }

    /// The one account answer read beside a failed read keeps its row under
    /// the pair digest; a complete or empty pair yields none.
    #[test]
    fn recovery_partial_account_answer_keeps_its_row() {
        let read = AccountAnswer {
            sequence: Some(6),
            latest_ledger: Some(60),
        };
        let shared = (Some(60), Some(61));
        let rows = partial_account_rows([Err("endpoint_unreachable"), Ok(read)], shared).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].endpoint, EvidenceEndpoint::Witness);
        assert_eq!(
            rows[0].digest,
            account_digest(&[AccountAnswer::default(), read]).unwrap()
        );
        assert_eq!(
            rows[0].answer,
            EvidenceAnswer::Account {
                sequence: Some(6),
                latest_ledger: Some(60),
            }
        );
        assert!(
            partial_account_rows([Ok(read), Ok(read)], shared)
                .unwrap()
                .is_empty()
        );
        assert!(
            partial_account_rows(
                [Err("endpoint_unreachable"), Err("request_allowance")],
                shared
            )
            .unwrap()
            .is_empty()
        );
    }

    /// Commits `transition` after the accounting horizon of attempt 1, with
    /// and without its accounting expiry. Both runs commit to `state` with
    /// equal window totals. The expired rows stay expired, neither charged
    /// again nor released twice.
    fn assert_outcome_after_accounting_expiry(
        label: &str,
        transition: &DecidedTransition,
        state: OperationState,
    ) {
        use super::super::operations::tests::{bucket_rows, decide, decided_attempt, envelope_id};
        use super::super::store::RecordStatus;
        use stellar_agent_core::policy::v1::criteria::state_store::{PolicyStateStore, StateKey};
        let mut outcomes = Vec::new();
        {
            for expire in [false, true] {
                let mut fx = Fx::new();
                let (handle, _) = decided_attempt(&mut fx, 1);
                let max_time = NOW / 1_000 + 60;
                fx.rewrite(|wire| {
                    for record in wire
                        .entries
                        .iter_mut()
                        .flat_map(|bucket| &mut bucket.records)
                    {
                        if record.id == envelope_id(1) {
                            record.max_time = max_time;
                        }
                    }
                });
                let after = max_time * 1_000 + 86_400_000 + 1;
                fx.clock.set(after);
                if expire {
                    let hold = fx
                        .store
                        .pending_reservations(&fx.profile)
                        .unwrap()
                        .into_iter()
                        .find(|hold| hold.id == envelope_id(1))
                        .unwrap();
                    assert!(
                        fx.store
                            .expire_accounting(&fx.profile, None, &hold, after)
                            .unwrap()
                            .is_some(),
                        "{label}"
                    );
                }
                let attempt = OperationStatus::new(&fx.store, &fx.profile)
                    .outcome_snapshot(Some(&[1 ^ 0x80; 32]))
                    .unwrap()
                    .pop()
                    .unwrap();
                fx.recorder()
                    .commit_decision(&decide(&attempt, transition.clone()))
                    .unwrap_or_else(|error| panic!("{label}, expired {expire}: {error}"));
                assert_eq!(fx.record(handle.id()).state, state, "{label}");
                let memory = PolicyStateStore::new();
                fx.store.load_into("ops", &fx.profile, &memory).unwrap();
                let totals: Vec<_> = ["native", "usdc"]
                    .into_iter()
                    .map(|bucket| {
                        memory
                            .query_window(&StateKey::new("ops", 1, bucket, 86_400), after)
                            .unwrap()
                    })
                    .collect();
                if expire {
                    let rows = bucket_rows(&fx, 1);
                    assert_eq!(rows.len(), 2, "{label}: no expired row is released twice");
                    assert!(
                        rows.iter()
                            .all(|row| row.1 == RecordStatus::AccountingExpired),
                        "{label}: expired rows stay expired"
                    );
                }
                outcomes.push(totals);
            }
            assert_eq!(outcomes[0], outcomes[1], "{label}");
        }
    }

    /// A success after accounting expiry commits and resurrects no charge.
    #[test]
    #[serial_test::serial]
    fn recovery_success_after_accounting_expiry_commits() {
        use super::super::operations::tests::agreed;
        assert_outcome_after_accounting_expiry(
            "success",
            &DecidedTransition::Succeeded(agreed(1, "SUCCESS")),
            OperationState::Succeeded,
        );
    }

    /// A failure after accounting expiry commits and charges no fee again.
    #[test]
    #[serial_test::serial]
    fn recovery_failure_after_accounting_expiry_commits() {
        use super::super::operations::tests::agreed;
        assert_outcome_after_accounting_expiry(
            "failure",
            &DecidedTransition::Failed {
                outcome: agreed(1, "FAILED"),
                fee_charged: 100,
            },
            OperationState::Failed,
        );
    }

    /// An account non-inclusion after accounting expiry commits and
    /// releases no expired row twice.
    #[test]
    #[serial_test::serial]
    fn recovery_account_non_inclusion_after_accounting_expiry_commits() {
        use super::super::operations::tests::not_included_proof;
        assert_outcome_after_accounting_expiry(
            "account non-inclusion",
            &DecidedTransition::NotIncluded(not_included_proof()),
            OperationState::NotIncluded,
        );
    }

    /// A complete-history non-inclusion after accounting expiry commits and
    /// releases no expired row twice.
    #[test]
    #[serial_test::serial]
    fn recovery_history_non_inclusion_after_accounting_expiry_commits() {
        use super::super::operations::EndpointCoverage;
        let coverage = |latest| EndpointCoverage {
            first_ledger: 10,
            last_ledger: latest,
            latest_ledger: latest,
            oldest_ledger: 5,
        };
        assert_outcome_after_accounting_expiry(
            "history non-inclusion",
            &DecidedTransition::NotIncluded(NotIncludedProof::CompleteHistory {
                primary: coverage(140),
                witness: coverage(141),
            }),
            OperationState::NotIncluded,
        );
    }

    /// An accounting horizon releases only bucket accounting: the classic
    /// outcome stays unknown, the attempt stays selected for recovery, and
    /// its native reservation keeps counting without a release row.
    #[test]
    #[serial_test::serial]
    fn recovery_bucket_horizon_keeps_classic_outcome_and_native_obligation_open() {
        use super::super::operations::tests::{bucket_rows, decided_attempt, envelope_id};
        use super::super::store::RecordStatus;
        let mut fx = Fx::new();
        let (handle, _) = decided_attempt(&mut fx, 1);
        let max_time = NOW / 1_000 + 60;
        fx.rewrite(|wire| {
            for record in wire
                .entries
                .iter_mut()
                .flat_map(|bucket| &mut bucket.records)
            {
                if record.id == envelope_id(1) {
                    record.max_time = max_time;
                }
            }
        });
        let hold = fx
            .store
            .pending_reservations(&fx.profile)
            .unwrap()
            .into_iter()
            .find(|hold| hold.id == envelope_id(1))
            .unwrap();
        let after = max_time * 1_000 + 86_400_000 + 1;
        fx.clock.set(after);
        let settled = fx
            .store
            .expire_accounting(&fx.profile, None, &hold, after)
            .unwrap();
        assert!(settled.is_some());
        assert!(
            bucket_rows(&fx, 1)
                .iter()
                .all(|row| row.1 == RecordStatus::AccountingExpired)
        );
        let record = fx.record(handle.id());
        assert_eq!(record.state, OperationState::SentOutcomeUnknown);
        let status = OperationStatus::new(&fx.store, &fx.profile);
        assert_eq!(status.outcome_snapshot(None).unwrap().len(), 1);
        assert_eq!(status.native_reserved_stroops(None).unwrap(), 125);
        assert!(
            fx.wire()
                .authorizations
                .iter()
                .all(|auth| auth.native_release.is_none())
        );
    }

    /// Raw time capture stays apart from its encoding: negative, malformed,
    /// fractional and absent times keep their codes, and a missing deciding
    /// field is `missing_field`, never a parse failure.
    #[test]
    fn recovery_missing_fields_and_times_keep_their_codes() {
        for (raw, expected) in [
            (None, Ok(None)),
            (Some(json!(null)), Ok(None)),
            (Some(json!(0)), Ok(Some(0))),
            (Some(json!(1_700_000_000_u64)), Ok(Some(1_700_000_000))),
            (Some(json!("1700000000")), Ok(Some(1_700_000_000))),
            (Some(json!(-1)), Err(INVALID_TIME)),
            (Some(json!("-1")), Err(INVALID_TIME)),
            (Some(json!(1.5)), Err(INVALID_TIME)),
            (Some(json!("12a")), Err(INVALID_TIME)),
            (Some(json!("")), Err(INVALID_TIME)),
            (Some(json!("99999999999999999999999")), Err(INVALID_TIME)),
            (Some(json!(true)), Err(INVALID_TIME)),
        ] {
            assert_eq!(canonical_time(raw.as_ref()), expected, "{raw:?}");
        }
        let full = json!({
            "status": "FAILED", "ledger": 120, "createdAt": 1_700_000_000_u64,
            "txHash": "AB07", "envelopeXdr": "AAAA", "resultXdr": "AAAB",
            "latestLedger": 130, "oldestLedger": 10,
        });
        assert_eq!(
            OutcomeAnswer::from_observed(&observed(full.clone())).defect(),
            None
        );
        for field in [
            "status",
            "ledger",
            "createdAt",
            "txHash",
            "envelopeXdr",
            "resultXdr",
            "latestLedger",
            "oldestLedger",
        ] {
            let mut answer = full.clone();
            answer.as_object_mut().unwrap().remove(field);
            assert_eq!(
                OutcomeAnswer::from_observed(&observed(answer)).defect(),
                Some(MISSING_FIELD),
                "{field}"
            );
        }
        for bad in [json!(-5), json!("later"), json!(2.25)] {
            let mut answer = full.clone();
            answer["createdAt"] = bad.clone();
            let canonical = OutcomeAnswer::from_observed(&observed(answer));
            assert_eq!(canonical.defect(), Some(INVALID_TIME), "{bad}");
            assert_eq!(canonical.created_at, None);
            assert!(
                serde_json::to_string(&canonical)
                    .unwrap()
                    .contains(r#""created_at":null"#)
            );
        }
        let uncovered = observed(json!({"status": "NOT_FOUND", "latestLedger": 130}));
        assert_eq!(
            OutcomeAnswer::from_observed(&uncovered).defect(),
            Some(MISSING_FIELD)
        );
        let covered = observed(json!({
            "status": "NOT_FOUND", "latestLedger": 130, "oldestLedger": 10,
        }));
        assert_eq!(OutcomeAnswer::from_observed(&covered).defect(), None);
        let long = "x".repeat(100_000);
        let detail = OutcomeAnswer::from_observed(&observed(json!({"status": long})))
            .defect()
            .unwrap();
        assert!(detail.len() <= 16, "{detail}");
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
                Some(&deciding(7, 11, 10)),
                NOW,
                "pending",
            )
            .unwrap();
            assert_eq!(
                input.sequence_released,
                Some(SequenceReleaseInput {
                    primary_ledger: 7,
                    witness_ledger: 7,
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
            let scan = scan_page(&first, 1, 10, 200).unwrap();
            if boundary <= 200 {
                assert_eq!(scan.upper, Some(boundary));
            } else {
                assert_eq!(scan.upper, None);
                assert_eq!(scan.cursor, 201);
                let next = scan_page(&page(201, 1, 201, 11), scan.cursor, 10, 1).unwrap();
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
            assert!(scan_page(&page, 1, 10, 200).is_none());
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
                let scan = scan_page(&page, 1, 10, 200).unwrap();
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
            Some(&deciding(7, 11, 10)),
            NOW,
            "pending",
        )
        .unwrap()
    }

    fn selected_batch(attempts: &[RecoveryAttempt]) -> Batch {
        Batch {
            inputs: attempts
                .iter()
                .map(|attempt| {
                    let mut input = release_input(attempt);
                    input.expected_attempt = Some(attempt.clone());
                    (attempt.operation_id, attempt.attempt_index, input)
                })
                .collect(),
            ..Batch::default()
        }
    }

    #[test]
    #[serial_test::serial]
    fn recovery_partial_sequence_failure_reports_verified_progress() {
        let mut fx = Fx::new();
        unknown_named(&mut fx, 1);
        unknown_named(&mut fx, 2);
        let store = fx.store.clone();
        let profile = fx.profile.clone();
        let status = OperationStatus::new(&store, &profile);
        let attempts = status.recovery_snapshot(None).unwrap();
        assert_eq!(attempts.len(), 2);
        // A separate recorder commits from the same initial view.
        let other_store = PersistedWindowStore::at_path(store.path().to_owned());
        let mut other_sink = super::super::operations::tests::Sink::default();
        OperationRecorder::new(&other_store, &profile, &mut other_sink, "other")
            .record_evidence(
                attempts[1].operation_id,
                attempts[1].attempt_index,
                &pending(
                    &attempts[1],
                    NOW,
                    "evidence_pending",
                    "endpoint_unreachable",
                ),
            )
            .unwrap();
        let other_record = fx.record(attempts[1].operation_id);
        let error = commit_sequence_batch(
            &mut fx.recorder(),
            selected_batch(&attempts),
            &status,
            &attempts,
        )
        .unwrap_err();
        assert_eq!(error.code(), "submission.record_unavailable");
        assert!(
            error
                .to_string()
                .contains("selected sequences: 1 released, 1 held, 0 unavailable"),
            "one selected sequence is released and the other is held: {error}"
        );
        assert_eq!(
            serde_json::to_value(fx.record(attempts[1].operation_id)).unwrap(),
            serde_json::to_value(other_record).unwrap()
        );
        let pass = crate::submission_flow::ReconcilePass::RecoveryFailed {
            legacy: Default::default(),
            error,
        };
        let (warnings, guard) = stellar_agent_test_support::WarningCapture::capture(None);
        crate::submission_flow::finish_reconciliation(&profile, "ops", &store, None, &pass, || {
            panic!("no accounting obligation needs a writer")
        })
        .unwrap();
        drop(guard);
        let messages = format!("{:?}", warnings.seen());
        assert!(
            messages.contains("1 released, 1 held, 0 unavailable"),
            "{messages}"
        );
        assert!(
            !messages.contains("every sequence stays held"),
            "{messages}"
        );
        let release = fx.record(attempts[0].operation_id).attempts[0]
            .sequence_released
            .clone();
        assert!(release.is_some());
        for clock in [NOW - 60_000, NOW + 365 * 24 * 60 * 60 * 1_000] {
            fx.clock.set(clock);
            let reopened = PersistedWindowStore::at_path(store.path().to_owned());
            let reopened_status = OperationStatus::new(&reopened, &profile);
            assert_eq!(
                sequence_failure_detail(&reopened_status, &attempts),
                "selected sequences: 1 released, 1 held, 0 unavailable"
            );
        }
        fx.clock.set(NOW);
        let fresh = status.recovery_snapshot(None).unwrap();
        assert_eq!(fresh.len(), 1);
        commit_sequence_batch(&mut fx.recorder(), selected_batch(&fresh), &status, &fresh).unwrap();
        assert_eq!(
            sequence_failure_detail(&status, &attempts),
            "selected sequences: 2 released, 0 held, 0 unavailable"
        );
        assert_eq!(
            fx.record(attempts[0].operation_id).attempts[0].sequence_released,
            release
        );
        let before = (std::fs::read(store.path()).unwrap(), fx.sink.entries.len());
        let stale = commit_sequence_batch(
            &mut fx.recorder(),
            selected_batch(&attempts),
            &status,
            &attempts,
        )
        .unwrap_err();
        assert!(
            stale
                .to_string()
                .contains("2 released, 0 held, 0 unavailable")
        );
        assert_eq!(
            (std::fs::read(store.path()).unwrap(), fx.sink.entries.len()),
            before
        );
    }

    #[test]
    #[serial_test::serial]
    fn recovery_sequence_failure_keeps_unavailable_state_unknown() {
        let mut fx = Fx::new();
        let attempt = stored_attempt(&mut fx);
        let status = OperationStatus::new(&fx.store, &fx.profile);
        let mut missing = attempt.clone();
        missing.attempt_index += 1;
        assert_eq!(
            sequence_failure_detail(&status, &[missing]),
            "selected sequences: 0 released, 0 held, 1 unavailable",
            "an unavailable attempt is not held"
        );
        let mut changed = attempt.clone();
        if let ExposureIdentity::Classic { tx_hash, .. } = &mut changed.exposure {
            tx_hash[0] ^= 1;
        }
        assert_eq!(
            sequence_failure_detail(&status, &[changed]),
            "selected sequences: 0 released, 0 held, 1 unavailable"
        );
        let mut bytes = std::fs::read(fx.store.path()).unwrap();
        bytes[0] ^= 1;
        std::fs::write(fx.store.path(), &bytes).unwrap();
        let read_code = status
            .recovery_snapshot(None)
            .unwrap_err()
            .submission_code();
        let detail = sequence_failure_detail(&status, &[attempt]);
        assert_eq!(
            detail,
            format!(
                "selected sequences: 0 released, 0 held, 1 unavailable; progress read refused with {read_code}"
            )
        );
        let error = RecoveryError::from(WindowStoreError::Invalid {
            detail: "commit refused".to_owned(),
        })
        .with_context(detail);
        assert_eq!(error.code(), "submission.record_unavailable");
        assert_eq!(std::fs::read(fx.store.path()).unwrap(), bytes);
    }

    #[test]
    #[serial_test::serial]
    fn recovery_sequence_failure_reads_the_commit_point() {
        use super::super::store::{
            COMMIT_FAULT_AFTER_COUNTER, COMMIT_FAULT_AFTER_PREPARED, arm_accounting_fault,
        };
        for seam in [COMMIT_FAULT_AFTER_PREPARED, COMMIT_FAULT_AFTER_COUNTER] {
            let mut fx = Fx::new();
            let attempt = stored_attempt(&mut fx);
            let store = fx.store.clone();
            let profile = fx.profile.clone();
            let attempts = [attempt];
            let error = {
                let _armed = arm_accounting_fault(seam);
                commit_sequence_batch(
                    &mut fx.recorder(),
                    selected_batch(&attempts),
                    &OperationStatus::new(&store, &profile),
                    &attempts,
                )
                .unwrap_err()
            };
            let expected = if seam == COMMIT_FAULT_AFTER_COUNTER {
                "selected sequences: 1 released, 0 held, 0 unavailable"
            } else {
                "selected sequences: 0 released, 1 held, 0 unavailable"
            };
            assert!(
                error.to_string().contains(expected),
                "the committed image decides release progress: {error}"
            );
            let (warnings, guard) = stellar_agent_test_support::WarningCapture::capture(None);
            crate::submission_flow::warn_status_recovery_refusal("ops", &error);
            drop(guard);
            let seen = warnings.seen();
            let logged = seen.first().unwrap();
            assert!(
                logged
                    .get("error")
                    .is_some_and(|detail| detail.contains(expected)),
                "the status warning retains durable progress: {seen:?}"
            );
            if seam == COMMIT_FAULT_AFTER_COUNTER {
                assert!(
                    logged
                        .get("message")
                        .is_some_and(|message| { !message.contains("every sequence stays held") }),
                    "the status warning does not call a committed release held: {seen:?}"
                );
            }
            let reopened = PersistedWindowStore::at_path(store.path().to_owned());
            let status = OperationStatus::new(&reopened, &profile);
            assert_eq!(sequence_failure_detail(&status, &attempts), expected);
            let fresh = status.recovery_snapshot(None).unwrap();
            commit_sequence_batch(&mut fx.recorder(), selected_batch(&fresh), &status, &fresh)
                .unwrap();
            assert_eq!(
                sequence_failure_detail(&status, &attempts),
                "selected sequences: 1 released, 0 held, 0 unavailable"
            );
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn recovery_entry_reports_progress_after_counter_commit() {
        use super::super::operations::tests::unknown_with;
        use super::super::store::{COMMIT_FAULT_AFTER_COUNTER, arm_accounting_fault};
        use crate::submission_flow::{ReconcilePass, finish_reconciliation};

        let mut fx = Fx::new();
        let id = unknown_with(&mut fx, 1, NOW / 1_000 - 10, vec![]).id();
        let primary = endpoint(7, NOW / 1_000).await;
        let oracle = endpoint(8, NOW / 1_000).await;
        let primary_client = StellarRpcClient::new(&primary.uri()).unwrap();
        let oracle_client = StellarRpcClient::new(&oracle.uri()).unwrap();
        let writer = crate::submission_flow::recovery::tests::writer_at(&fx.profile.audit_log_path);
        let error = {
            let _armed = arm_accounting_fault(COMMIT_FAULT_AFTER_COUNTER);
            recover_sequences(
                &fx.store,
                &fx.profile,
                EndpointPair::from_clients(&primary_client, Some(&oracle_client)),
                &writer,
                None,
            )
            .await
            .unwrap_err()
        };
        let expected = "selected sequences: 1 released, 0 held, 0 unavailable";
        assert!(
            error.to_string().contains(expected),
            "the recovery entry reports the committed release: {error}"
        );
        assert_eq!(error.code(), "submission.record_unavailable");
        assert!(fx.record(id).attempts[0].sequence_released.is_some());
        let pass = ReconcilePass::RecoveryFailed {
            legacy: Default::default(),
            error,
        };
        let (warnings, guard) = stellar_agent_test_support::WarningCapture::capture(None);
        finish_reconciliation(&fx.profile, "ops", &fx.store, None, &pass, || {
            Ok(Arc::clone(&writer))
        })
        .unwrap();
        drop(guard);
        let seen = warnings.seen();
        let logged = seen
            .iter()
            .find(|fields| fields.contains_key("error"))
            .unwrap();
        assert!(
            logged
                .get("error")
                .is_some_and(|detail| detail.contains(expected)),
            "the completion warning reports the committed release: {seen:?}"
        );
        assert_eq!(
            logged.get("message").map(String::as_str),
            Some("recovery: the stage refused; durable progress appears in the detail")
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn recovery_dispatch_store_context_precedes_repair_refusal() {
        use super::super::operations::tests::{Checked, historical_without, unknown_with};
        use super::super::store::{COMMIT_FAULT_AFTER_COUNTER, arm_accounting_fault};

        let mut fx = Fx::new();
        unknown_with(&mut fx, 1, NOW / 1_000 - 10, vec![]);
        let (_, refused) = historical_without(&mut fx, 2, Checked::NotIncluded, "source");
        let primary = endpoint(7, NOW / 1_000).await;
        let client = StellarRpcClient::new(&primary.uri()).unwrap();
        let writer = crate::submission_flow::recovery::tests::writer_at(&fx.profile.audit_log_path);
        let home = tempfile::tempdir().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
        let receipts = crate::submission_flow::open_receipts("ops").unwrap();
        let pass = {
            let _armed = arm_accounting_fault(COMMIT_FAULT_AFTER_COUNTER);
            crate::submission_flow::reconcile_pass(
                &fx.profile,
                &fx.store,
                &client,
                Some(&client),
                Some(&receipts),
                NOW,
                || Ok(Arc::clone(&writer)),
            )
            .await
        };
        let crate::submission_flow::ReconcilePass::RecoveryFailed {
            error: RecoveryError::Context { source, detail },
            ..
        } = pass
        else {
            panic!("the sequence refusal retains repair context: {pass:?}");
        };
        assert!(detail.contains(&refused.to_hex()));
        assert!(detail.contains("missing_projection_fact:source"));
        let RecoveryError::Context { source, detail } = *source else {
            panic!("the sequence progress remains authoritative: {source:?}");
        };
        assert!(matches!(*source, RecoveryError::Store(_)));
        assert_eq!(
            detail,
            "selected sequences: 1 released, 0 held, 0 unavailable"
        );
    }

    #[test]
    #[serial_test::serial]
    fn recovery_progress_counts_only_matched_stored_releases() {
        let (mut fx, id, _) = unmatched_release_fixture();
        let attempts = OperationStatus::new(&fx.store, &fx.profile)
            .recovery_snapshot(None)
            .unwrap();
        assert_eq!(
            sequence_failure_detail(&OperationStatus::new(&fx.store, &fx.profile), &attempts),
            "selected sequences: 0 released, 1 held, 0 unavailable"
        );
        fx.recorder()
            .record_evidence(
                id,
                1,
                &EvidenceInput {
                    sequence_released: Some(SequenceReleaseInput {
                        primary_ledger: 60,
                        witness_ledger: 60,
                        min_close_time_ms: NOW,
                    }),
                    ..EvidenceInput::default()
                },
            )
            .unwrap();
        assert_eq!(
            sequence_failure_detail(&OperationStatus::new(&fx.store, &fx.profile), &attempts),
            "selected sequences: 1 released, 0 held, 0 unavailable"
        );
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
            (Some(7), Some(7), Some(11_000))
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
                        witness_ledger: 10,
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
                            witness_ledger: 10,
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
        assert_eq!(expected.rpc_calls, 0);
        let primary_before = primary.received_requests().await.unwrap().len();
        let oracle_before = oracle.received_requests().await.unwrap().len();
        assert_eq!(primary_before + oracle_before, 0);
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
        assert_eq!(total, 0);
        assert_eq!(
            fx.window.pending_reservations(&fx.profile).unwrap(),
            reservations
        );
        assert_eq!(fx.receipts.get(&hold.id).unwrap(), receipt);
        crate::submission_flow::RECOVERY_STAGE_TRACE
            .with_borrow(|trace| assert_eq!(trace, &["expire", "legacy", "recovery"]));
    }

    /// The methods `server` receives, in order.
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
            "recovery: the stage refused; unresolved sequences stay held",
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
        assert_eq!(rpc_request_count(&primary, "getLedgers").await, 1);
        assert_eq!(rpc_request_count(&oracle, "getLedgers").await, 1);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn recovery_status_labels_missing_sequence_evidence() {
        use super::super::operations::tests::{Checked, historical_without};
        let mut fx = Fx::new();
        historical_without(&mut fx, 1, Checked::NotIncluded, "submission_ledger");
        let unknown = unknown_named(&mut fx, 2).id();
        let hash = [1 ^ 0x80; 32];
        fx.rewrite(|wire| {
            let record = wire
                .operations
                .as_mut()
                .unwrap()
                .records
                .iter_mut()
                .find(|record| record.id == unknown)
                .unwrap();
            let ExposureIdentity::Classic { tx_hash, .. } =
                &mut record.attempts[0].exposure.as_mut().unwrap().identity
            else {
                panic!("classic attempt required");
            };
            *tx_hash = hash;
        });
        assert_eq!(
            OperationStatus::new(&fx.store, &fx.profile)
                .recovery_snapshot(Some(&hash))
                .unwrap()
                .len(),
            1
        );
        let server = endpoint(7, NOW / 1000).await;
        mount(&server, "getTransaction", json!({"status":"NOT_FOUND", "latestLedger":7,
            "oldestLedger":1, "latestLedgerCloseTime":(NOW/1000).to_string(), "oldestLedgerCloseTime":"1"})).await;
        let client = StellarRpcClient::new(&server.uri()).unwrap();
        let writer = crate::submission_flow::recovery::tests::writer_at(&fx.profile.audit_log_path);
        let home = tempfile::tempdir().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
        let (warnings, guard) = stellar_agent_test_support::WarningCapture::capture(None);
        let answer = crate::submission_flow::transaction_status(
            crate::submission_flow::StatusRequest {
                profile: &fx.profile,
                profile_name: "ops",
                tx_hash: &stellar_agent_core::hex::encode(&hash),
                window: &fx.store,
                client: &client,
                oracle: None,
            },
            || Ok(home.path().join("approvals")),
            || Ok(Arc::clone(&writer)),
        )
        .await
        .unwrap();
        drop(guard);
        assert_eq!(answer.chain_status, "NOT_FOUND");
        let seen = warnings.seen();
        let repair = seen
            .iter()
            .find(|fields| {
                fields.get("message").is_some_and(|message| {
                    message.starts_with("transaction status: checked receipt repair refused")
                })
            })
            .unwrap();
        assert_eq!(
            repair.get("sequence_recovery").map(String::as_str),
            Some("\"evidence missing\"")
        );
        assert!(
            repair
                .get("detail")
                .unwrap()
                .contains("missing_projection_fact:submission_ledger")
        );
    }

    #[tokio::test]
    async fn recovery_malformed_history_charges_one_request() {
        let server = MockServer::start().await;
        let client = StellarRpcClient::new(&server.uri()).unwrap();
        let shared = SharedObservation {
            report: OperationalReport {
                latest_ledger: 3,
                close_time_unix: NOW / 1_000,
                close_lag_seconds: 0,
            },
            oldest: 1,
            read_at: Instant::now(),
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
                history(&client, &shared, &mut budget, &attempt, true, 3)
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
                json!({"method":"getLedgers", "params":{"pagination":{"limit":1}}}),
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
                shared: 4
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
        mount(&server, "getHealth", json!({"status":"healthy", "latestLedger":ledger, "oldestLedger":1, "ledgerRetentionWindow":ledger,"latestLedgerCloseTime":close,"oldestLedgerCloseTime":1})).await;
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
        assert!(shared_observation(&client, &mut budget, NOW).await.is_err());
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
    async fn compact_health_has_no_metadata_dependency() {
        let server = endpoint(7, NOW / 1_000).await;
        let client = StellarRpcClient::new(&server.uri()).unwrap();
        Mock::given(method("POST"))
            .and(body_partial_json(json!({"method":"getLatestLedger"})))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_string("x".repeat(11 * 1024 * 1024)),
            )
            .with_priority(1)
            .mount(&server)
            .await;
        let observed = shared_observation(&client, &mut Budget::new(), NOW).await;
        assert!(
            observed.is_ok(),
            "compact health must not read ledger metadata"
        );
        assert_eq!(methods(&server).await, ["getHealth"]);
    }

    #[tokio::test]
    async fn singleton_history_cannot_grant_complete_history_proof() {
        let primary = endpoint(60, NOW / 1000).await;
        let oracle = endpoint(61, NOW / 1000).await;
        for (server, ledger) in [(&primary, 60), (&oracle, 61)] {
            mount(server, "getTransaction", json!({"status":"NOT_FOUND", "oldestLedger":1,
                "latestLedger":ledger, "oldestLedgerCloseTime":"1", "latestLedgerCloseTime":NOW/1000})).await;
        }
        let left = StellarRpcClient::new(&primary.uri()).unwrap();
        let right = StellarRpcClient::new(&oracle.uri()).unwrap();
        let mut attempt = exposed(true);
        attempt.account = None;
        let (evaluations, _, _, failure) = collect_outcomes(
            &EndpointPair::from_clients(&left, Some(&right)),
            &[attempt],
            NOW,
        )
        .await
        .unwrap();
        assert_eq!(evaluations.len(), 1);
        assert!(
            evaluations[0].decision.is_none(),
            "unpaired singles cannot release a debit through history"
        );
        assert_eq!(failure.unwrap().reason, RecoveryReason::CoverageRequired);
    }

    #[tokio::test]
    async fn health_shape_and_freshness() {
        for defect in 0..10 {
            let server = MockServer::start().await;
            let mut health = json!({"status":"healthy", "latestLedger":7, "oldestLedger":1,
                "ledgerRetentionWindow":7, "latestLedgerCloseTime":NOW/1000, "oldestLedgerCloseTime":1});
            match defect {
                0 => {
                    health
                        .as_object_mut()
                        .unwrap()
                        .remove("latestLedgerCloseTime");
                }
                1 => health["oldestLedger"] = json!(0),
                2 => health["oldestLedger"] = json!(8),
                3 => health["ledgerRetentionWindow"] = json!(0),
                4 => health["status"] = json!("unhealthy"),
                5 => health["oldestLedgerCloseTime"] = json!(0),
                6 => health["oldestLedgerCloseTime"] = json!(NOW / 1000 + 1),
                7 => health["latestLedgerCloseTime"] = json!(NOW / 1000 - 61),
                8 => health["latestLedgerCloseTime"] = json!(NOW / 1000 + 61),
                _ => {
                    health
                        .as_object_mut()
                        .unwrap()
                        .remove("oldestLedgerCloseTime");
                }
            }
            mount(&server, "getHealth", health).await;
            let client = StellarRpcClient::new(&server.uri()).unwrap();
            let mut budget = Budget::new();
            assert!(
                shared_observation(&client, &mut budget, NOW).await.is_err(),
                "invalid health {defect}"
            );
            assert_eq!(
                budget.failure.unwrap().reason,
                if matches!(defect, 0 | 1 | 2 | 3 | 5 | 6 | 9) {
                    RecoveryReason::MissingField
                } else {
                    RecoveryReason::Lagging
                },
                "invalid health {defect}"
            );
            assert_eq!(methods(&server).await, ["getHealth"]);
        }
        let server = endpoint(7, NOW / 1000).await;
        let client = StellarRpcClient::new(&server.uri()).unwrap();
        let mut observed = shared_observation(&client, &mut Budget::new(), NOW)
            .await
            .unwrap();
        observed.read_at = Instant::now() - OBSERVATION_AGE - Duration::from_millis(1);
        assert!(observed.stale());
    }

    #[tokio::test]
    async fn recovery_unadmissible_health_reports_lagging() {
        let server = endpoint(7, NOW / 1000 - 61).await;
        let client = StellarRpcClient::new(&server.uri()).unwrap();
        let batch = collect(
            &EndpointPair::from_clients(&client, Some(&client)),
            &[attempt(10)],
            NOW,
        )
        .await
        .unwrap();
        assert!(batch.inputs[0].2.sequence_released.is_none());
        assert_eq!(
            batch.missing,
            Some(RecoveryFailure {
                reason: RecoveryReason::Lagging,
                endpoint: RecoveryEndpoint::Primary,
                method: RecoveryMethod::GetHealth,
                ledger: None,
            })
        );
        assert_eq!(
            methods(&server).await,
            ["getNetwork", "getNetwork", "getHealth"]
        );
    }

    #[tokio::test]
    async fn recovery_tip_sequence_releases_in_one_pass() {
        for oracle_tip in [7, 8] {
            for outcomes in [false, true] {
                let primary = endpoint(7, 140).await;
                let oracle = endpoint(oracle_tip, u64::from(oracle_tip) * 20).await;
                for (server, tip) in [(&primary, 7), (&oracle, oracle_tip)] {
                    Mock::given(method("POST"))
                        .and(body_partial_json(json!({"method":"getLedgers"})))
                        .respond_with(move |request: &wiremock::Request| {
                            let body: serde_json::Value =
                                serde_json::from_slice(&request.body).unwrap();
                            let start =
                                u32::try_from(body["params"]["startLedger"].as_u64().unwrap())
                                    .unwrap();
                            wiremock::Respond::respond(
                                &EchoIdResponder::new(page_json(
                                    start,
                                    1,
                                    tip,
                                    u64::from(start) * 20,
                                )),
                                request,
                            )
                        })
                        .with_priority(1)
                        .mount(server)
                        .await;
                    mount(
                        server,
                        "getTransaction",
                        json!({"status":"NOT_FOUND", "oldestLedger":1, "latestLedger":tip}),
                    )
                    .await;
                }
                let left = StellarRpcClient::new(&primary.uri()).unwrap();
                let right = StellarRpcClient::new(&oracle.uri()).unwrap();
                let pair = EndpointPair::from_clients(&left, Some(&right));
                let mut attempt = attempt(100);
                let mut passes = 0;
                let mut requests = RecoveryRequests::default();
                let release = loop {
                    passes += 1;
                    let (input, used) = if outcomes {
                        let (mut evaluations, _, used, missing) =
                            collect_outcomes(&pair, &[attempt.clone()], 140_000)
                                .await
                                .unwrap();
                        assert!(missing.is_none());
                        (evaluations.remove(0).input, used)
                    } else {
                        let mut batch = collect(&pair, &[attempt.clone()], 140_000).await.unwrap();
                        assert!(batch.missing.is_none());
                        (batch.inputs.remove(0).2, batch.requests)
                    };
                    requests.attempt += used.attempt;
                    requests.shared += used.shared;
                    if let Some(release) = input.sequence_released {
                        break release;
                    }
                    assert!(passes < 7, "the expired sequence must release");
                    attempt.recovery = input.recovery.unwrap();
                };
                assert_eq!(passes, 1);
                assert_eq!(
                    requests,
                    RecoveryRequests {
                        attempt: if outcomes { 4 } else { 2 },
                        shared: 4
                    }
                );
                assert_eq!((release.primary_ledger, release.witness_ledger), (7, 7));
                assert_eq!(release.min_close_time_ms, 140_000);
                assert_eq!(requested_starts(&primary).await, [7]);
                assert_eq!(requested_starts(&oracle).await, [7]);
                assert_eq!(
                    primary.received_requests().await.unwrap().len()
                        + oracle.received_requests().await.unwrap().len(),
                    if outcomes { 8 } else { 6 }
                );
            }
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn recovery_target_coverage_waits_for_equal_tips() {
        for primary_ahead in [true, false] {
            for saved_upper in [false, true] {
                for outcomes in [false, true] {
                    let mut fx = Fx::new();
                    let id = super::super::operations::tests::unknown_with(
                        &mut fx,
                        1,
                        NOW / 1000 - 1,
                        vec![],
                    )
                    .id();
                    let account =
                        stellar_agent_test_support::signed_envelope::account_id_for_seed([1; 32]);
                    fx.rewrite(|wire| {
                        let auth = &mut wire.authorizations[0];
                        let super::super::DomainBinding::Transaction { source, .. } =
                            &mut auth.binding
                        else {
                            panic!("classic binding required");
                        };
                        *source = account.clone();
                        auth.native_reservation = Some(super::super::NativeReservation {
                            debit_stroops: 25,
                            fee_stroops: 100,
                        });
                    });
                    if saved_upper {
                        fx.recorder()
                            .record_evidence(
                                id,
                                1,
                                &EvidenceInput {
                                    recovery: Some(RecoveryUpdate {
                                        primary_upper: primary_ahead.then_some(9),
                                        witness_upper: (!primary_ahead).then_some(9),
                                        ..RecoveryUpdate::default()
                                    }),
                                    ..EvidenceInput::default()
                                },
                            )
                            .unwrap();
                    }
                    let held = OperationStatus::new(&fx.store, &fx.profile)
                        .native_reserved_stroops(None)
                        .unwrap();
                    assert_eq!(held, 125);
                    for pass in 0..3 {
                        let tips = if pass > 0 {
                            [9, 9]
                        } else if primary_ahead {
                            [9, 7]
                        } else {
                            [7, 9]
                        };
                        let primary = endpoint(tips[0], NOW / 1000).await;
                        let oracle = endpoint(tips[1], NOW / 1000).await;
                        for (index, server) in [&primary, &oracle].into_iter().enumerate() {
                            let oldest = if !saved_upper && (index == 0) == primary_ahead {
                                9
                            } else {
                                1
                            };
                            Mock::given(method("POST"))
                                .and(body_partial_json(json!({"method":"getHealth"})))
                                .respond_with(EchoIdResponder::new(json!({
                                    "status":"healthy", "latestLedger":tips[index], "oldestLedger":oldest,
                                    "ledgerRetentionWindow":tips[index] - oldest + 1,
                                    "latestLedgerCloseTime":NOW/1000, "oldestLedgerCloseTime":1
                                })))
                                .with_priority(1).mount(server).await;
                            mount(server, "getTransaction", json!({
                                "status":"NOT_FOUND", "latestLedger":tips[index], "oldestLedger":1
                            })).await;
                        }
                        let left = StellarRpcClient::new(&primary.uri()).unwrap();
                        let right = StellarRpcClient::new(&oracle.uri()).unwrap();
                        let pair = EndpointPair::from_clients(&left, Some(&right));
                        let attempts = OperationStatus::new(&fx.store, &fx.profile)
                            .outcome_snapshot(None)
                            .unwrap();
                        for (server, tip) in [(&primary, tips[0]), (&oracle, tips[1])] {
                            let mut answer = stellar_agent_test_support::signed_envelope::ledger_entries_result_for(&[&account]);
                            answer["latestLedger"] = json!(tip);
                            mount(server, "getLedgerEntries", answer).await;
                        }
                        let batch = if outcomes {
                            let (evaluations, observation, requests, missing) =
                                collect_outcomes(&pair, &attempts, NOW).await.unwrap();
                            assert_eq!(evaluations.len(), 1);
                            if pass < 2 {
                                assert!(evaluations[0].decision.is_none());
                            } else {
                                assert!(matches!(
                                    evaluations[0].decision,
                                    Some((
                                        DecidedTransition::NotIncluded(
                                            NotIncludedProof::AccountSequence { .. }
                                        ),
                                        _,
                                        _
                                    ))
                                ));
                            }
                            Batch {
                                inputs: evaluations
                                    .into_iter()
                                    .map(|e| {
                                        (e.attempt.operation_id, e.attempt.attempt_index, e.input)
                                    })
                                    .collect(),
                                observation,
                                requests,
                                missing,
                            }
                        } else {
                            collect(&pair, &attempts, NOW).await.unwrap()
                        };
                        if pass == 0 {
                            assert!(batch.inputs[0].2.sequence_released.is_none());
                            assert_eq!(
                                batch.missing,
                                Some(RecoveryFailure {
                                    reason: RecoveryReason::CoverageRequired,
                                    endpoint: if primary_ahead {
                                        RecoveryEndpoint::Primary
                                    } else {
                                        RecoveryEndpoint::Oracle
                                    },
                                    method: RecoveryMethod::GetLedgers,
                                    ledger: Some(7),
                                })
                            );
                            assert_eq!(
                                requested_starts(if primary_ahead { &primary } else { &oracle })
                                    .await,
                                Vec::<u64>::new()
                            );
                            assert_eq!(
                                requested_starts(if primary_ahead { &oracle } else { &primary })
                                    .await,
                                [7]
                            );
                        } else {
                            assert!(batch.missing.is_none());
                            if pass == 1 {
                                let release = batch.inputs[0].2.sequence_released.unwrap();
                                assert_eq!(
                                    (release.primary_ledger, release.witness_ledger),
                                    (9, 9)
                                );
                                assert_eq!(requested_starts(&primary).await, [9]);
                                assert_eq!(requested_starts(&oracle).await, [9]);
                            }
                        }
                        let report = commit_batch(&mut fx.recorder(), batch).unwrap();
                        if pass == 0 {
                            assert!(matches!(
                                report.require_evidence(),
                                Err(RecoveryError::NeedsEvidence(RecoveryFailure {
                                    reason: RecoveryReason::CoverageRequired,
                                    ..
                                }))
                            ));
                        }
                        let record = fx.record(id);
                        assert_eq!(record.attempts[0].sequence_released.is_some(), pass > 0);
                        assert_eq!(record.state, OperationState::SentOutcomeUnknown);
                        assert_eq!(
                            OperationStatus::new(&fx.store, &fx.profile)
                                .native_reserved_stroops(None)
                                .unwrap(),
                            held
                        );
                        assert_eq!(
                            fx.sink
                                .entries
                                .iter()
                                .filter(|entry| matches!(
                                    entry.event_kind,
                                    EventKind::OperationEvidence {
                                        sequence_released: true,
                                        ..
                                    }
                                ))
                                .count(),
                            usize::from(pass > 0)
                        );
                    }
                }
            }
        }
    }

    fn unmatched_release_fixture() -> (Fx, OperationId, String) {
        use super::super::operations::tests::unknown_with;

        let mut fx = Fx::new();
        let id = unknown_with(&mut fx, 1, NOW / 1000 - 1, vec![]).id();
        let account = stellar_agent_test_support::signed_envelope::account_id_for_seed([1; 32]);
        fx.rewrite(|wire| {
            let auth = &mut wire.authorizations[0];
            let super::super::DomainBinding::Transaction { source, .. } = &mut auth.binding else {
                panic!("classic binding required");
            };
            *source = account.clone();
            auth.native_reservation = Some(super::super::NativeReservation {
                debit_stroops: 25,
                fee_stroops: 100,
            });
        });
        fx.recorder()
            .record_evidence(
                id,
                1,
                &EvidenceInput {
                    sequence_released: Some(SequenceReleaseInput {
                        primary_ledger: 50,
                        witness_ledger: 51,
                        min_close_time_ms: NOW,
                    }),
                    ..EvidenceInput::default()
                },
            )
            .unwrap();
        (fx, id, account)
    }

    async fn unmatched_release_endpoints(account: &str, tips: [u32; 2]) -> [MockServer; 2] {
        let servers = [
            endpoint(tips[0], NOW / 1000).await,
            endpoint(tips[1], NOW / 1000).await,
        ];
        for (server, tip) in servers.iter().zip(tips) {
            Mock::given(method("POST"))
                .and(body_partial_json(json!({"method":"getHealth"})))
                .respond_with(EchoIdResponder::new(json!({
                    "status":"healthy", "latestLedger":tip, "oldestLedger":tip,
                    "ledgerRetentionWindow":1,
                    "latestLedgerCloseTime":NOW/1000, "oldestLedgerCloseTime":NOW/1000
                })))
                .with_priority(1)
                .mount(server)
                .await;
            mount(
                server,
                "getTransaction",
                json!({
                    "status":"NOT_FOUND", "oldestLedger":1, "latestLedger":tip
                }),
            )
            .await;
            let mut answer =
                stellar_agent_test_support::signed_envelope::ledger_entries_result_for(&[account]);
            answer["latestLedger"] = json!(tip);
            mount(server, "getLedgerEntries", answer).await;
        }
        servers
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn recovery_unmatched_stored_release_keeps_debit_when_target_unreadable() {
        let (mut fx, id, account) = unmatched_release_fixture();
        let attempts = OperationStatus::new(&fx.store, &fx.profile)
            .outcome_snapshot(None)
            .unwrap();
        assert!(
            classify_non_inclusion(
                &attempts[0],
                &[absent(1, 60), absent(1, 59)],
                Some(&accounts(0, 0, (60, 59))),
            )
            .is_err()
        );
        assert_eq!(
            OperationStatus::new(&fx.store, &fx.profile)
                .recovery_snapshot(None)
                .unwrap()
                .len(),
            1
        );
        let ExposureIdentity::Classic {
            envelope_sha256, ..
        } = attempts[0].exposure
        else {
            panic!("classic exposure required");
        };
        assert!(
            !OperationStatus::new(&fx.store, &fx.profile)
                .sequence_released_unlocked(
                    &stellar_agent_core::profile::receipt::AttemptRef::EnvelopeHash(
                        envelope_sha256
                    )
                )
                .unwrap()
        );
        let [primary, oracle] = unmatched_release_endpoints(&account, [60, 59]).await;
        let left = StellarRpcClient::new(&primary.uri()).unwrap();
        let right = StellarRpcClient::new(&oracle.uri()).unwrap();
        let (evaluations, _, _, missing) = collect_outcomes(
            &EndpointPair::from_clients(&left, Some(&right)),
            &attempts,
            NOW,
        )
        .await
        .unwrap();
        assert_eq!(evaluations.len(), 1);
        assert!(evaluations[0].decision.is_none());
        assert!(evaluations[0].input.sequence_released.is_none());
        assert_eq!(
            missing,
            Some(RecoveryFailure {
                reason: RecoveryReason::CoverageRequired,
                endpoint: RecoveryEndpoint::Primary,
                method: RecoveryMethod::GetLedgers,
                ledger: Some(59),
            })
        );
        assert_eq!(requested_starts(&primary).await, Vec::<u64>::new());
        assert_eq!(requested_starts(&oracle).await, [59]);
        fx.recorder()
            .record_evidence(id, 1, &evaluations[0].input)
            .unwrap();
        assert_eq!(fx.record(id).state, OperationState::SentOutcomeUnknown);
        let release = fx.record(id).attempts[0].sequence_released.clone().unwrap();
        assert_eq!((release.primary_ledger, release.witness_ledger), (50, 51));
        assert_eq!(
            OperationStatus::new(&fx.store, &fx.profile)
                .native_reserved_stroops(None)
                .unwrap(),
            125
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn recovery_unmatched_stored_release_reads_target_once_then_decides() {
        let (mut fx, id, account) = unmatched_release_fixture();
        for pass in 0..3 {
            let [primary, oracle] = unmatched_release_endpoints(&account, [60, 60]).await;
            let left = StellarRpcClient::new(&primary.uri()).unwrap();
            let right = StellarRpcClient::new(&oracle.uri()).unwrap();
            let attempts = OperationStatus::new(&fx.store, &fx.profile)
                .outcome_snapshot(None)
                .unwrap();
            let (evaluations, _, _, missing) = collect_outcomes(
                &EndpointPair::from_clients(&left, Some(&right)),
                &attempts,
                NOW,
            )
            .await
            .unwrap();
            assert!(missing.is_none());
            assert_eq!(evaluations.len(), usize::from(pass < 2));
            let starts: Vec<u64> = if pass == 0 { vec![60] } else { vec![] };
            assert_eq!(requested_starts(&primary).await, starts);
            assert_eq!(requested_starts(&oracle).await, starts);
            if let Some(evaluation) = evaluations.into_iter().next() {
                if pass == 0 {
                    assert!(evaluation.decision.is_none());
                    let release = evaluation.input.sequence_released.unwrap();
                    assert_eq!((release.primary_ledger, release.witness_ledger), (60, 60));
                } else {
                    assert!(evaluation.input.sequence_released.is_none());
                    assert!(matches!(
                        evaluation.decision,
                        Some((
                            DecidedTransition::NotIncluded(
                                NotIncludedProof::AccountSequence { .. }
                            ),
                            _,
                            _
                        ))
                    ));
                }
                fx.recorder()
                    .record_evidence(id, 1, &evaluation.input)
                    .unwrap();
                assert_eq!(
                    OperationStatus::new(&fx.store, &fx.profile)
                        .native_reserved_stroops(None)
                        .unwrap(),
                    125
                );
                if let Some((transition, digest, ledgers)) = evaluation.decision {
                    let fresh = OperationStatus::new(&fx.store, &fx.profile)
                        .outcome_snapshot(None)
                        .unwrap()
                        .remove(0);
                    let decision = CheckedRecoveryDecision::new(
                        &fresh,
                        digest,
                        ledgers,
                        transition,
                        evaluation.input.recovery.unwrap(),
                    )
                    .unwrap();
                    fx.recorder().commit_decision(&decision).unwrap();
                }
            }
            let release = fx.record(id).attempts[0].sequence_released.clone().unwrap();
            assert_eq!((release.primary_ledger, release.witness_ledger), (60, 60));
            assert_eq!(
                fx.sink
                    .entries
                    .iter()
                    .filter(|entry| matches!(
                        entry.event_kind,
                        EventKind::OperationEvidence {
                            sequence_released: true,
                            ..
                        }
                    ))
                    .count(),
                2
            );
            assert_eq!(
                fx.record(id).state,
                if pass == 0 {
                    OperationState::SentOutcomeUnknown
                } else {
                    OperationState::NotIncluded
                }
            );
            assert_eq!(
                OperationStatus::new(&fx.store, &fx.profile)
                    .native_reserved_stroops(None)
                    .unwrap(),
                if pass == 0 { 125 } else { 0 }
            );
        }
    }

    #[test]
    fn recovery_sequence_release_requires_matching_ledger_and_close() {
        for (ledger, close) in [(9, 11), (7, 12)] {
            let input = evaluate(
                &attempt(10),
                Some(&deciding(7, 11, 10)),
                Some(&deciding(ledger, close, 10)),
                NOW,
                "pending",
            )
            .unwrap();
            assert!(input.sequence_released.is_none());
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn recovery_history_failures_keep_each_reads_reason() {
        for parse_first in [true, false] {
            let mut fx = Fx::new();
            let ids = [
                unknown_named(&mut fx, 1).id(),
                unknown_named(&mut fx, 2).id(),
            ];
            for (id, ledger) in ids.iter().zip([1, 2]) {
                fx.recorder()
                    .record_evidence(
                        *id,
                        1,
                        &EvidenceInput {
                            recovery: Some(RecoveryUpdate {
                                primary_cursor: Some(ledger),
                                witness_cursor: Some(ledger),
                                primary_upper: Some(ledger),
                                witness_upper: Some(ledger),
                                ..RecoveryUpdate::default()
                            }),
                            ..EvidenceInput::default()
                        },
                    )
                    .unwrap();
            }
            let mut attempts = OperationStatus::new(&fx.store, &fx.profile)
                .recovery_snapshot(None)
                .unwrap();
            attempts.sort_by_key(|attempt| attempt.recovery.primary_upper);
            let primary = endpoint(7, NOW / 1000).await;
            let oracle = endpoint(7, NOW / 1000).await;
            let calls = std::sync::atomic::AtomicUsize::new(0);
            Mock::given(method("POST"))
                .and(body_partial_json(json!({"method":"getLedgers"})))
                .respond_with(move |request: &wiremock::Request| {
                    let first = calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0;
                    if first == parse_first {
                        wiremock::Respond::respond(
                            &EchoIdResponder::new(json!({"ledgers":"invalid"})),
                            request,
                        )
                    } else {
                        wiremock::ResponseTemplate::new(500)
                    }
                })
                .with_priority(1)
                .mount(&primary)
                .await;
            let left = StellarRpcClient::new(&primary.uri()).unwrap();
            let right = StellarRpcClient::new(&oracle.uri()).unwrap();
            let batch = collect(
                &EndpointPair::from_clients(&left, Some(&right)),
                &attempts,
                NOW,
            )
            .await
            .unwrap();
            assert_eq!(
                batch.requests,
                RecoveryRequests {
                    attempt: 4,
                    shared: 4
                }
            );
            assert!(
                batch
                    .inputs
                    .iter()
                    .all(|(_, _, input)| input.sequence_released.is_none())
            );
            commit_batch(&mut fx.recorder(), batch).unwrap();
            for (id, ledger) in ids.iter().zip([1, 2]) {
                let record = fx.record(*id);
                let recovery = record.attempts[0].recovery.as_ref().unwrap();
                assert_eq!(
                    recovery.diagnostic.as_ref().map(|reason| reason.text()),
                    Some(if (ledger == 1) == parse_first {
                        "malformed_history"
                    } else {
                        "endpoint_unreachable"
                    })
                );
            }
            assert_eq!(requested_starts(&primary).await, [7, 7]);
        }
    }

    #[tokio::test]
    async fn recovery_not_found_without_latest_records_missing_field() {
        for missing_primary in [false, true] {
            let primary = endpoint(60, NOW / 1000).await;
            let oracle = endpoint(60, NOW / 1000).await;
            for (server, missing) in [(&primary, missing_primary), (&oracle, !missing_primary)] {
                let mut answer = json!({"status":"NOT_FOUND", "oldestLedger":1, "latestLedger":60});
                if missing {
                    answer.as_object_mut().unwrap().remove("latestLedger");
                }
                mount(server, "getTransaction", answer).await;
            }
            let left = StellarRpcClient::new(&primary.uri()).unwrap();
            let right = StellarRpcClient::new(&oracle.uri()).unwrap();
            let (evaluations, _, requests, missing) = collect_outcomes(
                &EndpointPair::from_clients(&left, Some(&right)),
                &[exposed(true)],
                NOW,
            )
            .await
            .unwrap();
            assert_eq!(evaluations.len(), 1);
            assert!(evaluations[0].decision.is_none());
            assert!(evaluations[0].input.sequence_released.is_none());
            assert_eq!(
                evaluations[0]
                    .input
                    .recovery
                    .as_ref()
                    .unwrap()
                    .diagnostic
                    .as_deref(),
                Some(MISSING_FIELD)
            );
            let expected = RecoveryFailure {
                reason: RecoveryReason::MissingField,
                endpoint: if missing_primary {
                    RecoveryEndpoint::Primary
                } else {
                    RecoveryEndpoint::Oracle
                },
                method: RecoveryMethod::GetTransaction,
                ledger: None,
            };
            assert_eq!(missing, Some(expected));
            let report = RecoveryReport {
                requests,
                evaluated: evaluations.len(),
                missing,
            };
            assert!(
                matches!(report.require_evidence(), Err(RecoveryError::NeedsEvidence(failure)) if failure == expected)
            );
        }
    }

    async fn account_recovery_fixture(
        primary_account: serde_json::Value,
        account: String,
    ) -> (Vec<Evaluated>, Option<RecoveryFailure>) {
        let primary = endpoint(60, NOW / 1000).await;
        let oracle = endpoint(60, NOW / 1000).await;
        for server in [&primary, &oracle] {
            mount(
                server,
                "getTransaction",
                json!({"status":"NOT_FOUND", "oldestLedger":1, "latestLedger":60}),
            )
            .await;
        }
        mount(&primary, "getLedgerEntries", primary_account).await;
        let mut valid =
            stellar_agent_test_support::signed_envelope::ledger_entries_result_for(&[&account]);
        valid["latestLedger"] = json!(60);
        mount(&oracle, "getLedgerEntries", valid).await;
        let left = StellarRpcClient::new(&primary.uri()).unwrap();
        let right = StellarRpcClient::new(&oracle.uri()).unwrap();
        let mut attempt = exposed(true);
        attempt.account = Some(account);
        let (evaluations, _, _, failure) = collect_outcomes(
            &EndpointPair::from_clients(&left, Some(&right)),
            &[attempt],
            NOW,
        )
        .await
        .unwrap();
        assert_eq!(evaluations.len(), 1);
        (evaluations, failure)
    }

    #[tokio::test]
    async fn recovery_account_read_below_its_health_tip_refuses() {
        let account = stellar_agent_test_support::signed_envelope::account_id_for_seed([1; 32]);
        for latest in [60, 55] {
            let mut answer =
                stellar_agent_test_support::signed_envelope::ledger_entries_result_for(&[&account]);
            answer["latestLedger"] = json!(latest);
            let (evaluations, failure) = account_recovery_fixture(answer, account.clone()).await;
            if latest == 60 {
                assert!(matches!(
                    evaluations[0].decision,
                    Some((
                        DecidedTransition::NotIncluded(NotIncludedProof::AccountSequence { .. }),
                        _,
                        _
                    ))
                ));
                assert!(failure.is_none());
            } else {
                assert!(evaluations[0].decision.is_none());
                assert!(evaluations[0].input.sequence_released.is_none());
                assert_eq!(
                    failure,
                    Some(RecoveryFailure {
                        reason: RecoveryReason::AccountUnavailable,
                        endpoint: RecoveryEndpoint::Primary,
                        method: RecoveryMethod::GetLedgerEntries,
                        ledger: None
                    })
                );
            }
        }
    }

    #[tokio::test]
    async fn recovery_missing_and_undecodable_accounts_keep_their_reasons() {
        let account = stellar_agent_test_support::signed_envelope::account_id_for_seed([1; 32]);
        for missing in [true, false] {
            let mut answer =
                stellar_agent_test_support::signed_envelope::ledger_entries_result_for(&[&account]);
            answer["latestLedger"] = json!(60);
            let reason = if missing {
                answer["entries"] = json!([]);
                RecoveryReason::CoverageRequired
            } else {
                answer["entries"][0]["xdr"] = json!("invalid");
                RecoveryReason::MissingField
            };
            let (evaluations, failure) = account_recovery_fixture(answer, account.clone()).await;
            assert!(evaluations[0].decision.is_none());
            assert!(evaluations[0].input.sequence_released.is_none());
            assert_eq!(
                failure,
                Some(RecoveryFailure {
                    reason,
                    endpoint: RecoveryEndpoint::Primary,
                    method: RecoveryMethod::GetLedgerEntries,
                    ledger: None
                })
            );
        }
    }

    async fn streamed_response(truncated: bool) -> (StellarRpcClient, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client =
            StellarRpcClient::new(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            let mut buffer = [0; 4096];
            let request: serde_json::Value = loop {
                let count = stream.read(&mut buffer).await.unwrap();
                assert_ne!(count, 0);
                bytes.extend_from_slice(&buffer[..count]);
                if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n")
                    && let Ok(request) = serde_json::from_slice(&bytes[end + 4..])
                {
                    break request;
                }
            };
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n").await.unwrap();
            let body = serde_json::to_vec(&json!({"jsonrpc":"2.0", "id":request["id"],
                "result":{"status":"NOT_FOUND", "padding":"x".repeat(if truncated { 100 } else { 11 * 1024 * 1024 })}})).unwrap();
            if truncated {
                stream.write_all(b"1000\r\n{").await.unwrap();
                return;
            }
            for chunk in body.chunks(16 * 1024) {
                let header = format!("{:x}\r\n", chunk.len());
                if stream.write_all(header.as_bytes()).await.is_err()
                    || stream.write_all(chunk).await.is_err()
                    || stream.write_all(b"\r\n").await.is_err()
                {
                    return;
                }
            }
            let _ = stream.write_all(b"0\r\n\r\n").await;
        });
        (client, task)
    }

    #[tokio::test]
    async fn stream_length_limit_is_oversize() {
        let (client, server) = streamed_response(false).await;
        let mut budget = Budget::new();
        budget.context(
            RecoveryEndpoint::Oracle,
            RecoveryMethod::GetTransaction,
            None,
        );
        assert!(
            budget
                .read(
                    false,
                    client.recovery_transaction(&stellar_xdr::Hash([0; 32]))
                )
                .await
                .is_err()
        );
        server.await.unwrap();
        assert_eq!(
            budget.failure.unwrap().reason,
            RecoveryReason::ResponseTooLarge
        );
        assert_eq!(budget.used.attempt, 1);
    }

    #[tokio::test]
    async fn other_stream_error_is_transport() {
        let (client, server) = streamed_response(true).await;
        let error = client
            .recovery_transaction(&stellar_xdr::Hash([0; 32]))
            .await
            .unwrap_err();
        server.await.unwrap();
        assert_eq!(read_failure(&error), RecoveryReason::Transport);
    }

    #[tokio::test]
    async fn non_history_oversize_is_typed() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_string("x".repeat(11 * 1024 * 1024)),
            )
            .mount(&server)
            .await;
        let client = StellarRpcClient::new(&server.uri()).unwrap();
        let hash = stellar_xdr::Hash([0; 32]);
        let account = stellar_agent_test_support::signed_envelope::account_id_for_seed([1; 32]);
        let report = OperationalReport {
            latest_ledger: 1,
            close_time_unix: NOW / 1000,
            close_lag_seconds: 0,
        };
        let errors = [
            client.recovery_identity().await.unwrap_err(),
            client.recovery_health().await.unwrap_err(),
            client.recovery_transaction(&hash).await.unwrap_err(),
            crate::account::fetch_account_recovery(&client, &account, &report)
                .await
                .unwrap_err(),
        ];
        for error in errors {
            assert_eq!(read_failure(&error), RecoveryReason::ResponseTooLarge);
        }
        assert_eq!(server.received_requests().await.unwrap().len(), 4);
    }

    #[tokio::test]
    async fn recovery_reads_one_measured_ledger() {
        let server = endpoint(7, NOW / 1000).await;
        Mock::given(method("POST"))
            .and(body_partial_json(json!({"method":"getLedgers"})))
            .respond_with(|request: &wiremock::Request| {
                let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
                let start = u32::try_from(body["params"]["startLedger"].as_u64().unwrap()).unwrap();
                if body["params"]["pagination"]["limit"] == 200 {
                    let mut result = page_json(start, 200, start + 199, NOW / 1000);
                    result["ledgers"][0]["metadataXdr"] = json!("x".repeat(11 * 1024 * 1024));
                    return wiremock::ResponseTemplate::new(200)
                        .insert_header("transfer-encoding", "chunked")
                        .set_body_json(json!({"jsonrpc":"2.0", "id":body["id"], "result":result}));
                }
                let mut result = page_json(start, 1, 7, NOW / 1000);
                result["ledgers"][0]["metadataXdr"] = json!("x".repeat(1_009_496));
                let mut answer = json!({"jsonrpc":"2.0","id":body["id"],"result":result});
                let padding = 1_010_468 - serde_json::to_vec(&answer).unwrap().len() - 13;
                answer["padding"] = json!("x".repeat(padding));
                assert_eq!(serde_json::to_vec(&answer).unwrap().len(), 1_010_468);
                wiremock::ResponseTemplate::new(200).set_body_json(answer)
            })
            .with_priority(1)
            .mount(&server)
            .await;
        let client = StellarRpcClient::new(&server.uri()).unwrap();
        let batch = collect(
            &EndpointPair::from_clients(&client, Some(&client)),
            &[attempt(NOW / 1000 - 1)],
            NOW,
        )
        .await
        .unwrap();
        assert!(batch.inputs[0].2.sequence_released.is_some());
        assert!(batch.missing.is_none());
        assert_eq!(
            batch.requests,
            RecoveryRequests {
                attempt: 2,
                shared: 4
            }
        );
        for request in server.received_requests().await.unwrap() {
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            if body["method"] == "getLedgers" {
                assert_eq!(
                    body["params"]["pagination"]["limit"], 1,
                    "recovery reads at most one ledger"
                );
            }
        }
        let error = client
            .inner
            .get_ledgers(LedgerStart::Ledger(1), Some(200), None)
            .await
            .unwrap_err();
        assert_eq!(rpc_failure(&error), RecoveryReason::ResponseTooLarge);
        let stellar_rpc_client::Error::JsonRpc(jsonrpsee_core::ClientError::Transport(error)) =
            error
        else {
            panic!("stream transport error required");
        };
        assert!(
            matches!(error.downcast_ref::<jsonrpsee_http_client::transport::Error>(),
            Some(jsonrpsee_http_client::transport::Error::Http(jsonrpsee_core::http_helpers::HttpError::Stream(error)))
                if stream_is_length_limit(error.as_ref()))
        );
    }

    #[test]
    fn retention_close_times_are_preserved() {
        let observed = observed(
            json!({"status":"NOT_FOUND", "oldestLedger":1, "latestLedger":7,
            "oldestLedgerCloseTime":"10", "latestLedgerCloseTime":20}),
        );
        assert_eq!(observed.oldest_ledger_close_time, Some(json!("10")));
        assert_eq!(observed.latest_ledger_close_time, Some(json!(20)));
        let absent = crate::ObservedTransaction::from_json(&json!({"status":"NOT_FOUND"})).unwrap();
        assert_eq!(absent.oldest_ledger_close_time, None);
        assert_eq!(absent.latest_ledger_close_time, None);
    }

    #[tokio::test]
    async fn rate_limit_is_typed() {
        for status in [429, 503] {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(wiremock::ResponseTemplate::new(status))
                .mount(&server)
                .await;
            let client = StellarRpcClient::new(&server.uri()).unwrap();
            let error = client.recovery_health().await.unwrap_err();
            assert_eq!(read_failure(&error), RecoveryReason::RateLimited);
            assert_eq!(server.received_requests().await.unwrap().len(), 1);
        }
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(|request: &wiremock::Request| {
                let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(json!({"jsonrpc":"2.0", "id":body["id"],
                "error":{"code":-32001,"message":"provider secret"}}))
            })
            .mount(&server)
            .await;
        let client = StellarRpcClient::new(&server.uri()).unwrap();
        let mut budget = Budget::new();
        assert!(budget.read(true, client.recovery_health()).await.is_err());
        assert_eq!(budget.failure.unwrap().reason, RecoveryReason::RateLimited);
        assert!(
            !serde_json::to_string(&budget.failure)
                .unwrap()
                .contains("secret")
        );
    }

    #[tokio::test(start_paused = true)]
    async fn all_reads_share_absolute_deadline() {
        for method in [
            RecoveryMethod::GetNetwork,
            RecoveryMethod::GetHealth,
            RecoveryMethod::GetTransaction,
            RecoveryMethod::GetLedgers,
            RecoveryMethod::GetLedgerEntries,
        ] {
            let mut budget = Budget::new();
            budget.context(RecoveryEndpoint::Oracle, method, Some(7));
            let start = Instant::now();
            assert_eq!(
                budget.read::<(), ()>(false, std::future::pending()).await,
                Err(ReadFailure::Deadline)
            );
            assert_eq!(Instant::now() - start, Duration::from_secs(20));
            let failure = budget.failure.unwrap();
            assert_eq!(
                failure,
                RecoveryFailure {
                    reason: RecoveryReason::Deadline,
                    endpoint: RecoveryEndpoint::Oracle,
                    method,
                    ledger: Some(7)
                }
            );
            assert_eq!(
                budget.read(false, async { Ok::<_, ()>(()) }).await,
                Err(ReadFailure::Deadline)
            );
            assert_eq!(budget.used.attempt, 1);
            let report = RecoveryReport {
                requests: budget.used,
                evaluated: 0,
                missing: Some(failure),
            };
            assert!(
                matches!(report.require_evidence(), Err(RecoveryError::NeedsEvidence(seen)) if seen == failure)
            );
        }
    }

    #[tokio::test]
    async fn recovery_four_attempts_use_eight_history_requests() {
        let primary = endpoint(7, NOW / 1_000).await;
        let oracle = endpoint(8, NOW / 1_000).await;
        let calls = std::sync::atomic::AtomicUsize::new(0);
        Mock::given(method("POST"))
            .and(body_partial_json(
                json!({"method":"getLedgers", "params":{"pagination":{"limit":1}}}),
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
                shared: 6
            }
        );
        assert_eq!(
            primary.received_requests().await.unwrap().len()
                + oracle.received_requests().await.unwrap().len(),
            14
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
                    json!({"method":"getLedgers", "params":{"pagination":{"limit":1}}}),
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
                shared: 6
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
                            witness_ledger: 7,
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
        assert_eq!(proof["witness_ledger"], 7);
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
                json!({"method":"getLedgers", "params":{"pagination":{"limit":1}}}),
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
