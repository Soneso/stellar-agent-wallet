//! Authenticated recovery metadata and pure scheduling views.
//! Reading a view changes neither proof nor accounting nor driver selection.

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use sha2::{Digest as _, Sha256};

use super::WindowStoreError;
use super::operations::{ExposureIdentity, OperationId, WireAttempt};
use super::recovery_scan::RecoveryScan;

/// The largest stored run object, including its JSON framing.
pub const RECOVERY_RUN_MAX: usize = 1_024;

/// A contextual recovery stop, including reasons available only in read views.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryStopReason {
    /// The signed expiry still bounds recovery.
    AwaitingExpiry,
    /// Only hash inclusion can resolve this exposure.
    Untimed,
    /// An answer lacks required facts.
    MissingField,
    /// The endpoints disagree.
    Disagreement,
    /// The response exceeds the transport bound.
    ResponseTooLarge,
    /// An endpoint refuses its current load.
    RateLimited,
    /// Transport cannot deliver evidence.
    Transport,
    /// An account is absent or regressed.
    AccountUnavailable,
    /// Evidence does not reach the required ledger.
    Lagging,
    /// The run deadline expires.
    Deadline,
    /// The request allowance is spent.
    RequestBudget,
    /// The clock precedes a persisted timestamp.
    ClockRegression,
    /// A covered account sequence requires unavailable history.
    CoverageRequired,
    /// An unread ledger is no longer retained.
    HistoryLost,
    /// The exposure has no authenticated starting ledger.
    MissingProvenance,
    /// Authenticated recovery metadata or source identity is unusable.
    RecordUnusable,
    /// An unfinished reservation reaches its lease deadline.
    #[serde(skip)]
    Interrupted,
    /// Required configuration is missing or contradictory.
    #[serde(skip)]
    ConfigurationRequired,
}

/// The evidence stage of a stop or ephemeral report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryStage {
    /// Transaction hash evidence.
    Hash,
    /// Ledger target evidence.
    Target,
    /// Account sequence evidence.
    Account,
    /// Reservation time or request allowance.
    Lease,
    /// Endpoint identity in an ephemeral prefix report.
    #[serde(skip)]
    Identity,
    /// Endpoint health in an ephemeral prefix report.
    #[serde(skip)]
    Health,
    /// Attempt selection in an ephemeral report.
    #[serde(skip)]
    Selection,
    /// Configuration in an ephemeral report.
    #[serde(skip)]
    Configuration,
    /// Unusable metadata in a normalized report.
    #[serde(skip)]
    Record,
}

/// A stored evidence request method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryRunMethod {
    /// Transaction lookup.
    GetTransaction,
    /// Ledger lookup.
    GetLedgers,
    /// Account lookup.
    GetLedgerEntries,
}

/// An endpoint's role in a stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryRole {
    /// The submission endpoint.
    Primary,
    /// The independent oracle.
    Oracle,
}

/// Whether another observation can repair a stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryClass {
    /// Another bounded observation can repair the failure.
    Automatic,
    /// A configuration, record or protocol fact prevents automatic progress.
    Explicit,
}

/// The stored ownership phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryRunPhase {
    /// A reservation owns a live or expired lease.
    Running,
    /// A reservation ends with a contextual stop.
    Stopped,
    /// A committed decision resolves the attempt.
    Resolved,
}

/// A bounded stop report. The target is reporting data and grants no proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryStop {
    /// The underlying cause.
    pub reason: RecoveryStopReason,
    /// The stage that observes the cause.
    pub stage: RecoveryStage,
    /// The method, absent for a local stop.
    #[serde(deserialize_with = "Deserialize::deserialize")]
    pub method: Option<RecoveryRunMethod>,
    /// Zero, one or both roles, with primary before oracle.
    pub roles: Vec<RecoveryRole>,
    /// The positive ledger named by the failed request.
    #[serde(deserialize_with = "Deserialize::deserialize")]
    pub ledger: Option<u32>,
    /// The positive target used by this run, for reporting only.
    #[serde(deserialize_with = "Deserialize::deserialize")]
    pub target: Option<u32>,
    /// The stable stop timestamp in Unix milliseconds.
    pub stopped_at_ms: u64,
    /// The contextual classification.
    pub class: RecoveryClass,
    /// The checked automatic retry time; explicit stops have none.
    #[serde(deserialize_with = "Deserialize::deserialize")]
    pub earliest_retry_ms: Option<u64>,
}

/// The interpreted run record, with an optional paired scan in version two.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireRecoveryRun {
    /// The record version, one without a scan or two with a scan.
    pub version: u8,
    /// The lowercase SHA-256 exposure binding.
    pub exposure: String,
    /// The ownership phase.
    pub phase: RecoveryRunPhase,
    /// The reservation timestamp in Unix milliseconds.
    pub run_started_ms: u64,
    /// The checked reservation timestamp plus 20,000 milliseconds.
    pub run_deadline_ms: u64,
    /// The spent reservations, from one through sixteen.
    pub automatic_runs: u8,
    /// The stops before a running reservation or including a stopped reservation.
    pub consecutive_stops: u8,
    /// The contextual stop, present only in the stopped phase.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_stop"
    )]
    pub stop: Option<RecoveryStop>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_scan"
    )]
    pub(super) scan: Option<RecoveryScan>,
}

fn deserialize_scan<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<RecoveryScan>, D::Error> {
    RecoveryScan::deserialize(d).map(Some)
}

fn deserialize_stop<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<RecoveryStop>, D::Error> {
    RecoveryStop::deserialize(d).map(Some)
}

#[derive(Clone, Serialize)]
pub(super) struct RawRecoveryRun(Box<RawValue>);

impl std::fmt::Debug for RawRecoveryRun {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RawRecoveryRun")
    }
}

impl PartialEq for RawRecoveryRun {
    fn eq(&self, other: &Self) -> bool {
        self.0.get() == other.0.get()
    }
}
impl Eq for RawRecoveryRun {}

impl<'de> Deserialize<'de> for RawRecoveryRun {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = Box::<RawValue>::deserialize(d)?;
        if raw.get().len() > RECOVERY_RUN_MAX || !raw.get().starts_with('{') {
            return Err(serde::de::Error::custom(
                "recovery_run requires a bounded object",
            ));
        }
        Ok(Self(raw))
    }
}

pub(super) fn deserialize_run<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<RawRecoveryRun>, D::Error> {
    RawRecoveryRun::deserialize(d).map(Some)
}

/// An authenticated run snapshot. Unusable data retains its exact stored identity.
#[derive(Debug, Clone)]
pub struct RecoveryRunSnapshot {
    raw: RawRecoveryRun,
    run: Option<WireRecoveryRun>,
    spent: Option<u8>,
}

impl PartialEq for RecoveryRunSnapshot {
    fn eq(&self, other: &Self) -> bool {
        match (&self.run, &other.run) {
            (Some(a), Some(b)) => a == b,
            _ => self.raw == other.raw,
        }
    }
}
impl Eq for RecoveryRunSnapshot {}

impl RecoveryRunSnapshot {
    /// The interpreted record, absent when its metadata is unusable.
    #[must_use]
    pub fn record(&self) -> Option<&WireRecoveryRun> {
        self.run.as_ref()
    }

    pub(super) fn of(
        id: OperationId,
        attempt: &WireAttempt,
        account: Option<&str>,
    ) -> Option<Self> {
        let raw = attempt.recovery_run.clone()?;
        #[derive(Deserialize)]
        struct Count {
            automatic_runs: u8,
        }
        let spent = serde_json::from_str::<Count>(raw.0.get())
            .ok()
            .map(|c| c.automatic_runs);
        let run = serde_json::from_str::<WireRecoveryRun>(raw.0.get())
            .ok()
            .filter(|run| {
                attempt.exposure.as_ref().is_some_and(|exposure| {
                    validate_run(
                        run,
                        id,
                        attempt.index,
                        &exposure.identity,
                        account,
                        attempt.decision.is_some(),
                        attempt,
                    )
                })
            });
        Some(Self { raw, run, spent })
    }
}

fn overflow() -> WindowStoreError {
    WindowStoreError::Invalid {
        detail: "recovery_schedule_overflow".into(),
    }
}

/// Computes a new reservation deadline with checked arithmetic.
///
/// # Errors
/// Returns `Invalid` with `recovery_schedule_overflow` when the sum is unrepresentable.
pub fn recovery_deadline(started_ms: u64) -> Result<u64, WindowStoreError> {
    started_ms.checked_add(20_000).ok_or_else(overflow)
}

/// Computes capped exponential backoff from the count before a stop.
#[must_use]
pub fn recovery_backoff(pre_stop_count: u8) -> u64 {
    1_u64
        .checked_shl(u32::from(pre_stop_count))
        .and_then(|factor| 30_000_u64.checked_mul(factor))
        .map_or(3_600_000, |delay| delay.min(3_600_000))
}

/// Computes a new retry time with checked arithmetic.
///
/// # Errors
/// Returns `Invalid` with `recovery_schedule_overflow` when the sum is unrepresentable.
pub fn recovery_retry_time(stopped_ms: u64, pre_stop_count: u8) -> Result<u64, WindowStoreError> {
    stopped_ms
        .checked_add(recovery_backoff(pre_stop_count))
        .ok_or_else(overflow)
}

/// The finite expiry bound; absence selects hash-only untimed recovery.
#[must_use]
pub fn recovery_expiry(max_time: u64) -> Option<u64> {
    (max_time > 0 && max_time != u64::MAX)
        .then_some(max_time)?
        .checked_add(6)?
        .checked_mul(1_000)
}

/// Classifies contextual failures without inferring configuration from answer quality.
#[must_use]
pub fn classify_recovery_stop(reason: RecoveryStopReason, stage: RecoveryStage) -> RecoveryClass {
    use RecoveryStopReason as R;
    if matches!(
        reason,
        R::ConfigurationRequired | R::RecordUnusable | R::HistoryLost | R::MissingProvenance
    ) || matches!(stage, RecoveryStage::Configuration | RecoveryStage::Record)
    {
        RecoveryClass::Explicit
    } else {
        RecoveryClass::Automatic
    }
}

/// Hashes only normalized provider hosts and declared operators, in role order.
///
/// The digest reads the `profile` its caller passes and binds no host: a
/// mismatch reopens a stopped run and restarts its history scan. On mainnet
/// the caller passes the profile whose hosts the enablement verified.
pub(super) fn recovery_configuration_digest(
    profile: &stellar_agent_core::profile::schema::Profile,
) -> String {
    use stellar_agent_core::profile::schema::{provider_host, provider_operator_fold};
    let providers = profile.providers.as_ref();
    let fields = [
        provider_host(&profile.rpc_url).unwrap_or_default(),
        provider_operator_fold(
            providers
                .and_then(|p| p.primary.as_ref())
                .map_or("", |p| p.operator.as_str()),
        ),
        provider_host(
            profile
                .oracle_provider_url
                .as_ref()
                .map_or("", url::Url::as_str),
        )
        .unwrap_or_default(),
        provider_operator_fold(
            providers
                .and_then(|p| p.oracle.as_ref())
                .map_or("", |p| p.operator.as_str()),
        ),
    ];
    let mut hash = Sha256::new();
    hash.update(b"stellar-agent/recovery-configuration/v1\0");
    for field in fields {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field.as_bytes());
    }
    stellar_agent_core::hex::encode(&hash.finalize())
}

fn configuration_reopens(snapshot: Option<&RecoveryRunSnapshot>, configuration: &str) -> bool {
    snapshot
        .and_then(RecoveryRunSnapshot::record)
        .is_some_and(|run| {
            run.automatic_runs < 16
                && run
                    .stop
                    .as_ref()
                    .is_some_and(|stop| stop.class == RecoveryClass::Explicit)
                && run
                    .scan
                    .as_ref()
                    .is_some_and(|scan| scan.configuration != configuration)
        })
}

pub(super) fn recovery_runnable(
    view: &RecoveryRunView,
    snapshot: Option<&RecoveryRunSnapshot>,
    now: u64,
    configuration: &str,
) -> bool {
    view.earliest_retry_ms.is_some_and(|due| now >= due)
        || configuration_reopens(snapshot, configuration)
}

/// Whether an explicit request may reserve a new run for a stopped attempt.
/// It needs interpreted metadata, a clock at or after every stored time, and
/// no live lease, so it never repairs unusable state or steals ownership.
/// A running lease before its deadline refuses even at the sixteenth
/// reservation, which normalization reports as exhausted.
pub(super) fn explicit_retry_eligible(
    view: &RecoveryRunView,
    snapshot: Option<&RecoveryRunSnapshot>,
    now: u64,
) -> bool {
    snapshot
        .and_then(RecoveryRunSnapshot::record)
        .is_some_and(|run| {
            let live = run.phase == RecoveryRunPhase::Running && now < run.run_deadline_ms;
            !live
                && now
                    >= run
                        .stop
                        .as_ref()
                        .map_or(run.run_started_ms, |s| s.stopped_at_ms)
                && match view.state {
                    RecoveryRunState::Stopped(reason) => {
                        reason != RecoveryStopReason::ClockRegression
                    }
                    RecoveryRunState::RetriesExhausted { .. } => true,
                    _ => false,
                }
        })
}

/// Whether an explicit request meets a stored run it may not reserve:
/// unusable metadata, a live lease, or a clock before a stored time.
pub(super) fn explicit_retry_refused(snapshot: Option<&RecoveryRunSnapshot>, now: u64) -> bool {
    snapshot.is_some_and(|snapshot| {
        snapshot.record().is_none_or(|run| {
            (run.phase == RecoveryRunPhase::Running && now < run.run_deadline_ms)
                || now
                    < run
                        .stop
                        .as_ref()
                        .map_or(run.run_started_ms, |s| s.stopped_at_ms)
        })
    })
}

/// Whether an explicit run continues the saved scan. Only a spent allowance,
/// deadline or interruption leaves the matched prefix compatible; every other
/// stop restarts the scan from the authenticated pre-exposure ledger.
pub(super) fn explicit_retry_keeps_scan(view: &RecoveryRunView) -> bool {
    use RecoveryStopReason as R;
    matches!(
        view.state,
        RecoveryRunState::Stopped(R::RequestBudget | R::Deadline | R::Interrupted)
            | RecoveryRunState::RetriesExhausted {
                last_reason: R::RequestBudget | R::Deadline | R::Interrupted
            }
    )
}

/// Binds a classic exposure using length-prefixed fields and big-endian integers.
///
/// # Errors
/// Returns `Invalid` for an unsupported exposure or an unrepresentable byte length.
pub fn recovery_exposure_digest(
    id: OperationId,
    index: u32,
    exposure: &ExposureIdentity,
) -> Result<String, WindowStoreError> {
    let ExposureIdentity::Classic {
        envelope_sha256,
        tx_hash,
        sequence,
        max_time,
        receipt,
    } = exposure
    else {
        return Err(WindowStoreError::Invalid {
            detail: "recovery_exposure_unsupported".into(),
        });
    };
    let mut hash = Sha256::new();
    hash.update(b"stellar-agent/recovery-exposure/v1\0");
    let operation_id = id.to_hex();
    let length = |len| {
        u32::try_from(len)
            .map(u32::to_be_bytes)
            .map_err(|_| WindowStoreError::Invalid {
                detail: "recovery_exposure_length".into(),
            })
    };
    hash.update(length(operation_id.len())?);
    hash.update(operation_id.as_bytes());
    hash.update(index.to_be_bytes());
    hash.update([0]);
    hash.update(envelope_sha256);
    hash.update(tx_hash);
    hash.update(sequence.to_be_bytes());
    hash.update(max_time.to_be_bytes());
    hash.update(length(receipt.len())?);
    hash.update(receipt.as_bytes());
    Ok(stellar_agent_core::hex::encode(&hash.finalize()))
}

fn valid_context(stop: &RecoveryStop, timed: bool, account: Option<&str>) -> bool {
    use RecoveryRunMethod as M;
    use RecoveryStage as S;
    use RecoveryStopReason as R;
    let paired = stop.roles == [RecoveryRole::Primary, RecoveryRole::Oracle];
    let shape = stop.roles.len() <= 1 || paired;
    let method = match stop.stage {
        S::Hash => stop.method == Some(M::GetTransaction),
        S::Target => stop.method == Some(M::GetLedgers) && timed,
        S::Account => {
            if stop.reason == R::RecordUnusable {
                stop.method.is_none() && stop.roles.is_empty()
            } else {
                stop.method == Some(M::GetLedgerEntries) && timed
            }
        }
        S::Lease => stop.method.is_none() && stop.roles.is_empty(),
        _ => false,
    };
    let reason = match stop.reason {
        R::AwaitingExpiry => stop.stage == S::Target && paired,
        R::Untimed => stop.stage == S::Hash && !timed && paired,
        R::AccountUnavailable | R::CoverageRequired => {
            stop.stage == S::Account && !stop.roles.is_empty()
        }
        R::HistoryLost => {
            stop.stage == S::Target && stop.ledger.is_some() && !stop.roles.is_empty()
        }
        R::MissingProvenance => stop.stage == S::Target && paired,
        R::RecordUnusable => {
            stop.stage == S::Account
                && account
                    .is_none_or(|a| !a.starts_with('G') || !super::operations::account_id_shaped(a))
        }
        R::ClockRegression | R::RequestBudget => stop.stage == S::Lease,
        R::Disagreement => paired && stop.stage != S::Lease,
        R::Deadline => true,
        R::MissingField | R::ResponseTooLarge | R::RateLimited | R::Transport | R::Lagging => {
            stop.stage != S::Lease && !stop.roles.is_empty()
        }
        R::Interrupted | R::ConfigurationRequired => false,
    };
    shape
        && method
        && reason
        && stop.ledger != Some(0)
        && stop.target != Some(0)
        && (timed || (stop.target.is_none() && stop.ledger.is_none()))
        && (!matches!(stop.stage, S::Target | S::Account)
            || stop.reason == R::RecordUnusable
            || stop.target.is_some())
}

fn stop_schedule(
    stop: &RecoveryStop,
    count: u8,
    max_time: u64,
) -> Result<Option<u64>, WindowStoreError> {
    if classify_recovery_stop(stop.reason, stop.stage) == RecoveryClass::Explicit {
        return Ok(None);
    }
    let retry = recovery_retry_time(stop.stopped_at_ms, count)?;
    Ok(Some(if stop.reason == RecoveryStopReason::AwaitingExpiry {
        retry.max(recovery_expiry(max_time).ok_or_else(overflow)?)
    } else {
        retry
    }))
}

fn legacy_coverage(run: &WireRecoveryRun, stop: &RecoveryStop) -> bool {
    run.version == 1
        && stop.reason == RecoveryStopReason::CoverageRequired
        && stop.class == RecoveryClass::Explicit
        && stop.earliest_retry_ms.is_none()
}

fn validate_run(
    run: &WireRecoveryRun,
    id: OperationId,
    index: u32,
    exposure: &ExposureIdentity,
    account: Option<&str>,
    decision: bool,
    attempt: &WireAttempt,
) -> bool {
    let ExposureIdentity::Classic { max_time, .. } = exposure else {
        return false;
    };
    let scan_valid = match (run.version, &run.scan) {
        (1, None) => true,
        (2, Some(scan)) => scan.valid(
            attempt.pre_exposure_ledger,
            attempt
                .sequence_released
                .as_ref()
                .filter(|r| r.primary_ledger == r.witness_ledger)
                .map(|r| r.primary_ledger),
            *max_time,
        ),
        _ => false,
    };
    if !scan_valid
        || !(1..=16).contains(&run.automatic_runs)
        || run.consecutive_stops > 16
        || recovery_exposure_digest(id, index, exposure).ok().as_ref() != Some(&run.exposure)
        || recovery_deadline(run.run_started_ms).ok() != Some(run.run_deadline_ms)
    {
        return false;
    }
    match (run.phase, &run.stop) {
        (RecoveryRunPhase::Running, None) => {
            run.consecutive_stops == run.automatic_runs - 1
                && recovery_retry_time(run.run_deadline_ms, run.consecutive_stops).is_ok()
        }
        (RecoveryRunPhase::Resolved, None) => decision && run.consecutive_stops == 0,
        (RecoveryRunPhase::Stopped, Some(stop)) => {
            run.consecutive_stops == run.automatic_runs
                && stop.stopped_at_ms >= run.run_started_ms
                && valid_context(stop, recovery_expiry(*max_time).is_some(), account)
                && (legacy_coverage(run, stop)
                    || (stop.class == classify_recovery_stop(stop.reason, stop.stage)
                        && stop_schedule(stop, run.consecutive_stops - 1, *max_time).ok()
                            == Some(stop.earliest_retry_ms)))
        }
        _ => false,
    }
}

/// A pure read result. Exhaustion retains its underlying cause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryRunState {
    /// No run is stored.
    RecoveryRequired,
    /// A live lease owns the attempt.
    Running,
    /// A contextual stop or ephemeral guard applies.
    Stopped(RecoveryStopReason),
    /// Sixteen reservations are spent.
    RetriesExhausted {
        /// The underlying stop, interruption or unusable metadata.
        last_reason: RecoveryStopReason,
    },
    /// A valid committed decision resolves the attempt.
    Resolved,
}

/// Normalized scheduling advice. It grants neither proof nor permission to write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryRunView {
    /// The normalized state and underlying reason.
    pub state: RecoveryRunState,
    /// Automatic or explicit advice, absent for a decision or live lease.
    pub class: Option<RecoveryClass>,
    /// The stable automatic eligibility time.
    pub earliest_retry_ms: Option<u64>,
    /// The effective stop count, including one expired or exhausted lease.
    pub effective_stops: u8,
}

/// Normalizes an authenticated snapshot into scheduling advice.
/// A valid committed decision takes precedence over run metadata.
#[must_use]
pub fn normalize_recovery_run(
    snapshot: Option<&RecoveryRunSnapshot>,
    max_time: u64,
    send_by_ms: u64,
    committed_decision: bool,
    now_ms: u64,
) -> RecoveryRunView {
    use RecoveryRunState as V;
    use RecoveryStopReason as R;
    let mut view = RecoveryRunView {
        state: V::Resolved,
        class: None,
        earliest_retry_ms: None,
        effective_stops: 0,
    };
    if committed_decision {
        return view;
    }
    let Some(snapshot) = snapshot else {
        view.state = V::RecoveryRequired;
        view.class = Some(RecoveryClass::Automatic);
        view.earliest_retry_ms = Some(recovery_expiry(max_time).unwrap_or(send_by_ms));
        return view;
    };
    let run = snapshot.run.as_ref();
    let underlying = run.map_or(R::RecordUnusable, |r| {
        r.stop.as_ref().map_or(R::Interrupted, |s| s.reason)
    });
    view.effective_stops = run.map_or(0, |r| r.consecutive_stops);
    if snapshot.spent == Some(16) {
        view.state = V::RetriesExhausted {
            last_reason: underlying,
        };
        view.class = Some(RecoveryClass::Explicit);
        view.effective_stops = 16;
        return view;
    }
    let Some(run) = run else {
        view.state = V::Stopped(R::RecordUnusable);
        view.class = Some(RecoveryClass::Explicit);
        return view;
    };
    let latest = run
        .stop
        .as_ref()
        .map_or(run.run_started_ms, |s| s.stopped_at_ms);
    let due = if let Some(stop) = &run.stop {
        view.state = V::Stopped(stop.reason);
        if legacy_coverage(run, stop) {
            view.class = Some(RecoveryClass::Automatic);
            recovery_retry_time(stop.stopped_at_ms, run.consecutive_stops - 1).ok()
        } else {
            view.class = Some(stop.class);
            stop.earliest_retry_ms
        }
    } else {
        view.state = V::Running;
        // validate_run guarantees a representable running retry time.
        let due = recovery_retry_time(run.run_deadline_ms, run.consecutive_stops).ok();
        if now_ms >= run.run_deadline_ms {
            view.state = V::Stopped(R::Interrupted);
            view.class = Some(RecoveryClass::Automatic);
            view.effective_stops += 1;
        }
        due
    };
    if now_ms < latest && view.class != Some(RecoveryClass::Explicit) {
        view.state = V::Stopped(R::ClockRegression);
        view.class = Some(RecoveryClass::Automatic);
        view.earliest_retry_ms = due.map(|due| due.max(latest));
    } else if view.class == Some(RecoveryClass::Automatic) {
        view.earliest_retry_ms = due;
    }
    view
}

#[cfg(test)]
mod tests;
