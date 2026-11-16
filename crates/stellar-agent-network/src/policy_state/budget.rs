//! A read-only budget projection of one verified window snapshot.
//!
//! [`BudgetProjection::for_profile`] reads the profile's window snapshot once,
//! under the shared window-state lock that also guards the policy pin, and
//! computes every figure from that one generation. It reads no network,
//! sweeps nothing, and writes no policy, budget, approval or audit state.
//!
//! The figures are recorded amounts. An authorization minted without native
//! amounts counts zero and is listed as an unreserved legacy obligation, and
//! an x402 authorization records a zero native debit. The projection carries
//! no live account balance, floor headroom, earlier-epoch total obligation,
//! unlisted allowance, or counter reconciliation time, because no stored fact
//! supplies them.

use stellar_agent_core::mainnet::verified_policy::VerifiedPolicy;
use stellar_agent_core::policy::pin::PinState;
use stellar_agent_core::policy::v1::criteria::descriptor::{BucketDescriptor, BucketKind};
use stellar_agent_core::policy::v1::verified::with_pin_without_creating;
use stellar_agent_core::policy::{DenyReason, PolicyError};
use stellar_agent_core::profile::schema::Profile;

use super::ledger::{AuthorizationState, WireAuthorization};
use super::operations::{
    self, Disposition, ExposureIdentity, OperationState, ReleaseBound, ReleaseClass, ReleaseRow,
    WindowObservation,
};
use super::store::{self, WireFile};
use super::{PersistedWindowStore, WindowStoreError};
use crate::mainnet::AuthorizationId;

/// The part of a bucket's figures one stored representation adds to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Share {
    /// A settled debit.
    Used,
    /// An outstanding hold, a pending or exposed debit, or a signed intent.
    Reserved,
}

/// The budget of one profile, projected from one verified window generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetProjection {
    /// The projected generation; zero when nothing is recorded yet.
    pub generation: u64,
    /// The rules the policy applies to the profile, in document order.
    pub rules: Vec<RuleBudget>,
    /// Every stored authorization, of every epoch and state.
    pub authorizations: Vec<AuthorizationView>,
    /// The native reservations at the stored observation.
    pub native: NativeTotal,
}

/// The limits of one rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleBudget {
    /// The rule's position in the signed document.
    pub index: usize,
    /// The per-call limits, which accumulate nothing.
    pub per_call: Vec<BucketDescriptor>,
    /// The accumulating limits with their figures.
    pub buckets: Vec<BucketProjection>,
}

/// One accumulating limit and its figures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BucketProjection {
    /// The limit as the signed policy states it.
    pub descriptor: BucketDescriptor,
    /// The figures, or why the stored state supplies none.
    pub usage: Result<BucketUsage, UsageUnavailable>,
}

/// The figures of one bucket, in stroops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BucketUsage {
    /// The settled debits the bucket counts.
    pub used: i128,
    /// The outstanding holds, pending and exposed debits, and signed intents.
    pub reserved: i128,
    /// `max(0, cap - used - reserved)`.
    pub remaining: i128,
}

/// Why a bucket has no figures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UsageUnavailable {
    /// The unlisted bucket's stored history neither joins every spelling of
    /// its asset nor separates approved excess, so its sums do not state the
    /// unattended allowance.
    UnlistedAccounting,
    /// An earlier build wrote the history, or the policy's epoch is retired:
    /// the state holds no trustworthy total for the epoch.
    TotalEpochRetired,
}

/// One stored authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationView {
    /// The authorization's identity.
    pub id: AuthorizationId,
    /// The stored state.
    pub state: AuthorizationState,
    /// The stored disposition, never derived from the state.
    pub disposition: Option<Disposition>,
    /// The native obligation; `None` for an authorization minted without
    /// native amounts.
    pub native_obligation: Option<NativeObligation>,
}

/// The native reservation of one authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeObligation {
    /// Whether the reservation counts, or why the stored observation cannot
    /// decide.
    pub counted: Result<bool, Undecided>,
    /// The evidence class.
    pub class: NativeClass,
    /// The informational release bound. A bound alone releases nothing.
    pub release_bound: Option<InformationalBound>,
}

/// Why the stored observation cannot decide a count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Undecided {
    /// No observation is stored.
    NoObservation,
    /// The stored observation lies below an admissible floor.
    ObservationBelowFloor,
}

/// The evidence class of a native reservation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NativeClass {
    /// No other class applies yet; the reservation is live.
    Live,
    /// Nothing was spent.
    ProvedUnspent,
    /// The spend settled.
    Settled,
    /// The outcome is unknown.
    Unknown,
    /// Retired unused for a remint.
    RetiredUnused,
}

/// An informational release bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InformationalBound {
    /// The ledger from which the reservation may release.
    Ledger(u32),
    /// The close time, in Unix milliseconds, from which the reservation may
    /// release.
    AfterMs(u64),
}

/// The native reservations of the window at its stored observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeTotal {
    /// The counted debit plus fee, once per authorization, or why the stored
    /// observation cannot decide.
    pub counted: Result<i128, Undecided>,
    /// The stored observation.
    pub observation: Option<WindowObservation>,
    /// The age of the stored observation at the projection's clock.
    pub observation_age_ms: Option<u64>,
    /// The authorizations minted without native amounts whose release is
    /// not proved by the stored observation or an `Always` row. Each counts zero.
    pub unreserved_legacy: Vec<AuthorizationId>,
}

/// Why the committed window state is unavailable to a projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SnapshotUnavailable {
    /// The file is missing under a committed generation.
    FileMissing,
    /// The file exists under a committed generation and cannot be read.
    Unreadable,
    /// The generation counter cannot be read.
    GenerationUnreadable,
}

/// Why a budget projection has no answer.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BudgetError {
    /// The policy pin or its lock cannot be read.
    #[error("{0}")]
    Policy(PolicyError),
    /// The committed window state is unavailable.
    #[error("the committed window state is unavailable: {reason:?} at generation {generation:?}")]
    Unavailable {
        /// The committed generation, when the counter is readable.
        generation: Option<u64>,
        /// What is unavailable.
        reason: SnapshotUnavailable,
    },
    /// The window state refuses verification, names another policy, or
    /// holds a figure that overflows.
    #[error("{0}")]
    State(WindowStoreError),
    /// A stored time lies beyond the projection's clock.
    #[error("{detail}")]
    Clock {
        /// The stored time and the clock.
        detail: String,
    },
}

impl BudgetError {
    /// The stable code: the pin and lock codes,
    /// `policy.window_state_unverifiable` for unavailable state, the store's
    /// inspection codes, and `wallet.clock_error`.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Policy(error) => error.wire_code(),
            Self::Unavailable { .. } => "policy.window_state_unverifiable",
            Self::State(error) => store::inspection_code(error),
            Self::Clock { .. } => "wallet.clock_error",
        }
    }
}

impl BudgetProjection {
    /// Projects `profile`'s budget under `policy` at `now_ms`.
    ///
    /// The shared window-state lock is held across the pin comparison and
    /// the one snapshot read, so no writer commits between them, and is
    /// released before this returns. A verified absence projects generation
    /// zero with zero figures.
    ///
    /// It writes no policy, budget, approval or audit state. It uses the
    /// ordinary credential reads used by admission and compare-only policy
    /// inspection. The headless keyring backend rebinds an entry sealed before
    /// coordinate binding on its first read, as on every wallet read.
    ///
    /// # Errors
    ///
    /// [`BudgetError::Policy`] for an unreadable pin or lock, or state that
    /// cannot be proved fresh without a pin under the shared lock;
    /// [`BudgetError::State`] with [`WindowStoreError::TotalEpochStale`] when
    /// the pin names another policy, and for every verification failure and
    /// overflowing figure; [`BudgetError::Unavailable`] for a missing or
    /// unreadable committed file or counter; [`BudgetError::Clock`] for a
    /// stored observation or debit dated beyond `now_ms`.
    pub fn for_profile(
        profile_name: &str,
        profile: &Profile,
        store: &PersistedWindowStore,
        policy: &VerifiedPolicy,
        now_ms: u64,
    ) -> Result<Self, BudgetError> {
        let snapshot = with_pin_without_creating(store.path(), profile, |pin| match pin {
            PinState::Present(pin) if pin.digest() != policy.digest() => {
                Err(BudgetError::State(WindowStoreError::TotalEpochStale))
            }
            PinState::Present(_) => store.snapshot_for_projection(profile),
            PinState::Absent => match store.snapshot_for_projection(profile) {
                Ok(None) => Ok(None),
                _ => Err(BudgetError::Policy(PolicyError::PinAbsent)),
            },
        })
        .map_err(BudgetError::Policy)??;
        let empty = WireFile::default();
        let wire = snapshot.as_ref().unwrap_or(&empty);
        let rules = policy
            .engine()
            .effective_rules()
            .into_iter()
            .enumerate()
            .map(|(index, rule)| {
                rule_budget(
                    wire,
                    profile_name,
                    policy.digest(),
                    now_ms,
                    index,
                    rule.descriptors(),
                )
            })
            .collect::<Result<_, _>>()?;
        let (authorizations, native) = native(wire, now_ms)?;
        Ok(Self {
            generation: wire.generation,
            rules,
            authorizations,
            native,
        })
    }
}

fn overflow() -> BudgetError {
    BudgetError::State(WindowStoreError::Invalid {
        detail: "a budget figure overflows".to_owned(),
    })
}

/// The used and reserved sums of one bucket; `None` once a sum overflows.
struct Tally {
    used: Option<i128>,
    reserved: Option<i128>,
}

impl Tally {
    const ZERO: Self = Self {
        used: Some(0),
        reserved: Some(0),
    };

    fn add(&mut self, share: Share, amount: i128) {
        let sum = match share {
            Share::Used => &mut self.used,
            Share::Reserved => &mut self.reserved,
        };
        *sum = sum.and_then(|sum| sum.checked_add(amount));
    }

    fn usage(self, cap: i128) -> Result<BucketUsage, BudgetError> {
        let (Some(used), Some(reserved)) = (self.used, self.reserved) else {
            return Err(overflow());
        };
        used.checked_add(reserved).ok_or_else(|| {
            BudgetError::State(WindowStoreError::Invalid {
                detail: "a total-budget sum overflows".to_owned(),
            })
        })?;
        let left = cap
            .checked_sub(used)
            .and_then(|left| left.checked_sub(reserved))
            .ok_or_else(overflow)?;
        Ok(BucketUsage {
            used,
            reserved,
            remaining: left.max(0),
        })
    }
}

/// The limits of one rule with their figures. A total counts its epoch's
/// representations whatever their age; every other accumulating limit
/// counts what is live in its window at `now_ms`.
fn rule_budget(
    wire: &WireFile,
    profile_name: &str,
    epoch: [u8; 32],
    now_ms: u64,
    index: usize,
    descriptors: Vec<BucketDescriptor>,
) -> Result<RuleBudget, BudgetError> {
    let mut per_call = Vec::new();
    let mut buckets = Vec::new();
    for descriptor in descriptors {
        let Some(key) = descriptor.state_key(profile_name) else {
            per_call.push(descriptor);
            continue;
        };
        let mut tally = Tally::ZERO;
        let usage = match descriptor.kind {
            BucketKind::UnlistedPeriod => Err(UsageUnavailable::UnlistedAccounting),
            BucketKind::Total
                if store::earlier_build(wire) || wire.retired_total_epoch == Some(epoch) =>
            {
                Err(UsageUnavailable::TotalEpochRetired)
            }
            BucketKind::Total => {
                store::total_shares(wire, &key, epoch, |share, amount| {
                    tally.add(share, amount);
                    Ok(())
                })
                .map_err(BudgetError::State)?;
                Ok(tally.usage(descriptor.cap_stroops)?)
            }
            _ => {
                store::window_shares(wire, &key, now_ms, |share, amount, _| {
                    tally.add(share, amount);
                })
                .map_err(|error| match error {
                    WindowStoreError::PolicyDenied { reason } => BudgetError::Clock {
                        detail: match *reason {
                            DenyReason::EvaluationError { detail } => detail,
                            other => other.code().to_owned(),
                        },
                    },
                    other => BudgetError::State(other),
                })?;
                Ok(tally.usage(descriptor.cap_stroops)?)
            }
        };
        buckets.push(BucketProjection { descriptor, usage });
    }
    Ok(RuleBudget {
        index,
        per_call,
        buckets,
    })
}

/// Every authorization's view and the native total at the stored
/// observation.
fn native(
    wire: &WireFile,
    now_ms: u64,
) -> Result<(Vec<AuthorizationView>, NativeTotal), BudgetError> {
    let seen = admissible_observation(wire);
    let observation_age_ms = wire
        .last_observation
        .map(|seen| {
            now_ms
                .checked_sub(seen.observed_at_ms)
                .ok_or_else(|| BudgetError::Clock {
                    detail: format!(
                        "the stored observation at {} ms is later than the clock at {now_ms} ms",
                        seen.observed_at_ms
                    ),
                })
        })
        .transpose()?;
    let mut counted = seen.map(|_| 0_i128);
    let mut unreserved_legacy = Vec::new();
    let mut views = Vec::with_capacity(wire.authorizations.len());
    for auth in &wire.authorizations {
        let native_obligation = match auth.native_reservation {
            Some(amounts) => {
                let obligation = NativeObligation {
                    counted: reservation_counts(auth.native_release.as_ref(), seen),
                    class: class_of(wire, auth),
                    release_bound: release_bound(wire, auth)?,
                };
                if obligation.counted == Ok(true)
                    && let Ok(sum) = &mut counted
                {
                    *sum = sum
                        .checked_add(amounts.total_stroops())
                        .ok_or_else(overflow)?;
                }
                Some(obligation)
            }
            None => {
                if reservation_counts(auth.native_release.as_ref(), seen) != Ok(false) {
                    unreserved_legacy.push(auth.id);
                }
                None
            }
        };
        views.push(AuthorizationView {
            id: auth.id,
            state: auth.state,
            disposition: auth.disposition,
            native_obligation,
        });
    }
    let native = NativeTotal {
        counted,
        observation: wire.last_observation,
        observation_age_ms,
        unreserved_legacy,
    };
    Ok((views, native))
}

/// The stored observation when it lies at or above both admissible floors.
fn admissible_observation(wire: &WireFile) -> Result<&WindowObservation, Undecided> {
    let seen = wire
        .last_observation
        .as_ref()
        .ok_or(Undecided::NoObservation)?;
    let below = wire
        .admissible_floor_ledger
        .is_some_and(|floor| seen.ledger < floor)
        || wire
            .admissible_floor_close_time_ms
            .is_some_and(|floor| seen.close_time_floor_ms < floor);
    if below {
        Err(Undecided::ObservationBelowFloor)
    } else {
        Ok(seen)
    }
}

/// Whether a reservation with release row `row` counts. An `Always` row
/// releases whatever the observation. Every other count needs the
/// admissible observation `seen`: a bounded row releases as
/// [`operations::row_releases`] states, and without a row the reservation
/// counts.
fn reservation_counts(
    row: Option<&ReleaseRow>,
    seen: Result<&WindowObservation, Undecided>,
) -> Result<bool, Undecided> {
    if row.is_some_and(|row| row.bound == ReleaseBound::Always) {
        return Ok(false);
    }
    let seen = seen?;
    Ok(!row.is_some_and(|row| operations::row_releases(row, Some(seen))))
}

/// The class of `auth`'s reservation: its release row's class, or else the
/// class its operation's evidence names. A settled operation is settled; a
/// released x402 payload, a cancelled operation, and an operation that
/// expired after exposing this authorization have an unknown outcome.
fn class_of(wire: &WireFile, auth: &WireAuthorization) -> NativeClass {
    if let Some(row) = auth.native_release {
        return match row.class {
            ReleaseClass::ProvedUnspent => NativeClass::ProvedUnspent,
            ReleaseClass::Settled => NativeClass::Settled,
            ReleaseClass::Unknown => NativeClass::Unknown,
            ReleaseClass::RetiredUnused => NativeClass::RetiredUnused,
        };
    }
    let Some(record) = auth.operation.as_ref().and_then(|link| {
        operations::records(wire)
            .iter()
            .find(|record| record.id == link.operation_id)
    }) else {
        return NativeClass::Live;
    };
    let exposed = record
        .attempts
        .iter()
        .any(|attempt| attempt.authorization_id == auth.id && attempt.exposure.is_some());
    match record.state {
        OperationState::Succeeded | OperationState::Failed => NativeClass::Settled,
        OperationState::PayloadReleased | OperationState::Cancelled => NativeClass::Unknown,
        OperationState::Expired if exposed => NativeClass::Unknown,
        _ => NativeClass::Live,
    }
}

/// The informational bound of `auth`'s reservation: its release row's
/// bound, or else the last exposure of an attempt under it. An x402
/// exposure is bounded by its signature expiration ledger, a timed classic
/// one by its `max_time` in milliseconds; `Always` and an untimed exposure
/// have none.
fn release_bound(
    wire: &WireFile,
    auth: &WireAuthorization,
) -> Result<Option<InformationalBound>, BudgetError> {
    match auth.native_release.map(|row| row.bound) {
        Some(ReleaseBound::Ledger(ledger)) => return Ok(Some(InformationalBound::Ledger(ledger))),
        Some(ReleaseBound::CloseTime(ms)) => return Ok(Some(InformationalBound::AfterMs(ms))),
        Some(ReleaseBound::Always) => return Ok(None),
        None => {}
    }
    let exposure = operations::records(wire)
        .iter()
        .flat_map(|record| &record.attempts)
        .rev()
        .filter(|attempt| attempt.authorization_id == auth.id)
        .find_map(|attempt| attempt.exposure.as_ref());
    match exposure.map(|exposure| &exposure.identity) {
        Some(ExposureIdentity::X402 {
            signature_expiration_ledger,
            ..
        }) => Ok(Some(InformationalBound::Ledger(
            *signature_expiration_ledger,
        ))),
        Some(ExposureIdentity::Classic { max_time, .. }) if *max_time > 0 => max_time
            .checked_mul(1000)
            .map(|ms| Some(InformationalBound::AfterMs(ms)))
            .ok_or_else(overflow),
        _ => Ok(None),
    }
}
