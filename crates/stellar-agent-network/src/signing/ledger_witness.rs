//! Independent ledger observations with checked endpoint and clock provenance.
//!
//! At least one independently operated stored endpoint must report the chain honestly.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use stellar_agent_core::error::{NetworkError, WalletError};
use stellar_agent_core::profile::caip2::Caip2;
use stellar_agent_core::profile::loader::OnDiskRpcEndpoints;
use stellar_agent_core::profile::schema::{check_endpoint_url, same_provider_host};
use tokio::time::Instant;
use tracing::debug;

use crate::policy_state::ChainScope;
use crate::{PreparedSigningLedgerRead, SigningLedgerObservation, StellarRpcClient};

/// The largest accepted difference between endpoint ledger heights.
pub const MAX_SIGNING_LEDGER_SKEW: u32 = 2;
/// The longest age of either endpoint observation.
pub const MAX_OBSERVATION_AGE: Duration = Duration::from_secs(10);
/// The authorization lifetime beyond the lower witnessed ledger.
pub const AUTH_VALIDITY_LEDGERS: u32 = 100;

/// Whether a ledger lies within the operational signing range.
#[must_use]
pub const fn operational_ledger(ledger: u32) -> bool {
    ledger > 0 && ledger <= u32::MAX - AUTH_VALIDITY_LEDGERS - 1_000_000
}

/// A fixed, credential safe witness refusal.
#[derive(Clone, Copy, Debug, thiserror::Error)]
pub enum LedgerWitnessError {
    /// The observations cannot be acquired or used before their deadline.
    #[error("{reason}")]
    Unavailable {
        /// The fixed refusal reason.
        reason: &'static str,
    },
    /// The observations contradict the required witness facts.
    #[error("{reason}")]
    Mismatch {
        /// The fixed refusal reason.
        reason: &'static str,
    },
    /// A signing endpoint reports mainnet.
    #[error("mainnet signing is unavailable")]
    MainnetWriteForbidden,
}

fn unavailable(reason: &'static str) -> LedgerWitnessError {
    LedgerWitnessError::Unavailable { reason }
}
fn mismatch(reason: &'static str) -> LedgerWitnessError {
    LedgerWitnessError::Mismatch { reason }
}

/// Checks usable endpoint URLs on independent hosts.
///
/// # Errors
/// Refuses absent, malformed, or colocated endpoints without exposing URLs.
pub fn checked_secondary_rpc_url<'a>(
    primary: &str,
    secondary: Option<&'a str>,
    passphrase: &str,
) -> Result<&'a str, LedgerWitnessError> {
    let secondary =
        secondary.ok_or_else(|| unavailable("no secondary RPC endpoint is configured"))?;
    let chain = Caip2::from_passphrase(passphrase).unwrap_or(Caip2::Testnet);
    for (field, value, reason) in [
        (
            "rpc_url",
            primary,
            "the primary RPC URL is not a usable endpoint URL",
        ),
        (
            "secondary_rpc_url",
            secondary,
            "the secondary RPC URL is not a usable endpoint URL",
        ),
    ] {
        if !check_endpoint_url(field, value, chain).is_ok_and(|url| url.host_str().is_some()) {
            return Err(unavailable(reason));
        }
    }
    if same_provider_host(primary, secondary) {
        return Err(unavailable(
            "no secondary RPC endpoint on a host other than the primary's is configured",
        ));
    }
    Ok(secondary)
}

/// The most height pairs one witness call reads under its deadline.
const MAX_PAIR_ACQUISITIONS: u32 = 3;

/// The fixed reason of a refusal: `LedgerWitnessError::Unavailable` or
/// `LedgerWitnessError::Mismatch` never echoes endpoint input, which can hold a
/// credential.
mod reason {
    pub(super) const SKEW: &str = "the endpoints' latest ledgers differ by more than the tolerance";
    pub(super) const STALE: &str = "the ledger observations are stale";
    pub(super) const DEADLINE_ELAPSED: &str = "the pre-submit deadline elapsed";
}

/// One endpoint's height, reduced to what the bound keeps of it.
#[derive(Debug, Clone)]
struct ObservedLedger {
    ledger: u32,
    authority: String,
    observed_at: Instant,
}

impl From<SigningLedgerObservation> for ObservedLedger {
    fn from(observation: SigningLedgerObservation) -> Self {
        Self {
            ledger: observation.ledger(),
            authority: observation.identity().authority().to_owned(),
            observed_at: observation.observed_at(),
        }
    }
}

/// Why a pair of observations was not bound.
#[derive(Debug)]
enum PairRefusal {
    /// The heights differ by more than [`MAX_SIGNING_LEDGER_SKEW`]; a later
    /// pair can agree.
    Skew {
        primary: ObservedLedger,
        secondary: ObservedLedger,
    },
    /// A refusal no later pair changes.
    Terminal(LedgerWitnessError),
}

impl PairRefusal {
    /// The refusal a caller receives for this pair: the skew mismatch for a
    /// skewed pair, and the terminal refusal itself otherwise.
    fn into_error(self) -> LedgerWitnessError {
        match self {
            Self::Skew { .. } => mismatch(reason::SKEW),
            Self::Terminal(error) => error,
        }
    }
}

/// What made the acquisition loop discard a pair.
#[derive(Debug, Clone, Copy)]
enum Trigger {
    /// The older observation of an otherwise valid pair passed
    /// [`MAX_OBSERVATION_AGE`].
    Stale,
    /// The heights differ by more than [`MAX_SIGNING_LEDGER_SKEW`].
    Skew,
}

impl Trigger {
    fn as_str(self) -> &'static str {
        match self {
            Self::Stale => "stale",
            Self::Skew => "skew",
        }
    }
}

/// A pair the acquisition loop discarded, kept for its refusal and for the
/// event that announces the next pair.
struct RejectedPair {
    trigger: Trigger,
    primary: ObservedLedger,
    secondary: ObservedLedger,
}

impl RejectedPair {
    /// The refusal the pair receives when no further pair is read: the skew
    /// refusal for a skewed pair and the stale refusal for a stale one.
    fn into_refusal(self) -> LedgerWitnessError {
        match self.trigger {
            Trigger::Skew => PairRefusal::Skew {
                primary: self.primary,
                secondary: self.secondary,
            }
            .into_error(),
            Trigger::Stale => unavailable(reason::STALE),
        }
    }
}

/// A pair acquired through checked clients under one deadline.
///
/// Production construction always reads both endpoints. Heights alone carry no authority.
#[derive(Clone)]
pub struct LedgerWitnessCapability {
    scope: ChainScope,
    primary: SigningLedgerObservation,
    secondary: SigningLedgerObservation,
    clients: [Arc<StellarRpcClient>; 2],
    deadline: Instant,
    schedule_evidence: Vec<ScheduleStateEvidence>,
}

impl std::fmt::Debug for LedgerWitnessCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LedgerWitnessCapability")
            .field("scope", &self.scope)
            .field("lower", &self.lower())
            .field("upper", &self.upper())
            .finish_non_exhaustive()
    }
}

impl LedgerWitnessCapability {
    /// Checks both identities before reading either height, then reads both heights concurrently.
    ///
    /// Each identity is checked once. A stale or skewed pair permits at most two
    /// rereads within the same deadline. Each pair carries its own arrival times.
    ///
    /// # Errors
    /// Refuses unavailable identities, invalid heights, skew, stale answers, or an elapsed deadline.
    pub async fn acquire(
        primary: &StellarRpcClient,
        secondary: &StellarRpcClient,
        passphrase: &str,
        deadline: Instant,
    ) -> Result<Self, LedgerWitnessError> {
        checked_secondary_rpc_url(primary.url(), Some(secondary.url()), passphrase)?;
        let scope = ChainScope::from_passphrase(passphrase)
            .map_err(|_| mismatch("the endpoints identify different chains"))?;
        let clients = [
            Arc::new(primary.share_for_witness()),
            Arc::new(secondary.share_for_witness()),
        ];
        let (primary_prepared, secondary_prepared) = tokio::join!(
            clients[0].prepare_signing_ledger_observation(passphrase, deadline),
            clients[1].prepare_signing_ledger_observation(passphrase, deadline),
        );
        let primary = primary_prepared.map_err(|error| observation_refusal(&error, true))?;
        let secondary = secondary_prepared.map_err(|error| observation_refusal(&error, false))?;
        let bound = acquire_fresh_pair(deadline, || {
            read_pair(&primary, &secondary, scope, &clients, deadline)
        })
        .await?;
        debug!(
            primary_ledger = bound.primary.ledger(),
            secondary_ledger = bound.secondary.ledger(),
            primary = %bound.primary.identity().authority(),
            secondary = %bound.secondary.identity().authority(),
            chain = bound.scope.chain().caip2_str(),
            "ledger witness accepted",
        );
        Ok(bound)
    }

    /// Constructs controlled observations for tests.
    ///
    /// # Errors
    /// Refuses invalid endpoint URLs, heights, or pair identities.
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn for_test(
        scope: ChainScope,
        endpoints: [&str; 2],
        heights: [u32; 2],
        instants: [Instant; 2],
        arrivals_ms: [u64; 2],
        deadline: Instant,
    ) -> Result<Self, LedgerWitnessError> {
        let clients = [
            Arc::new(
                StellarRpcClient::new(endpoints[0])
                    .map_err(|_| unavailable("the primary RPC client could not be built"))?,
            ),
            Arc::new(
                StellarRpcClient::new(endpoints[1])
                    .map_err(|_| unavailable("the secondary RPC client could not be built"))?,
            ),
        ];
        let observation = |index: usize| {
            SigningLedgerObservation::checked(
                crate::EndpointIdentity::checked(
                    Some(scope.chain()),
                    23,
                    stellar_agent_core::redact::redact_url_authority(endpoints[index]),
                    clients[index].id(),
                ),
                heights[index],
                instants[index],
                arrivals_ms[index],
            )
        };
        let pair = Self {
            scope,
            primary: observation(0),
            secondary: observation(1),
            clients,
            deadline,
            schedule_evidence: Vec::new(),
        };
        pair.validate_pair()?;
        Ok(pair)
    }

    fn validate_non_skew(&self) -> Result<(), LedgerWitnessError> {
        if !operational_ledger(self.lower()) || !operational_ledger(self.upper()) {
            return Err(mismatch("a reported ledger height is out of bounds"));
        }
        if self.primary.identity().chain_id() != Some(self.scope.chain())
            || self.secondary.identity().chain_id() != Some(self.scope.chain())
        {
            return Err(mismatch("the endpoints identify different chains"));
        }
        checked_secondary_rpc_url(
            self.clients[0].url(),
            Some(self.clients[1].url()),
            self.scope.chain().network_passphrase(),
        )?;
        Ok(())
    }

    fn validate_pair(&self) -> Result<(), LedgerWitnessError> {
        self.validate_non_skew()?;
        if self.upper() - self.lower() > MAX_SIGNING_LEDGER_SKEW {
            return Err(mismatch(reason::SKEW));
        }
        Ok(())
    }

    /// Classifies only skew as a refusal that another pair can change.
    fn bind_classified(self) -> Result<Self, PairRefusal> {
        self.validate_non_skew().map_err(PairRefusal::Terminal)?;
        if self.upper() - self.lower() > MAX_SIGNING_LEDGER_SKEW {
            return Err(PairRefusal::Skew {
                primary: self.primary.into(),
                secondary: self.secondary.into(),
            });
        }
        Ok(self)
    }

    /// The lower observed ledger, which bounds closure authority.
    #[must_use]
    pub fn lower(&self) -> u32 {
        self.primary.ledger().min(self.secondary.ledger())
    }
    /// The higher observed ledger.
    #[must_use]
    pub fn upper(&self) -> u32 {
        self.primary.ledger().max(self.secondary.ledger())
    }
    /// The authenticated canonical chain scope.
    #[must_use]
    pub fn scope(&self) -> ChainScope {
        self.scope
    }
    /// The later endpoint arrival on the store clock.
    #[must_use]
    pub fn arrived_at_ms(&self) -> u64 {
        self.primary
            .arrived_at_ms()
            .max(self.secondary.arrived_at_ms())
    }
    /// The older observation instant, which bounds freshness.
    #[must_use]
    pub fn oldest_observation(&self) -> Instant {
        self.primary.observed_at().min(self.secondary.observed_at())
    }
    /// Whether either observation is stale or lies in the monotonic future.
    #[must_use]
    pub fn is_stale(&self, now: Instant) -> bool {
        [&self.primary, &self.secondary].iter().any(|observation| {
            now.checked_duration_since(observation.observed_at())
                .is_none_or(|age| age > MAX_OBSERVATION_AGE)
        })
    }
    /// Requires fresh observations within the acquisition deadline.
    ///
    /// # Errors
    /// Refuses stale observations or an elapsed deadline.
    pub fn ensure_fresh(&self, now: Instant) -> Result<(), LedgerWitnessError> {
        if now >= self.deadline {
            return Err(unavailable(reason::DEADLINE_ELAPSED));
        }
        if self.is_stale(now) {
            return Err(unavailable(reason::STALE));
        }
        Ok(())
    }
    /// Checks exact stored endpoint provenance and local clock ordering.
    #[must_use]
    pub fn authorizes(
        &self,
        endpoints: &OnDiskRpcEndpoints,
        scope: ChainScope,
        now_ms: u64,
    ) -> bool {
        self.scope == scope
            && endpoints.chain_id == scope.chain()
            && endpoints.rpc_url == self.clients[0].url()
            && endpoints.secondary_rpc_url.as_deref() == Some(self.clients[1].url())
            && self.validate_pair().is_ok()
            && self.ensure_fresh(Instant::now()).is_ok()
            && self.arrived_at_ms() <= now_ms
    }
}

/// Runs `acquire` until it returns a fresh pair, at most
/// [`MAX_PAIR_ACQUISITIONS`] times, and only while `deadline` has
/// not passed.
///
/// A stale or skewed pair permits another acquisition; every other refusal
/// returns at once. When the count or the deadline stops the loop after a
/// rejected pair, that pair's own refusal returns: the skew mismatch or the
/// stale unavailable refusal. The deadline is checked only before an
/// acquisition starts; a fresh pair that arrives is accepted.
async fn acquire_fresh_pair<F, Fut>(
    deadline: Instant,
    mut acquire: F,
) -> Result<LedgerWitnessCapability, LedgerWitnessError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<LedgerWitnessCapability, PairRefusal>>,
{
    let mut rejected: Option<RejectedPair> = None;
    for attempt in 1..=MAX_PAIR_ACQUISITIONS {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        if let Some(previous) = &rejected {
            debug!(
                attempt,
                trigger = previous.trigger.as_str(),
                primary_ledger = previous.primary.ledger,
                secondary_ledger = previous.secondary.ledger,
                primary_age_ms = millis_between(previous.primary.observed_at, now),
                secondary_age_ms = millis_between(previous.secondary.observed_at, now),
                remaining_ms = millis_between(now, deadline),
                primary = %previous.primary.authority,
                secondary = %previous.secondary.authority,
                "ledger witness reads the pair again",
            );
        }
        let pair = match acquire().await {
            Ok(bound) if !bound.is_stale(Instant::now()) => return Ok(bound),
            Ok(bound) => RejectedPair {
                trigger: Trigger::Stale,
                primary: bound.primary.into(),
                secondary: bound.secondary.into(),
            },
            Err(PairRefusal::Skew { primary, secondary }) => RejectedPair {
                trigger: Trigger::Skew,
                primary,
                secondary,
            },
            Err(PairRefusal::Terminal(error)) => return Err(error),
        };
        rejected = Some(pair);
    }
    Err(rejected.map_or_else(
        || unavailable(reason::DEADLINE_ELAPSED),
        RejectedPair::into_refusal,
    ))
}

/// Milliseconds from `earlier` to `later`, zero when `later` is not after it.
fn millis_between(earlier: Instant, later: Instant) -> u64 {
    u64::try_from(later.saturating_duration_since(earlier).as_millis()).unwrap_or(u64::MAX)
}

/// Reads both heights through the prepared clients and binds their provenance.
async fn read_pair(
    primary: &PreparedSigningLedgerRead<'_>,
    secondary: &PreparedSigningLedgerRead<'_>,
    scope: ChainScope,
    clients: &[Arc<StellarRpcClient>; 2],
    deadline: Instant,
) -> Result<LedgerWitnessCapability, PairRefusal> {
    let (primary, secondary) = tokio::join!(primary.read(), secondary.read());
    LedgerWitnessCapability {
        scope,
        primary: primary
            .map_err(|error| PairRefusal::Terminal(observation_refusal(&error, true)))?,
        secondary: secondary
            .map_err(|error| PairRefusal::Terminal(observation_refusal(&error, false)))?,
        clients: clients.clone(),
        deadline,
        schedule_evidence: Vec::new(),
    }
    .bind_classified()
}

fn observation_refusal(error: &WalletError, primary: bool) -> LedgerWitnessError {
    match error {
        WalletError::Network(NetworkError::MainnetWriteForbidden) => {
            LedgerWitnessError::MainnetWriteForbidden
        }
        WalletError::Network(NetworkError::EndpointNetworkMismatch { .. }) => {
            unavailable(if primary {
                "the primary RPC endpoint serves another network"
            } else {
                "the secondary RPC endpoint serves another network"
            })
        }
        _ => unavailable(if primary {
            "the primary RPC endpoint gave no ledger observation"
        } else {
            "the secondary RPC endpoint gave no ledger observation"
        }),
    }
}

/// The maximum number of schedules one observation probes.
pub const MAX_SCHEDULE_PROBES: usize = 8;

/// The authenticated identity of an open schedule selected for observation.
#[derive(Clone, Debug)]
pub(crate) struct ScheduleProbe {
    pub(crate) intent_id: String,
    pub(crate) timelock: String,
    pub(crate) operation_id: [u8; 32],
    pub(crate) expiration: u32,
    pub(crate) admitted_at_ms: u64,
}

#[derive(Clone)]
struct StateAnswer {
    value: u32,
    ledger: u32,
    arrived_at_ms: u64,
    observed_at: Instant,
}

#[derive(Clone)]
struct ScheduleStateEvidence {
    probe: ScheduleProbe,
    answers: [StateAnswer; 2],
}

pub(crate) fn select_schedule_probes(
    scope: &str,
    mut probes: Vec<ScheduleProbe>,
) -> Vec<ScheduleProbe> {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    static CURSORS: OnceLock<Mutex<HashMap<String, usize>>> = OnceLock::new();
    if probes.is_empty() {
        return probes;
    }
    probes.sort_by(|a, b| (a.admitted_at_ms, &a.intent_id).cmp(&(b.admitted_at_ms, &b.intent_id)));
    let mut cursors = CURSORS
        .get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let cursor = cursors.entry(scope.into()).or_default();
    let start = *cursor % probes.len();
    *cursor = (start + MAX_SCHEDULE_PROBES.min(probes.len())) % probes.len();
    probes.rotate_left(start);
    probes.truncate(MAX_SCHEDULE_PROBES);
    probes
}

/// Builds the unsigned operation state request used by both witnesses.
///
/// # Errors
/// Refuses malformed timelock identities or an unencodable request.
pub(crate) fn operation_state_envelope(
    timelock: &str,
    operation_id: &[u8; 32],
    passphrase: &str,
) -> Result<stellar_xdr::TransactionEnvelope, LedgerWitnessError> {
    use stellar_baselib::account::AccountBehavior as _;
    use stellar_baselib::transaction::TransactionBehavior as _;
    use stellar_baselib::transaction_builder::TransactionBuilderBehavior as _;
    use stellar_xdr::*;
    let invalid = || mismatch("the operation state request is invalid");
    let contract = stellar_strkey::Contract::from_string(timelock).map_err(|_| invalid())?;
    if contract.to_string().as_str() != timelock {
        return Err(invalid());
    }
    let host_function = HostFunction::InvokeContract(InvokeContractArgs {
        contract_address: ScAddress::Contract(ContractId(Hash(contract.0))),
        function_name: ScSymbol::try_from("get_operation_ledger").map_err(|_| invalid())?,
        args: vec![ScVal::Bytes(ScBytes(
            operation_id.to_vec().try_into().map_err(|_| invalid())?,
        ))]
        .try_into()
        .map_err(|_| invalid())?,
    });
    let source = stellar_strkey::ed25519::PublicKey([0; 32]).to_string();
    let mut account =
        stellar_baselib::account::Account::new(source.as_str(), "0").map_err(|_| invalid())?;
    let mut builder = stellar_baselib::transaction_builder::TransactionBuilder::new(
        &mut account,
        passphrase,
        None,
    );
    builder.fee(100_u32);
    builder.add_operation(Operation {
        source_account: None,
        body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
            host_function,
            auth: Default::default(),
        }),
    });
    builder
        .build_for_simulation()
        .to_envelope()
        .map_err(|_| invalid())
}

async fn read_state(
    client: &StellarRpcClient,
    envelope: &stellar_xdr::TransactionEnvelope,
    deadline: Instant,
) -> Result<StateAnswer, LedgerWitnessError> {
    let response =
        tokio::time::timeout_at(deadline, client.simulate_transaction_envelope(envelope))
            .await
            .map_err(|_| unavailable("the operation state deadline elapses"))?
            .map_err(|_| unavailable("the operation state answer is unavailable"))?;
    let observed_at = Instant::now();
    let arrived_at_ms = crate::mainnet::clock::now_ms()
        .map_err(|_| unavailable("the local clock is unavailable"))?;
    if response.error.is_some() {
        return Err(unavailable("the operation state simulation refuses"));
    }
    let result = response
        .results()
        .map_err(|_| unavailable("the operation state answer is unreadable"))?
        .into_iter()
        .next()
        .ok_or_else(|| unavailable("the operation state answer is absent"))?;
    let stellar_xdr::ScVal::U32(value) = result.xdr else {
        return Err(unavailable("the operation state answer is invalid"));
    };
    Ok(StateAnswer {
        value,
        ledger: response.latest_ledger,
        arrived_at_ms,
        observed_at,
    })
}

/// Reads one operation state through the supplied checked endpoint.
///
/// # Errors
/// Refuses identity, transport, deadline, or simulation failures.
pub async fn read_operation_ledger(
    client: &StellarRpcClient,
    timelock: &str,
    operation_id: &[u8; 32],
    passphrase: &str,
    deadline: Instant,
) -> Result<u32, LedgerWitnessError> {
    client
        .endpoint_identity(passphrase, deadline)
        .await
        .map_err(|error| observation_refusal(&error, true))?;
    let envelope = operation_state_envelope(timelock, operation_id, passphrase)?;
    Ok(read_state(client, &envelope, deadline).await?.value)
}

impl LedgerWitnessCapability {
    /// Acquires both state answers for each selected schedule within remaining freshness.
    ///
    /// Failed or nonterminal probes supply no terminal evidence.
    pub(crate) async fn read_operation_states(&self, probes: &[ScheduleProbe]) -> Self {
        let mut capability = self.clone();
        capability.schedule_evidence.clear();
        if self.ensure_fresh(Instant::now()).is_err() {
            return capability;
        }
        let deadline = self
            .deadline
            .min(self.oldest_observation() + MAX_OBSERVATION_AGE);
        let mut tasks = tokio::task::JoinSet::new();
        for probe in probes.iter().take(MAX_SCHEDULE_PROBES) {
            let Ok(envelope) = operation_state_envelope(
                &probe.timelock,
                &probe.operation_id,
                self.scope.chain().network_passphrase(),
            ) else {
                continue;
            };
            let clients = self.clients.clone();
            let probe = probe.clone();
            tasks.spawn(async move {
                let (primary, secondary) = tokio::join!(
                    read_state(&clients[0], &envelope, deadline),
                    read_state(&clients[1], &envelope, deadline)
                );
                match (primary, secondary) {
                    (Ok(a), Ok(b)) => Some(ScheduleStateEvidence {
                        probe,
                        answers: [a, b],
                    }),
                    _ => None,
                }
            });
        }
        while let Some(result) = tasks.join_next().await {
            if let Ok(Some(evidence)) = result {
                capability.schedule_evidence.push(evidence);
            }
        }
        capability
    }

    pub(crate) fn terminal_for(
        &self,
        id: &str,
        timelock: &str,
        operation_id: &[u8; 32],
        expiration: u32,
        admitted: u64,
        now: u64,
    ) -> Option<(u32, [u32; 2], u64)> {
        let evidence = self.schedule_evidence.iter().find(|e| {
            e.probe.intent_id == id
                && e.probe.timelock == timelock
                && &e.probe.operation_id == operation_id
                && e.probe.expiration == expiration
        })?;
        let [a, b] = &evidence.answers;
        let t = a.arrived_at_ms.max(b.arrived_at_ms);
        let instant = Instant::now();
        if a.value != b.value
            || !matches!(a.value, 0 | 1)
            || self.lower() <= expiration
            || a.ledger <= expiration
            || b.ledger <= expiration
            || !operational_ledger(a.ledger)
            || !operational_ledger(b.ledger)
            || t < admitted
            || t > now
            || [a, b].iter().any(|answer| {
                instant
                    .checked_duration_since(answer.observed_at)
                    .is_none_or(|age| age > MAX_OBSERVATION_AGE)
            })
        {
            return None;
        }
        Some((a.value, [a.ledger, b.ledger], t))
    }

    /// Attaches controlled operation answers to a test capability.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_operation_states_for_test(
        mut self,
        probe: ScheduleProbe,
        values: [u32; 2],
        heights: [u32; 2],
        arrivals: [u64; 2],
    ) -> Self {
        let answer = |i| StateAnswer {
            value: values[i],
            ledger: heights[i],
            arrived_at_ms: arrivals[i],
            observed_at: Instant::now(),
        };
        self.schedule_evidence.push(ScheduleStateEvidence {
            probe,
            answers: [answer(0), answer(1)],
        });
        self
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test assertions")]
    #![allow(clippy::panic, reason = "test assertions")]

    use super::*;
    use std::cell::Cell;
    use std::sync::Mutex;
    use stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE;
    use stellar_agent_test_support::second_loopback_host;
    use stellar_agent_test_support::signed_envelope::get_network_result;
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    const FUTURENET_PASSPHRASE: &str = "Test SDF Future Network ; October 2022";
    use stellar_agent_core::error::ReportedPassphrase;

    const LEDGER_CEILING: u32 = u32::MAX - AUTH_VALIDITY_LEDGERS - 1_000_000;
    const PRIMARY: &str = "https://primary.example";
    const SECONDARY: &str = "https://secondary.example";

    mod reason {
        pub(super) const DEADLINE_ELAPSED: &str = "the pre-submit deadline elapsed";
        pub(super) const PRIMARY_UNREADABLE: &str =
            "the primary RPC endpoint gave no ledger observation";
        pub(super) const SECONDARY_UNREADABLE: &str =
            "the secondary RPC endpoint gave no ledger observation";
        pub(super) const SKEW: &str =
            "the endpoints' latest ledgers differ by more than the tolerance";
        pub(super) const HEIGHT_OUT_OF_BOUNDS: &str = "a reported ledger height is out of bounds";
        pub(super) const CHAIN: &str = "the endpoints identify different chains";
        pub(super) const SAME_HOST: &str =
            "no secondary RPC endpoint on a host other than the primary's is configured";
        pub(super) const STALE: &str = "the ledger observations are stale";
        pub(super) const SECONDARY_WRONG_NETWORK: &str =
            "the secondary RPC endpoint serves another network";
    }

    fn observed_at(ledger: u32, authority: &str, observed_at: Instant) -> ObservedLedger {
        ObservedLedger {
            ledger,
            authority: authority.into(),
            observed_at,
        }
    }

    fn bind_classified(
        primary: ObservedLedger,
        secondary: ObservedLedger,
        secondary_chain: Option<Caip2>,
    ) -> Result<LedgerWitnessCapability, PairRefusal> {
        let observed = [primary, secondary];
        let clients = [
            Arc::new(StellarRpcClient::new(&observed[0].authority).unwrap()),
            Arc::new(StellarRpcClient::new(&observed[1].authority).unwrap()),
        ];
        let observation = |index: usize| {
            SigningLedgerObservation::checked(
                crate::EndpointIdentity::checked(
                    if index == 0 {
                        Some(Caip2::Testnet)
                    } else {
                        secondary_chain
                    },
                    23,
                    stellar_agent_core::redact::redact_url_authority(&observed[index].authority),
                    clients[index].id(),
                ),
                observed[index].ledger,
                observed[index].observed_at,
                0,
            )
        };
        let pair = LedgerWitnessCapability {
            scope: ChainScope::for_chain(Caip2::Testnet),
            primary: observation(0),
            secondary: observation(1),
            clients,
            deadline: Instant::now() + Duration::from_secs(3600),
            schedule_evidence: Vec::new(),
        };
        pair.bind_classified()
    }

    fn bind(
        primary: ObservedLedger,
        secondary: ObservedLedger,
    ) -> Result<LedgerWitnessCapability, LedgerWitnessError> {
        bind_classified(primary, secondary, Some(Caip2::Testnet)).map_err(PairRefusal::into_error)
    }

    fn budget(left: Duration) -> Instant {
        Instant::now().checked_add(left).unwrap()
    }

    fn refusal_code(error: &LedgerWitnessError) -> &'static str {
        match error {
            LedgerWitnessError::Unavailable { .. } => "smart_account.ledger_witness_unavailable",
            LedgerWitnessError::Mismatch { .. } => "simulation.divergence.ledger_skew",
            LedgerWitnessError::MainnetWriteForbidden => "network.mainnet_write_forbidden",
        }
    }

    fn pair(primary: u32, secondary: u32) -> Result<LedgerWitnessCapability, LedgerWitnessError> {
        let now = Instant::now();
        bind(
            observed_at(primary, PRIMARY, now),
            observed_at(secondary, SECONDARY, now),
        )
    }

    fn aged_pair(age: Duration) -> LedgerWitnessCapability {
        let then = Instant::now().checked_sub(age).unwrap();
        bind(
            observed_at(1000, PRIMARY, then),
            observed_at(1000, SECONDARY, then),
        )
        .unwrap()
    }

    fn reason_of(error: &LedgerWitnessError) -> &'static str {
        match error {
            LedgerWitnessError::Unavailable { reason }
            | LedgerWitnessError::Mismatch { reason } => reason,
            other => panic!("not a witness refusal: {other:?}"),
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn schedule_probes_rotate_and_finish_within_freshness() {
        use stellar_xdr::WriteXdr as _;
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};
        let server = MockServer::start().await;
        let arrivals = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded = arrivals.clone();
        let mock_delay = Duration::from_millis(500);
        let value = stellar_xdr::ScVal::U32(0)
            .to_xdr_base64(stellar_xdr::Limits::none())
            .unwrap();
        Mock::given(method("POST")).respond_with(move |request: &wiremock::Request| {
            recorded.lock().unwrap().push(Instant::now());
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            ResponseTemplate::new(200).set_delay(mock_delay).set_body_json(serde_json::json!({
                "jsonrpc": "2.0", "id": body["id"], "result": {
                    "latestLedger": 102, "minResourceFee": "100", "transactionData": "", "results": [{"auth": [], "xdr": value}],
                }
            }))
        }).mount(&server).await;
        let probes: Vec<_> = (0..9)
            .map(|index| ScheduleProbe {
                intent_id: format!("intent-{index}"),
                timelock: stellar_strkey::Contract([1; 32]).to_string().to_string(),
                operation_id: [index; 32],
                expiration: 100,
                admitted_at_ms: u64::from(index),
            })
            .collect();
        let first = select_schedule_probes("rotation-fixture", probes.clone());
        let second = select_schedule_probes("rotation-fixture", probes);
        assert_eq!(first.len(), MAX_SCHEDULE_PROBES);
        assert_eq!(first[0].operation_id, [0; 32]);
        assert_eq!(second[0].operation_id, [8; 32]);
        let primary = server.uri();
        let secondary = primary.replace("127.0.0.1", "localhost");
        let now = Instant::now();
        let capability = LedgerWitnessCapability::for_test(
            ChainScope::for_chain(Caip2::Testnet),
            [&primary, &secondary],
            [101, 101],
            [now, now],
            [1000, 1000],
            now + Duration::from_secs(10),
        )
        .unwrap();
        let observed = capability.read_operation_states(&first).await;
        assert_eq!(
            server.received_requests().await.unwrap().len(),
            16,
            "both endpoints start for every probe"
        );
        let arrivals = arrivals.lock().unwrap().clone();
        assert_eq!(arrivals.len(), 16);
        let gap = *arrivals.iter().max().unwrap() - *arrivals.iter().min().unwrap();
        assert!(
            gap < mock_delay,
            "endpoint arrival gap {gap:?} reaches the mock delay"
        );
        assert_eq!(
            observed.schedule_evidence.len(),
            8,
            "concurrent endpoint answers finish within freshness"
        );
        assert!(
            now.elapsed() < MAX_OBSERVATION_AGE + Duration::from_secs(1),
            "one shared freshness bound controls the batch"
        );
        server.reset().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(500).set_delay(MAX_OBSERVATION_AGE + Duration::from_secs(5)),
            )
            .mount(&server)
            .await;
        let now = Instant::now();
        let capability = LedgerWitnessCapability::for_test(
            ChainScope::for_chain(Caip2::Testnet),
            [&primary, &secondary],
            [101, 101],
            [now, now],
            [1000, 1000],
            now + Duration::from_millis(150),
        )
        .unwrap();
        let observed = capability.read_operation_states(&first).await;
        assert!(observed.schedule_evidence.is_empty());
        assert!(
            now.elapsed() < MAX_OBSERVATION_AGE + Duration::from_secs(1),
            "slow probes share one deadline"
        );
        server.reset().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(500).set_delay(MAX_OBSERVATION_AGE + Duration::from_secs(5)),
            )
            .mount(&server)
            .await;
        let now = Instant::now();
        let old = now - Duration::from_millis(9700);
        let capability = LedgerWitnessCapability::for_test(
            ChainScope::for_chain(Caip2::Testnet),
            [&primary, &secondary],
            [101, 101],
            [old, old],
            [1000, 1000],
            now + MAX_OBSERVATION_AGE + Duration::from_secs(5),
        )
        .unwrap();
        let observed = capability.read_operation_states(&first).await;
        assert!(observed.schedule_evidence.is_empty());
        assert!(
            now.elapsed() < MAX_OBSERVATION_AGE + Duration::from_secs(1),
            "old ledger observations bound slow state probes"
        );
    }

    #[test]
    fn a_pair_within_the_tolerance_binds_in_either_order() {
        for (primary, secondary) in [
            (1000, 1000),
            (1000, 1001),
            (1001, 1000),
            (1000, 1002),
            (1002, 1000),
        ] {
            let bound = pair(primary, secondary).unwrap();
            assert_eq!(bound.lower(), primary.min(secondary));
            assert_eq!(bound.upper(), primary.max(secondary));
        }
    }

    #[test]
    fn a_pair_beyond_the_tolerance_refuses_in_either_order() {
        for (primary, secondary) in [(1000, 1003), (1003, 1000), (1_000_000, 1000)] {
            let error = pair(primary, secondary).unwrap_err();
            assert!(matches!(error, LedgerWitnessError::Mismatch { .. }));
            assert_eq!(reason_of(&error), reason::SKEW);
        }
    }

    #[test]
    fn a_height_no_ledger_can_have_refuses_on_either_side() {
        for (primary, secondary) in [
            (0, 1),
            (1, 0),
            (0, 0),
            (LEDGER_CEILING + 1, LEDGER_CEILING + 1),
            (LEDGER_CEILING + 1, LEDGER_CEILING),
            (LEDGER_CEILING, LEDGER_CEILING + 1),
        ] {
            let error = pair(primary, secondary).unwrap_err();
            assert!(matches!(error, LedgerWitnessError::Mismatch { .. }));
            assert_eq!(reason_of(&error), reason::HEIGHT_OUT_OF_BOUNDS);
        }
        pair(LEDGER_CEILING, LEDGER_CEILING).unwrap();
    }

    #[test]
    fn observations_of_different_chains_refuse() {
        let now = Instant::now();
        let secondary = observed_at(1000, SECONDARY, now);
        let error = bind_classified(observed_at(1000, PRIMARY, now), secondary, None)
            .map_err(PairRefusal::into_error)
            .unwrap_err();
        assert!(matches!(error, LedgerWitnessError::Mismatch { .. }));
        assert_eq!(reason_of(&error), reason::CHAIN);
    }

    #[test]
    fn observations_of_one_host_refuse_on_any_port_or_scheme() {
        let now = Instant::now();
        for secondary in [
            "https://primary.example",
            "https://primary.example:8443",
            "http://PRIMARY.example",
            "https://primary.example.",
        ] {
            let error = bind(
                observed_at(1000, PRIMARY, now),
                observed_at(1000, secondary, now),
            )
            .unwrap_err();
            assert!(
                matches!(error, LedgerWitnessError::Unavailable { .. }),
                "{secondary}"
            );
            assert_eq!(reason_of(&error), reason::SAME_HOST);
        }
    }

    #[test]
    fn a_pair_is_stale_only_past_the_age_limit() {
        let bound = pair(1000, 1000).unwrap();
        let oldest = bound.oldest_observation();
        assert!(!bound.is_stale(oldest.checked_add(MAX_OBSERVATION_AGE).unwrap()));
        assert!(
            bound.is_stale(
                oldest
                    .checked_add(MAX_OBSERVATION_AGE + Duration::from_millis(1))
                    .unwrap()
            )
        );
        assert!(!bound.is_stale(Instant::now()));
        assert!(bound.is_stale(oldest - Duration::from_millis(1)));
    }

    #[test]
    fn the_older_observation_decides_staleness() {
        let now = Instant::now();
        let old = now
            .checked_sub(MAX_OBSERVATION_AGE + Duration::from_secs(1))
            .unwrap();
        for (primary_at, secondary_at) in [(old, now), (now, old)] {
            let bound = bind(
                observed_at(1000, PRIMARY, primary_at),
                observed_at(1000, SECONDARY, secondary_at),
            )
            .unwrap();
            assert!(bound.is_stale(now));
        }
    }

    #[test]
    fn a_fresh_pair_within_the_deadline_is_fit_for_signing() {
        pair(1000, 1000)
            .unwrap()
            .ensure_fresh(Instant::now())
            .unwrap();
    }

    #[test]
    fn an_elapsed_deadline_refuses_signing() {
        let mut bound = pair(1000, 1000).unwrap();
        bound.deadline = Instant::now();
        let error = bound.ensure_fresh(bound.deadline).unwrap_err();
        assert!(matches!(error, LedgerWitnessError::Unavailable { .. }));
        assert_eq!(reason_of(&error), "the pre-submit deadline elapsed");
    }

    #[test]
    fn a_stale_pair_refuses_signing() {
        let error = aged_pair(MAX_OBSERVATION_AGE + Duration::from_secs(1))
            .ensure_fresh(Instant::now())
            .unwrap_err();
        assert!(matches!(error, LedgerWitnessError::Unavailable { .. }));
        assert_eq!(reason_of(&error), reason::STALE);
    }

    /// A pair as the acquisition loop receives it.
    fn classified(primary: u32, secondary: u32) -> Result<LedgerWitnessCapability, PairRefusal> {
        let now = Instant::now();
        bind_classified(
            observed_at(primary, PRIMARY, now),
            observed_at(secondary, SECONDARY, now),
            Some(Caip2::Testnet),
        )
    }

    /// An otherwise valid pair that is stale on arrival.
    fn stale() -> Result<LedgerWitnessCapability, PairRefusal> {
        Ok(aged_pair(MAX_OBSERVATION_AGE + Duration::from_secs(1)))
    }

    /// A budget no acquisition test exhausts.
    fn ample() -> Instant {
        budget(Duration::from_secs(30))
    }

    #[tokio::test]
    async fn a_fresh_pair_is_acquired_once() {
        let calls = Cell::new(0);
        acquire_fresh_pair(ample(), || {
            calls.set(calls.get() + 1);
            async { classified(1000, 1000) }
        })
        .await
        .unwrap();
        assert_eq!(calls.get(), 1);
    }

    #[tokio::test]
    async fn a_stale_pair_is_reacquired_as_a_pair() {
        let calls = Cell::new(0);
        let bound = acquire_fresh_pair(ample(), || {
            calls.set(calls.get() + 1);
            let attempt = calls.get();
            async move {
                if attempt == 1 {
                    stale()
                } else {
                    classified(1004, 1005)
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(calls.get(), 2);
        assert_eq!(
            (bound.lower(), bound.upper()),
            (1004, 1005),
            "both members come from the second reading"
        );
    }

    #[tokio::test]
    async fn a_pair_stale_three_times_refuses() {
        let calls = Cell::new(0);
        let error = acquire_fresh_pair(ample(), || {
            calls.set(calls.get() + 1);
            async { stale() }
        })
        .await
        .unwrap_err();
        assert_eq!(calls.get(), MAX_PAIR_ACQUISITIONS);
        assert_eq!(
            refusal_code(&error),
            "smart_account.ledger_witness_unavailable"
        );
        assert_eq!(reason_of(&error), reason::STALE);
    }

    /// A stale pair followed by two skewed ones refuses with the skew of the
    /// last, and no fourth pair is read.
    #[tokio::test]
    async fn a_failed_reacquisition_keeps_its_refusal() {
        let calls = Cell::new(0);
        let error = acquire_fresh_pair(ample(), || {
            calls.set(calls.get() + 1);
            let attempt = calls.get();
            async move {
                if attempt == 1 {
                    stale()
                } else {
                    classified(1000, 1003)
                }
            }
        })
        .await
        .unwrap_err();
        assert_eq!(calls.get(), 3, "no fourth pair");
        assert_eq!(refusal_code(&error), "simulation.divergence.ledger_skew");
        assert_eq!(reason_of(&error), reason::SKEW);
    }

    /// A skewed pair is read again, in either endpoint order, and the second
    /// pair's agreement binds.
    #[tokio::test]
    async fn skewed_pair_retries_to_agreement() {
        for (first, second) in [((1000, 1003), (1002, 1003)), ((1003, 1000), (1003, 1002))] {
            let calls = Cell::new(0);
            let bound = acquire_fresh_pair(ample(), || {
                calls.set(calls.get() + 1);
                let (primary, secondary) = if calls.get() == 1 { first } else { second };
                async move { classified(primary, secondary) }
            })
            .await
            .unwrap();
            assert_eq!(calls.get(), 2, "{first:?}");
            assert_eq!((bound.lower(), bound.upper()), (1002, 1003), "{first:?}");
        }
    }

    #[tokio::test]
    async fn stale_pair_can_succeed_on_the_last_attempt() {
        let calls = Cell::new(0);
        let bound = acquire_fresh_pair(ample(), || {
            calls.set(calls.get() + 1);
            let attempt = calls.get();
            async move {
                if attempt < 3 {
                    stale()
                } else {
                    classified(1010, 1011)
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(calls.get(), 3);
        assert_eq!((bound.lower(), bound.upper()), (1010, 1011));
    }

    /// Each refusal other than skew and staleness ends the acquisition on the
    /// pair that produced it, with its own reason and code.
    #[tokio::test]
    #[serial_test::serial]
    async fn terminal_pair_failures_do_not_retry() {
        let now = Instant::now();
        let other_chain = observed_at(1000, SECONDARY, now);
        let cases = [
            (
                "invalid height",
                bind_classified(
                    observed_at(0, PRIMARY, now),
                    observed_at(1000, SECONDARY, now),
                    Some(Caip2::Testnet),
                ),
                reason::HEIGHT_OUT_OF_BOUNDS,
                "simulation.divergence.ledger_skew",
            ),
            (
                "chain mismatch",
                bind_classified(observed_at(1000, PRIMARY, now), other_chain, None),
                reason::CHAIN,
                "simulation.divergence.ledger_skew",
            ),
            (
                "same host",
                bind_classified(
                    observed_at(1000, PRIMARY, now),
                    observed_at(1000, "https://primary.example:8443", now),
                    Some(Caip2::Testnet),
                ),
                reason::SAME_HOST,
                "smart_account.ledger_witness_unavailable",
            ),
        ];
        // Every case is judged before the test fails, so a failure names each
        // case that broke.
        let mut broken = Vec::new();
        let mut judge = |case: &str,
                         result: Result<LedgerWitnessCapability, LedgerWitnessError>,
                         expected,
                         code,
                         pairs: Vec<usize>| {
            match result {
                Ok(_) => broken.push(format!("{case}: a pair bound")),
                Err(error) => {
                    if reason_of(&error) != expected || refusal_code(&error) != code {
                        broken.push(format!("{case}: {error:?}"));
                    }
                }
            }
            if pairs.iter().any(|&count| count != 1) {
                broken.push(format!("{case}: {pairs:?} pairs read"));
            }
        };
        for (case, outcome, expected, code) in cases {
            let outcome = Cell::new(Some(outcome));
            let calls = Cell::new(0);
            let result = acquire_fresh_pair(ample(), || {
                calls.set(calls.get() + 1);
                let outcome = outcome.take().unwrap_or_else(|| classified(1000, 1000));
                async move { outcome }
            })
            .await;
            judge(case, result, expected, code, vec![calls.get()]);
        }

        // A height that fails on the wire ends the call on its first read of
        // each endpoint.
        for (case, primary_heights, secondary_heights, expected) in [
            (
                "height transport failure",
                vec![Height::At(1000)],
                vec![Height::Refused, Height::At(1000)],
                reason::SECONDARY_UNREADABLE,
            ),
            (
                "malformed height",
                vec![Height::Malformed, Height::At(1000)],
                vec![Height::At(1000)],
                reason::PRIMARY_UNREADABLE,
            ),
        ] {
            let primary = Endpoint::start(Script::heights(primary_heights)).await;
            let secondary = Endpoint::start(Script::heights(secondary_heights)).await;

            let result = witness(&primary, &secondary).await;

            judge(
                case,
                result,
                expected,
                "smart_account.ledger_witness_unavailable",
                vec![
                    primary.count("getLatestLedger"),
                    secondary.count("getLatestLedger"),
                ],
            );
        }
        assert!(broken.is_empty(), "{broken:#?}");
    }

    /// No pair is read once the deadline has passed, and a pair rejected when
    /// the deadline then passes keeps its own refusal.
    #[tokio::test]
    async fn deadline_prevents_another_pair() {
        let calls = Cell::new(0);
        let error = acquire_fresh_pair(budget(Duration::ZERO), || {
            calls.set(calls.get() + 1);
            async { classified(1000, 1000) }
        })
        .await
        .unwrap_err();
        assert_eq!(calls.get(), 0, "no pair is read");
        assert_eq!(
            refusal_code(&error),
            "smart_account.ledger_witness_unavailable"
        );
        assert_eq!(reason_of(&error), reason::DEADLINE_ELAPSED);

        let calls = Cell::new(0);
        let error = acquire_fresh_pair(budget(Duration::from_millis(100)), || {
            calls.set(calls.get() + 1);
            async {
                tokio::time::sleep(Duration::from_millis(150)).await;
                stale()
            }
        })
        .await
        .unwrap_err();
        assert_eq!(calls.get(), 1, "the deadline stops the loop");
        assert_eq!(
            refusal_code(&error),
            "smart_account.ledger_witness_unavailable"
        );
        assert_eq!(reason_of(&error), reason::STALE);
    }

    #[tokio::test]
    async fn a_skewed_pair_at_the_deadline_keeps_the_skew_code() {
        let calls = Cell::new(0);
        let error = acquire_fresh_pair(budget(Duration::from_millis(100)), || {
            calls.set(calls.get() + 1);
            async {
                tokio::time::sleep(Duration::from_millis(150)).await;
                classified(1000, 1003)
            }
        })
        .await
        .unwrap_err();
        assert_eq!(calls.get(), 1, "the deadline stops the loop");
        assert!(
            matches!(error, LedgerWitnessError::Mismatch { .. }),
            "{error:?}"
        );
        assert_eq!(refusal_code(&error), "simulation.divergence.ledger_skew");
        assert_eq!(reason_of(&error), reason::SKEW);
    }

    /// The pair that binds after a skew holds both heights of its own
    /// reading, and the expiry derives from its lower member.
    #[tokio::test]
    async fn skew_retry_never_combines_attempts() {
        let calls = Cell::new(0);
        let bound = acquire_fresh_pair(ample(), || {
            calls.set(calls.get() + 1);
            let (primary, secondary) = if calls.get() == 1 {
                (1000, 1003)
            } else {
                (1003, 1004)
            };
            async move { classified(primary, secondary) }
        })
        .await
        .unwrap();
        assert_eq!(calls.get(), 2);
        assert_eq!(
            (bound.primary.ledger(), bound.secondary.ledger()),
            (1003, 1004)
        );
        assert_eq!(
            bound.lower().checked_add(AUTH_VALIDITY_LEDGERS).unwrap(),
            1103
        );
    }

    /// A pair whose observations arrived `primary_age` and `secondary_age`
    /// before now.
    fn classified_aged(
        primary: u32,
        secondary: u32,
        primary_age: Duration,
        secondary_age: Duration,
    ) -> Result<LedgerWitnessCapability, PairRefusal> {
        let now = Instant::now();
        bind_classified(
            observed_at(primary, PRIMARY, now.checked_sub(primary_age).unwrap()),
            observed_at(
                secondary,
                SECONDARY,
                now.checked_sub(secondary_age).unwrap(),
            ),
            Some(Caip2::Testnet),
        )
    }

    /// Each pair read again announces itself once, after the pair it
    /// replaces, with the trigger, the discarded heights, their ages, the
    /// remaining budget, and the redacted authorities.
    #[test]
    #[serial_test::serial]
    fn every_reread_has_a_debug_event() {
        // The paused clock moves only when an acquisition advances it, so
        // every age and the remaining budget are exact.
        let paused = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .unwrap();
        let logs = stellar_agent_test_support::log_capture::with_captured_trace_logs(|| {
            paused.block_on(async {
                let calls = Cell::new(0);
                acquire_fresh_pair(ample(), || {
                    calls.set(calls.get() + 1);
                    let attempt = calls.get();
                    async move {
                        match attempt {
                            1 => {
                                tokio::time::advance(Duration::from_millis(200)).await;
                                classified_aged(
                                    1000,
                                    1000,
                                    Duration::from_millis(11_000),
                                    Duration::from_millis(10_500),
                                )
                            }
                            2 => {
                                tokio::time::advance(Duration::from_millis(300)).await;
                                classified_aged(
                                    1000,
                                    1003,
                                    Duration::from_millis(40),
                                    Duration::from_millis(70),
                                )
                            }
                            _ => classified(1003, 1004),
                        }
                    }
                })
                .await
                .unwrap();
            });
        });
        let events: Vec<&str> = logs
            .lines()
            .filter(|line| line.contains("ledger witness reads the pair again"))
            .collect();
        assert_eq!(events.len(), 2, "{logs}");
        for (event, attempt, trigger, primary, secondary, ages, remaining) in [
            (events[0], 2, "stale", 1000, 1000, (11_000, 10_500), 29_800),
            (events[1], 3, "skew", 1000, 1003, (40, 70), 29_500),
        ] {
            for field in [
                format!("attempt={attempt} "),
                format!("trigger=\"{trigger}\" "),
                format!("primary_ledger={primary} "),
                format!("secondary_ledger={secondary} "),
                format!("primary_age_ms={} ", ages.0),
                format!("secondary_age_ms={} ", ages.1),
                format!("remaining_ms={remaining} "),
                format!("primary={PRIMARY} "),
                format!("secondary={SECONDARY}"),
            ] {
                assert!(event.contains(&field), "{field} in {event}");
            }
        }

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let logs = stellar_agent_test_support::log_capture::with_captured_trace_logs(|| {
            runtime.block_on(async {
                let primary = Endpoint::start(Script::heights(vec![Height::At(1000)])).await;
                let secondary =
                    Endpoint::start(Script::heights(vec![Height::At(1003), Height::At(1001)]))
                        .await;
                let client = StellarRpcClient::new(&format!(
                    "{}/rpc?token={CREDENTIAL}",
                    primary.server.uri()
                ))
                .unwrap();
                let secondary_url = second_loopback_host(&format!(
                    "{}/rpc?token={CREDENTIAL}",
                    secondary.server.uri()
                ));
                witness_through(&client, &secondary_url).await.unwrap();
            });
        });
        let events: Vec<&str> = logs
            .lines()
            .filter(|line| line.contains("ledger witness reads the pair again"))
            .collect();
        assert_eq!(events.len(), 1, "{logs}");
        assert!(events[0].contains("trigger=\"skew\""), "{}", events[0]);
        assert!(
            events[0].contains("primary=http://127.0.0.1:"),
            "{}",
            events[0]
        );
        assert!(
            events[0].contains("secondary=http://localhost:"),
            "{}",
            events[0]
        );
        assert!(!logs.contains(CREDENTIAL), "{logs}");
    }

    // ── Witness calls against mocked endpoints ─────────────────────────────

    /// A credential the endpoint URLs carry, which no log line may hold.
    const CREDENTIAL: &str = "SENTINEL-CREDENTIAL";

    /// One `getLatestLedger` answer.
    #[derive(Clone, Copy)]
    enum Height {
        At(u32),
        Malformed,
        Refused,
    }

    /// What one mocked endpoint answers.
    #[derive(Clone)]
    struct Script {
        identity: serde_json::Value,
        identity_delay: Duration,
        /// The answer to each `getLatestLedger` read in turn; the last one
        /// repeats.
        heights: Vec<Height>,
        height_delay: Duration,
    }

    impl Script {
        fn heights(heights: Vec<Height>) -> Self {
            Self {
                identity: get_network_result(TESTNET_PASSPHRASE),
                identity_delay: Duration::ZERO,
                heights,
                height_delay: Duration::ZERO,
            }
        }
    }

    /// Answers by `script` and records each request's method and arrival.
    struct ScriptedRpc {
        script: Script,
        log: Arc<Mutex<Vec<(String, Instant)>>>,
    }

    impl Respond for ScriptedRpc {
        fn respond(&self, request: &Request) -> ResponseTemplate {
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            let method = body["method"].as_str().unwrap().to_owned();
            let index = {
                let mut log = self.log.lock().unwrap();
                let index = log.iter().filter(|(seen, _)| *seen == method).count();
                log.push((method.clone(), Instant::now()));
                index
            };
            let answer = |result: serde_json::Value| {
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": body["id"],
                    "result": result,
                }))
            };
            match method.as_str() {
                "getNetwork" => {
                    answer(self.script.identity.clone()).set_delay(self.script.identity_delay)
                }
                "getLatestLedger" => {
                    let height = self
                        .script
                        .heights
                        .get(index)
                        .or(self.script.heights.last())
                        .copied()
                        .unwrap();
                    match height {
                        Height::At(ledger) => answer(serde_json::json!({
                            "id": "ab".repeat(32),
                            "sequence": ledger,
                            "protocolVersion": 29,
                        }))
                        .set_delay(self.script.height_delay),
                        Height::Malformed => answer(serde_json::json!({
                            "id": "ab".repeat(32),
                            "sequence": "not-a-ledger",
                            "protocolVersion": 29,
                        })),
                        Height::Refused => ResponseTemplate::new(503),
                    }
                }
                other => panic!("unexpected request: {other}"),
            }
        }
    }

    /// A mocked endpoint and the requests it received.
    struct Endpoint {
        server: MockServer,
        log: Arc<Mutex<Vec<(String, Instant)>>>,
    }

    impl Endpoint {
        async fn start(script: Script) -> Self {
            let server = MockServer::start().await;
            let log = Arc::new(Mutex::new(Vec::new()));
            Mock::given(wiremock::matchers::method("POST"))
                .respond_with(ScriptedRpc {
                    script,
                    log: Arc::clone(&log),
                })
                .mount(&server)
                .await;
            Self { server, log }
        }

        /// The arrival of each `method` request, in order.
        fn arrivals(&self, method: &str) -> Vec<Instant> {
            self.log
                .lock()
                .unwrap()
                .iter()
                .filter(|(seen, _)| seen == method)
                .map(|(_, at)| *at)
                .collect()
        }

        fn count(&self, method: &str) -> usize {
            self.arrivals(method).len()
        }
    }

    /// The deadline of every witness call against mocked endpoints.
    const WITNESS_DEADLINE: Duration = Duration::from_secs(20);

    async fn witness_through(
        primary: &StellarRpcClient,
        secondary_rpc_url: &str,
    ) -> Result<LedgerWitnessCapability, LedgerWitnessError> {
        let secondary = StellarRpcClient::new(secondary_rpc_url).unwrap();
        LedgerWitnessCapability::acquire(
            primary,
            &secondary,
            TESTNET_PASSPHRASE,
            budget(WITNESS_DEADLINE),
        )
        .await
    }

    /// One witness call with `primary` as the primary and `secondary` on a
    /// host apart from it.
    async fn witness(
        primary: &Endpoint,
        secondary: &Endpoint,
    ) -> Result<LedgerWitnessCapability, LedgerWitnessError> {
        let client = StellarRpcClient::new(&primary.server.uri()).unwrap();
        witness_through(&client, &second_loopback_host(&secondary.server.uri())).await
    }

    /// No height request starts before both identities have been answered,
    /// whichever identity is slow, and the two heights are in flight at the
    /// same time.
    #[tokio::test]
    #[serial_test::serial]
    async fn both_identities_finish_before_either_height_starts() {
        let slow = Duration::from_millis(400);
        let height_delay = Duration::from_millis(300);
        for slow_primary in [false, true] {
            let script = |identity_delay| Script {
                identity_delay,
                height_delay,
                ..Script::heights(vec![Height::At(1000)])
            };
            let (primary_delay, secondary_delay) = if slow_primary {
                (slow, Duration::ZERO)
            } else {
                (Duration::ZERO, slow)
            };
            let primary = Endpoint::start(script(primary_delay)).await;
            let secondary = Endpoint::start(script(secondary_delay)).await;

            witness(&primary, &secondary).await.unwrap();

            let identities_answered = (primary.arrivals("getNetwork")[0] + primary_delay)
                .max(secondary.arrivals("getNetwork")[0] + secondary_delay);
            let primary_height = primary.arrivals("getLatestLedger")[0];
            let secondary_height = secondary.arrivals("getLatestLedger")[0];
            for (side, height) in [("primary", primary_height), ("secondary", secondary_height)] {
                assert!(
                    height >= identities_answered,
                    "slow primary {slow_primary}: the {side} height waits for both identities"
                );
            }
            let gap = if primary_height > secondary_height {
                primary_height - secondary_height
            } else {
                secondary_height - primary_height
            };
            assert!(
                gap < height_delay,
                "slow primary {slow_primary}: both heights start before either answers: {gap:?}"
            );
        }
    }

    /// One witness call checks each identity once, and every further pair
    /// reads both heights again.
    #[tokio::test]
    #[serial_test::serial]
    async fn every_reread_replaces_both_heights() {
        let primary = Endpoint::start(Script {
            height_delay: Duration::from_millis(20),
            ..Script::heights(vec![Height::At(1000)])
        })
        .await;
        let secondary = Endpoint::start(Script::heights(vec![
            Height::At(1003),
            Height::At(1003),
            Height::At(1002),
        ]))
        .await;

        let before_ms = crate::mainnet::clock::now_ms().unwrap();
        let before = Instant::now();
        let bound = witness(&primary, &secondary).await.unwrap();
        for (observation, endpoint) in [(&bound.primary, &primary), (&bound.secondary, &secondary)]
        {
            let last_request = endpoint.arrivals("getLatestLedger")[2];
            assert!(observation.observed_at() >= last_request);
            let elapsed_ms =
                u64::try_from(last_request.duration_since(before).as_millis()).unwrap();
            assert!(observation.arrived_at_ms() >= before_ms + elapsed_ms);
            assert!(observation.arrived_at_ms() <= crate::mainnet::clock::now_ms().unwrap());
        }
        let endpoints = OnDiskRpcEndpoints {
            chain_id: Caip2::Testnet,
            rpc_url: primary.server.uri(),
            secondary_rpc_url: Some(second_loopback_host(&secondary.server.uri())),
        };
        assert!(bound.authorizes(
            &endpoints,
            bound.scope(),
            crate::mainnet::clock::now_ms().unwrap()
        ));
        let mut other_endpoints = endpoints.clone();
        other_endpoints.rpc_url.push_str("/other");
        assert!(!bound.authorizes(
            &other_endpoints,
            bound.scope(),
            crate::mainnet::clock::now_ms().unwrap()
        ));

        assert_eq!((bound.lower(), bound.upper()), (1000, 1002));
        assert_eq!(primary.count("getNetwork"), 1);
        assert_eq!(secondary.count("getNetwork"), 1);
        assert_eq!(primary.count("getLatestLedger"), 3);
        assert_eq!(secondary.count("getLatestLedger"), 3);
    }

    /// A second witness call checks both identities again. A refused
    /// identity, of another network or unreadable, is asked once and starts
    /// no height on either endpoint.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_new_witness_call_checks_both_identities() {
        let primary = Endpoint::start(Script::heights(vec![Height::At(1000)])).await;
        let secondary = Endpoint::start(Script::heights(vec![Height::At(1001)])).await;
        let client = StellarRpcClient::new(&primary.server.uri()).unwrap();
        let secondary_url = second_loopback_host(&secondary.server.uri());

        witness_through(&client, &secondary_url).await.unwrap();
        witness_through(&client, &secondary_url).await.unwrap();

        assert_eq!(primary.count("getNetwork"), 2);
        assert_eq!(secondary.count("getNetwork"), 2);
        assert_eq!(primary.count("getLatestLedger"), 2);
        assert_eq!(secondary.count("getLatestLedger"), 2);

        let unreadable = Script {
            identity: serde_json::json!({"passphrase": TESTNET_PASSPHRASE}),
            ..Script::heights(vec![Height::At(1000)])
        };
        let other_network = Script {
            identity: get_network_result(FUTURENET_PASSPHRASE),
            ..Script::heights(vec![Height::At(1000)])
        };
        for (case, primary_script, secondary_script, expected) in [
            (
                "secondary on another network",
                Script::heights(vec![Height::At(1000)]),
                other_network,
                reason::SECONDARY_WRONG_NETWORK,
            ),
            (
                "unreadable primary identity",
                unreadable,
                Script::heights(vec![Height::At(1000)]),
                reason::PRIMARY_UNREADABLE,
            ),
        ] {
            let primary = Endpoint::start(primary_script).await;
            let secondary = Endpoint::start(secondary_script).await;

            let error = witness(&primary, &secondary).await.unwrap_err();

            assert_eq!(reason_of(&error), expected, "{case}");
            assert_eq!(
                refusal_code(&error),
                "smart_account.ledger_witness_unavailable",
                "{case}"
            );
            for (side, endpoint) in [("primary", &primary), ("secondary", &secondary)] {
                assert_eq!(endpoint.count("getNetwork"), 1, "{case}: {side} identity");
                assert_eq!(
                    endpoint.count("getLatestLedger"),
                    0,
                    "{case}: {side} height"
                );
            }
        }
    }

    #[test]
    fn a_failed_observation_maps_to_its_refusal() {
        let mismatch = WalletError::Network(NetworkError::EndpointNetworkMismatch {
            expected: "SENTINEL-EXPECTED".to_owned(),
            server: ReportedPassphrase::from_reported("SENTINEL-REPORTED"),
        });
        let refusal = observation_refusal(&mismatch, false);
        assert_eq!(reason_of(&refusal), reason::SECONDARY_WRONG_NETWORK);
        assert!(!refusal.to_string().contains("SENTINEL"), "{refusal}");

        let mainnet = WalletError::Network(NetworkError::MainnetWriteForbidden);
        assert!(matches!(
            observation_refusal(&mainnet, false),
            LedgerWitnessError::MainnetWriteForbidden
        ));
    }
}
