//! The independent ledger observation every smart-account signing path
//! requires.
//!
//! A Soroban address signature carries a `signature_expiration_ledger`, and
//! the height it derives from comes from an RPC endpoint, so that height
//! decides how long a signature stays valid. Each signing path therefore reads
//! the latest ledger from the primary and from a secondary endpoint, through
//! [`StellarRpcClient`]'s checked identity, and refuses unless the two agree
//! within [`MAX_SIGNING_LEDGER_SKEW`].
//!
//! Both endpoint identities complete before either height request starts.
//! The two height requests run concurrently under the same deadline. Each
//! witness call checks both identities once. Each repeated acquisition
//! replaces both heights and their receipt times.
//!
//! # Trust assumption
//!
//! The bound holds when at least one of the two endpoints reports the chain
//! honestly. The endpoints must sit on different hosts, but different hosts do
//! not establish different operators: two hosts run by one hostile party can
//! agree on a false height. Choosing independently operated endpoints is the
//! operator's part of the contract.
//!
//! # Bound semantics
//!
//! Both members of an accepted pair are claims, so neither is chosen for being
//! favorable to the signer. A height that limits an authorization takes the
//! lower member and a check that an authorization is still valid takes the
//! higher one. The expiry is 100 ledgers beyond the lower member, which keeps
//! it at most that far beyond either observation.

use std::future::Future;
use std::time::Duration;

use async_trait::async_trait;
use stellar_agent_core::error::{NetworkError, WalletError};
use stellar_agent_core::profile::caip2::Caip2;
use stellar_agent_core::profile::schema::{check_endpoint_url, same_provider_host};
use stellar_agent_network::signing::{
    MessagePayload, Signer, SmartAccountAuthDigest, SorobanAuthPayload, TxSigningPayload,
};
use stellar_agent_network::{
    PreparedSigningLedgerRead, SigningLedgerObservation, StellarRpcClient, WebAuthnAssertion,
};
use tokio::time::Instant;
use tracing::debug;

use crate::SaError;
use crate::managers::auth_entry::PreSubmitBudget;
use crate::managers::rules::{AUTH_VALIDITY_LEDGERS, validate_latest_ledger};

/// Largest difference, in ledgers and in either order, between the primary's
/// and the secondary's latest ledger that a signing path accepts.
///
/// Mirrors the size of the oracle lag tolerance `MAX_ORACLE_LAG_LEDGERS` of
/// `stellar_agent_network::cross_check::soroban`. That constant is private and
/// asymmetric: the primary may lead by it, and an oracle ahead is bounded by
/// expiry alone. This one is symmetric, because either endpoint here can be
/// the dishonest one.
pub const MAX_SIGNING_LEDGER_SKEW: u32 = 2;

/// Longest age of an observation a signature may rest on: two ledger closes
/// at the network's five-second cadence, the span the skew tolerance admits.
pub(crate) const MAX_OBSERVATION_AGE: Duration = Duration::from_secs(10);

/// The most height pairs one witness call reads: the first pair and at most
/// two more, each read only while the deadline has not passed.
const MAX_PAIR_ACQUISITIONS: u32 = 3;

/// The fixed reason of a refusal: `LedgerWitnessUnavailable` or
/// `LedgerWitnessMismatch` never echoes endpoint input, which can hold a
/// credential.
mod reason {
    pub(super) const SECONDARY_ABSENT: &str = "no secondary RPC endpoint is configured";
    pub(super) const PRIMARY_URL_INVALID: &str = "the primary RPC URL is not a usable endpoint URL";
    pub(super) const SECONDARY_URL_INVALID: &str =
        "the secondary RPC URL is not a usable endpoint URL";
    pub(super) const SAME_HOST: &str =
        "no secondary RPC endpoint on a host other than the primary's is configured";
    pub(super) const SECONDARY_CLIENT: &str = "the secondary RPC client could not be built";
    pub(super) const PRIMARY_WRONG_NETWORK: &str =
        "the primary RPC endpoint serves another network";
    pub(super) const SECONDARY_WRONG_NETWORK: &str =
        "the secondary RPC endpoint serves another network";
    pub(super) const PRIMARY_UNREADABLE: &str =
        "the primary RPC endpoint gave no ledger observation";
    pub(super) const SECONDARY_UNREADABLE: &str =
        "the secondary RPC endpoint gave no ledger observation";
    pub(super) const STALE: &str = "the ledger observations are stale";
    pub(super) const DEADLINE_ELAPSED: &str = "the pre-submit deadline elapsed";
    pub(super) const SKEW: &str = "the endpoints' latest ledgers differ by more than the tolerance";
    pub(super) const HEIGHT_OUT_OF_BOUNDS: &str = "a reported ledger height is out of bounds";
    pub(super) const CHAIN: &str = "the endpoints identify different chains";
    pub(super) const SIMULATED_HEIGHT: &str =
        "the simulated ledger height disagrees with the ledger observations";
    pub(super) const EXPIRY_OVERFLOW: &str = "the signature expiration ledger overflows";
}

/// One endpoint's height, reduced to what the bound keeps of it.
#[derive(Debug, Clone)]
struct ObservedLedger {
    ledger: u32,
    authority: String,
    chain_id: Option<Caip2>,
    observed_at: Instant,
}

impl From<SigningLedgerObservation> for ObservedLedger {
    fn from(observation: SigningLedgerObservation) -> Self {
        Self {
            ledger: observation.ledger(),
            authority: observation.identity().authority().to_owned(),
            chain_id: observation.identity().chain_id(),
            observed_at: observation.observed_at(),
        }
    }
}

/// What one signing attempt asks of the witness.
#[derive(Clone, Copy)]
pub(crate) struct WitnessRequest<'a> {
    /// The client that simulates and sends: the primary's observation comes
    /// from the endpoint the transaction goes to.
    pub(crate) primary: &'a StellarRpcClient,
    /// The secondary endpoint, as [`checked_secondary_rpc_url`] returned it.
    pub(crate) secondary_rpc_url: &'a str,
    /// The passphrase both endpoints must report.
    pub(crate) network_passphrase: &'a str,
    /// The deadline both observations and the signature rest on.
    pub(crate) budget: PreSubmitBudget,
}

/// Two agreeing ledger observations, one from each endpoint.
///
/// The fields are private and [`witness_signing_ledger`] is the only
/// constructor outside this module, so a value means both endpoints were
/// asked directly and passed the checks. A caller holding a height from a
/// simulation cannot build one.
#[derive(Debug, Clone)]
pub(crate) struct WitnessedLedgerBound {
    primary: ObservedLedger,
    secondary: ObservedLedger,
    chain_id: Option<Caip2>,
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
    Terminal(SaError),
}

impl PairRefusal {
    /// The refusal a caller receives for this pair: the skew mismatch for a
    /// skewed pair, and the terminal refusal itself otherwise.
    fn into_error(self) -> SaError {
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
    fn into_refusal(self) -> SaError {
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

impl WitnessedLedgerBound {
    /// Binds a pair of observations, or refuses it with the refusal a caller
    /// receives. The validation tests bind pairs directly through it; the
    /// witness binds through [`Self::bind_classified`].
    #[cfg(test)]
    fn bind(primary: ObservedLedger, secondary: ObservedLedger) -> Result<Self, SaError> {
        Self::bind_classified(primary, secondary).map_err(PairRefusal::into_error)
    }

    /// Binds a pair of observations, or refuses it with the kind of refusal
    /// another pair could change.
    ///
    /// The checks run in this order: height bounds, chain equality, host
    /// distinctness, then the symmetric skew. Only the skew can differ in a
    /// later pair; every earlier refusal is terminal.
    fn bind_classified(
        primary: ObservedLedger,
        secondary: ObservedLedger,
    ) -> Result<Self, PairRefusal> {
        for observation in [&primary, &secondary] {
            validate_latest_ledger(observation.ledger)
                .map_err(|_| PairRefusal::Terminal(mismatch(reason::HEIGHT_OUT_OF_BOUNDS)))?;
        }
        // Both observations pass `endpoint_identity(expected_passphrase)` with
        // the passphrase of one request, and `bind_classified` is the one
        // constructor of a bound. The check refuses a mixed pair whichever
        // caller binds it.
        if primary.chain_id != secondary.chain_id {
            return Err(PairRefusal::Terminal(mismatch(reason::CHAIN)));
        }
        if same_provider_host(&primary.authority, &secondary.authority) {
            return Err(PairRefusal::Terminal(unavailable(reason::SAME_HOST)));
        }
        if primary.ledger.abs_diff(secondary.ledger) > MAX_SIGNING_LEDGER_SKEW {
            return Err(PairRefusal::Skew { primary, secondary });
        }
        let chain_id = primary.chain_id;
        Ok(Self {
            primary,
            secondary,
            chain_id,
        })
    }

    /// The lower member of the pair: the height a limit on an authorization
    /// is measured from.
    pub(crate) fn lower(&self) -> u32 {
        self.primary.ledger.min(self.secondary.ledger)
    }

    /// The higher member of the pair: the height an authorization must still
    /// be valid at.
    pub(crate) fn higher(&self) -> u32 {
        self.primary.ledger.max(self.secondary.ledger)
    }

    /// The expiry every signature of this attempt carries.
    ///
    /// # Errors
    ///
    /// [`SaError::LedgerWitnessMismatch`] when the sum overflows.
    pub(crate) fn signature_expiration_ledger(&self) -> Result<u32, SaError> {
        expiry_beyond(self.lower())
    }

    /// Whether the older observation has passed [`MAX_OBSERVATION_AGE`] at
    /// `now`.
    pub(crate) fn is_stale(&self, now: Instant) -> bool {
        let oldest = self.primary.observed_at.min(self.secondary.observed_at);
        now.saturating_duration_since(oldest) > MAX_OBSERVATION_AGE
    }

    /// Requires the height the simulation ran at to lie within the skew
    /// tolerance of the pair.
    ///
    /// The simulation answers from the primary, so a height outside that
    /// range means the primary contradicts its own observation. Called with
    /// the bound acquired right after the simulation.
    ///
    /// # Errors
    ///
    /// [`SaError::LedgerWitnessMismatch`] when the height lies outside.
    pub(crate) fn check_simulation_height(&self, simulated: u32) -> Result<(), SaError> {
        let floor = self.lower().saturating_sub(MAX_SIGNING_LEDGER_SKEW);
        let ceiling = self.higher().saturating_add(MAX_SIGNING_LEDGER_SKEW);
        if (floor..=ceiling).contains(&simulated) {
            Ok(())
        } else {
            Err(mismatch(reason::SIMULATED_HEIGHT))
        }
    }

    /// Requires the pair to be fit for signing now: the pre-submit deadline
    /// has not elapsed and neither observation is stale.
    ///
    /// # Errors
    ///
    /// [`SaError::LedgerWitnessUnavailable`] otherwise.
    pub(crate) fn ensure_fresh(&self, budget: PreSubmitBudget) -> Result<(), SaError> {
        self.ensure_fresh_at(budget, Instant::now())
    }

    /// [`Self::ensure_fresh`] judged at `now`.
    ///
    /// # Errors
    ///
    /// [`SaError::LedgerWitnessUnavailable`] when the deadline has elapsed or
    /// an observation is stale at `now`.
    pub(crate) fn ensure_fresh_at(
        &self,
        budget: PreSubmitBudget,
        now: Instant,
    ) -> Result<(), SaError> {
        if now >= budget.deadline {
            return Err(unavailable(reason::DEADLINE_ELAPSED));
        }
        if self.is_stale(now) {
            return Err(unavailable(reason::STALE));
        }
        Ok(())
    }
}

/// Requires a secondary endpoint a signing path can use as a witness, and
/// returns it.
///
/// The check is local. Both URLs must parse as HTTP(S) endpoint URLs with a
/// host, and the hosts must differ after the URL crate's normalization: scheme,
/// port and path do not make an endpoint on the same host a witness. Distinct
/// hosts do not establish distinct administration; see the module docs.
///
/// # Errors
///
/// [`SaError::LedgerWitnessUnavailable`] with a fixed reason. The reason never
/// names the input, which can hold a credential.
pub fn checked_secondary_rpc_url<'a>(
    primary_rpc_url: &str,
    secondary_rpc_url: Option<&'a str>,
    network_passphrase: &str,
) -> Result<&'a str, SaError> {
    let secondary = secondary_rpc_url.ok_or_else(|| unavailable(reason::SECONDARY_ABSENT))?;
    // Mainnet writes refuse before this check, so a network the wallet holds
    // no chain id for takes the non-mainnet URL rule as well.
    let chain = Caip2::from_passphrase(network_passphrase).unwrap_or(Caip2::Testnet);
    let has_host = |field, raw| {
        check_endpoint_url(field, raw, chain).is_ok_and(|url| url.host_str().is_some())
    };
    if !has_host("rpc_url", primary_rpc_url) {
        return Err(unavailable(reason::PRIMARY_URL_INVALID));
    }
    if !has_host("secondary_rpc_url", secondary) {
        return Err(unavailable(reason::SECONDARY_URL_INVALID));
    }
    if same_provider_host(primary_rpc_url, secondary) {
        return Err(unavailable(reason::SAME_HOST));
    }
    Ok(secondary)
}

/// Observes the latest ledger on both endpoints and binds the pair.
///
/// Both endpoint identities complete before either height request starts.
/// The two height requests run concurrently under the same deadline, that of
/// `request.budget`. Each witness call checks both identities once. Each
/// repeated acquisition replaces both heights and their receipt times. A
/// stale or skewed pair permits another acquisition while the count and
/// deadline allow it. [`MAX_PAIR_ACQUISITIONS`] bounds the total number of
/// pairs. The accepted pair passes every identity, height, skew, and
/// freshness check.
///
/// Signing refuses when it cannot obtain fresh, agreeing ledger observations
/// within the pre submit deadline. Persistent disagreement keeps the skew
/// refusal. Persistent staleness keeps the unavailable refusal. Nothing is
/// signed. A deadline that prevents another acquisition preserves the
/// rejected pair's refusal. Every other refusal ends the call without
/// another pair.
///
/// # Errors
///
/// - [`SaError::MainnetWriteForbidden`] when an endpoint reports the mainnet
///   passphrase.
/// - [`SaError::LedgerWitnessUnavailable`] when an endpoint cannot be read in
///   time, serves another network, or shares the primary's host, when the
///   last pair read is stale, or when the deadline elapses before a pair is
///   read.
/// - [`SaError::LedgerWitnessMismatch`] when a height is out of bounds, the
///   endpoints identify different chains, or the last pair read differs by
///   more than [`MAX_SIGNING_LEDGER_SKEW`].
pub(crate) async fn witness_signing_ledger(
    request: &WitnessRequest<'_>,
) -> Result<WitnessedLedgerBound, SaError> {
    let secondary = StellarRpcClient::new(request.secondary_rpc_url)
        .map_err(|_| unavailable(reason::SECONDARY_CLIENT))?;
    let deadline = request.budget.deadline;
    let (primary_prepared, secondary_prepared) = tokio::join!(
        request
            .primary
            .prepare_signing_ledger_observation(request.network_passphrase, deadline),
        secondary.prepare_signing_ledger_observation(request.network_passphrase, deadline),
    );
    let primary = primary_prepared.map_err(|error| {
        observation_refusal(
            &error,
            reason::PRIMARY_WRONG_NETWORK,
            reason::PRIMARY_UNREADABLE,
        )
    })?;
    let secondary = secondary_prepared.map_err(|error| {
        observation_refusal(
            &error,
            reason::SECONDARY_WRONG_NETWORK,
            reason::SECONDARY_UNREADABLE,
        )
    })?;
    let bound = acquire_fresh_pair(request.budget, || read_pair(&primary, &secondary)).await?;
    debug!(
        primary_ledger = bound.primary.ledger,
        secondary_ledger = bound.secondary.ledger,
        primary = %bound.primary.authority,
        secondary = %bound.secondary.authority,
        chain = bound.chain_id.map_or("unnamed", Caip2::caip2_str),
        "ledger witness accepted",
    );
    Ok(bound)
}

/// Runs `acquire` until it returns a fresh pair, at most
/// [`MAX_PAIR_ACQUISITIONS`] times, and only while `budget`'s deadline has
/// not passed.
///
/// A stale or skewed pair permits another acquisition; every other refusal
/// returns at once. When the count or the deadline stops the loop after a
/// rejected pair, that pair's own refusal returns: the skew mismatch or the
/// stale unavailable refusal. The deadline is checked only before an
/// acquisition starts; a fresh pair that arrives is accepted.
async fn acquire_fresh_pair<F, Fut>(
    budget: PreSubmitBudget,
    mut acquire: F,
) -> Result<WitnessedLedgerBound, SaError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<WitnessedLedgerBound, PairRefusal>>,
{
    let mut rejected: Option<RejectedPair> = None;
    for attempt in 1..=MAX_PAIR_ACQUISITIONS {
        let now = Instant::now();
        if now >= budget.deadline {
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
                remaining_ms = millis_between(now, budget.deadline),
                primary = %previous.primary.authority,
                secondary = %previous.secondary.authority,
                "ledger witness reads the pair again",
            );
        }
        let pair = match acquire().await {
            Ok(bound) if !bound.is_stale(Instant::now()) => return Ok(bound),
            Ok(bound) => RejectedPair {
                trigger: Trigger::Stale,
                primary: bound.primary,
                secondary: bound.secondary,
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

/// Reads both heights through the prepared reads at the same time and binds
/// the answers.
async fn read_pair(
    primary: &PreparedSigningLedgerRead<'_>,
    secondary: &PreparedSigningLedgerRead<'_>,
) -> Result<WitnessedLedgerBound, PairRefusal> {
    let (primary_observation, secondary_observation) =
        tokio::join!(primary.read(), secondary.read());
    let primary = primary_observation.map_err(|error| {
        PairRefusal::Terminal(observation_refusal(
            &error,
            reason::PRIMARY_WRONG_NETWORK,
            reason::PRIMARY_UNREADABLE,
        ))
    })?;
    let secondary = secondary_observation.map_err(|error| {
        PairRefusal::Terminal(observation_refusal(
            &error,
            reason::SECONDARY_WRONG_NETWORK,
            reason::SECONDARY_UNREADABLE,
        ))
    })?;
    WitnessedLedgerBound::bind_classified(primary.into(), secondary.into())
}

/// Maps a failed observation to its refusal. A mainnet endpoint keeps the one
/// code every mainnet refusal carries; everything else takes a fixed reason,
/// because the wallet error can quote what the endpoint reported.
fn observation_refusal(
    error: &WalletError,
    wrong_network: &'static str,
    unreadable: &'static str,
) -> SaError {
    match error {
        WalletError::Network(NetworkError::MainnetWriteForbidden) => SaError::MainnetWriteForbidden,
        WalletError::Network(NetworkError::EndpointNetworkMismatch { .. }) => {
            unavailable(wrong_network)
        }
        _ => unavailable(unreadable),
    }
}

/// A signer whose public key was read before the last witness check.
///
/// A key lookup can reach a hardware device or a keyring and take any time.
/// A signing path reads every key it needs into this wrapper before it checks
/// the pair for the last time with [`WitnessedLedgerBound::ensure_fresh`], so
/// no lookup lies between that check and the first signature:
/// [`Signer::public_key`] answers from the stored key without reaching the
/// wrapped signer, and every signing method forwards to it.
pub(crate) struct ResolvedKeySigner<'a> {
    inner: &'a (dyn Signer + Send + Sync),
    public_key: stellar_strkey::ed25519::PublicKey,
}

impl<'a> ResolvedKeySigner<'a> {
    /// Wraps `inner` with `public_key`, a key already read from it.
    pub(crate) fn with_key(
        inner: &'a (dyn Signer + Send + Sync),
        public_key: stellar_strkey::ed25519::PublicKey,
    ) -> Self {
        Self { inner, public_key }
    }

    /// Reads the public key of `inner` once and wraps it.
    ///
    /// # Errors
    ///
    /// The error of [`Signer::public_key`] on `inner`.
    pub(crate) async fn resolve(
        inner: &'a (dyn Signer + Send + Sync),
    ) -> Result<Self, WalletError> {
        let public_key = inner.public_key().await?;
        Ok(Self::with_key(inner, public_key))
    }
}

#[async_trait]
impl Signer for ResolvedKeySigner<'_> {
    async fn sign_tx_payload(&self, payload: &TxSigningPayload) -> Result<[u8; 64], WalletError> {
        self.inner.sign_tx_payload(payload).await
    }

    async fn sign_auth_digest(
        &self,
        digest: &SmartAccountAuthDigest,
    ) -> Result<[u8; 64], WalletError> {
        self.inner.sign_auth_digest(digest).await
    }

    async fn sign_soroban_address_auth_payload(
        &self,
        payload: &SorobanAuthPayload,
    ) -> Result<[u8; 64], WalletError> {
        self.inner.sign_soroban_address_auth_payload(payload).await
    }

    async fn sign_message(&self, payload: &MessagePayload) -> Result<[u8; 64], WalletError> {
        self.inner.sign_message(payload).await
    }

    async fn sign_webauthn_assertion(
        &self,
        auth_digest: &SmartAccountAuthDigest,
        credential_id: &[u8],
    ) -> Result<WebAuthnAssertion, WalletError> {
        self.inner
            .sign_webauthn_assertion(auth_digest, credential_id)
            .await
    }

    async fn public_key(&self) -> Result<stellar_strkey::ed25519::PublicKey, WalletError> {
        Ok(self.public_key)
    }
}

/// The expiry [`AUTH_VALIDITY_LEDGERS`] beyond `lower`.
fn expiry_beyond(lower: u32) -> Result<u32, SaError> {
    lower
        .checked_add(AUTH_VALIDITY_LEDGERS)
        .ok_or_else(|| mismatch(reason::EXPIRY_OVERFLOW))
}

fn unavailable(reason: &'static str) -> SaError {
    SaError::LedgerWitnessUnavailable { reason }
}

fn mismatch(reason: &'static str) -> SaError {
    SaError::LedgerWitnessMismatch { reason }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test-only")]
    #![allow(clippy::panic, reason = "test-only: panics are the failure mode")]

    use std::cell::Cell;
    use std::sync::{Arc, Mutex};

    use stellar_agent_core::error::ReportedPassphrase;
    use stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE;
    use stellar_agent_test_support::second_loopback_host;
    use stellar_agent_test_support::signed_envelope::get_network_result;
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    use super::*;

    /// A network whose passphrase names neither testnet nor mainnet.
    const FUTURENET_PASSPHRASE: &str = "Test SDF Future Network ; October 2022";

    /// The highest height `validate_latest_ledger` admits.
    const LEDGER_CEILING: u32 = u32::MAX - AUTH_VALIDITY_LEDGERS - 1_000_000;

    const PRIMARY: &str = "https://primary.example";
    const SECONDARY: &str = "https://secondary.example";

    fn observed_at(ledger: u32, authority: &str, observed_at: Instant) -> ObservedLedger {
        ObservedLedger {
            ledger,
            authority: authority.to_owned(),
            chain_id: Some(Caip2::Testnet),
            observed_at,
        }
    }

    fn pair(primary: u32, secondary: u32) -> Result<WitnessedLedgerBound, SaError> {
        let now = Instant::now();
        WitnessedLedgerBound::bind(
            observed_at(primary, PRIMARY, now),
            observed_at(secondary, SECONDARY, now),
        )
    }

    /// A pair whose observations are `age` old.
    fn aged_pair(age: Duration) -> WitnessedLedgerBound {
        let then = Instant::now().checked_sub(age).unwrap();
        WitnessedLedgerBound::bind(
            observed_at(1000, PRIMARY, then),
            observed_at(1000, SECONDARY, then),
        )
        .unwrap()
    }

    fn reason_of(error: &SaError) -> &'static str {
        match error {
            SaError::LedgerWitnessUnavailable { reason }
            | SaError::LedgerWitnessMismatch { reason } => reason,
            other => panic!("not a witness refusal: {other:?}"),
        }
    }

    fn budget(left: Duration) -> PreSubmitBudget {
        PreSubmitBudget {
            deadline: Instant::now().checked_add(left).unwrap(),
            total: left,
        }
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
            assert_eq!(bound.higher(), primary.max(secondary));
            assert_eq!(
                bound.signature_expiration_ledger().unwrap(),
                primary.min(secondary) + AUTH_VALIDITY_LEDGERS
            );
        }
    }

    #[test]
    fn a_pair_beyond_the_tolerance_refuses_in_either_order() {
        for (primary, secondary) in [(1000, 1003), (1003, 1000), (1_000_000, 1000)] {
            let error = pair(primary, secondary).unwrap_err();
            assert_eq!(error.wire_code(), "simulation.divergence.ledger_skew");
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
            assert_eq!(error.wire_code(), "simulation.divergence.ledger_skew");
            assert_eq!(reason_of(&error), reason::HEIGHT_OUT_OF_BOUNDS);
        }
        pair(LEDGER_CEILING, LEDGER_CEILING).unwrap();
    }

    #[test]
    fn the_expiry_addition_refuses_on_overflow() {
        assert_eq!(
            expiry_beyond(u32::MAX - AUTH_VALIDITY_LEDGERS).unwrap(),
            u32::MAX
        );
        let error = expiry_beyond(u32::MAX - AUTH_VALIDITY_LEDGERS + 1).unwrap_err();
        assert_eq!(error.wire_code(), "simulation.divergence.ledger_skew");
        assert_eq!(reason_of(&error), reason::EXPIRY_OVERFLOW);
    }

    #[test]
    fn observations_of_different_chains_refuse() {
        let now = Instant::now();
        let mut secondary = observed_at(1000, SECONDARY, now);
        secondary.chain_id = None;
        let error =
            WitnessedLedgerBound::bind(observed_at(1000, PRIMARY, now), secondary).unwrap_err();
        assert_eq!(error.wire_code(), "simulation.divergence.ledger_skew");
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
            let error = WitnessedLedgerBound::bind(
                observed_at(1000, PRIMARY, now),
                observed_at(1000, secondary, now),
            )
            .unwrap_err();
            assert_eq!(
                error.wire_code(),
                "smart_account.ledger_witness_unavailable",
                "{secondary}"
            );
            assert_eq!(reason_of(&error), reason::SAME_HOST);
        }
    }

    #[test]
    fn a_pair_is_stale_only_past_the_age_limit() {
        let now = Instant::now();
        let bound = pair(1000, 1000).unwrap();
        let oldest = bound.primary.observed_at.min(bound.secondary.observed_at);
        assert!(!bound.is_stale(oldest.checked_add(MAX_OBSERVATION_AGE).unwrap()));
        assert!(
            bound.is_stale(
                oldest
                    .checked_add(MAX_OBSERVATION_AGE + Duration::from_millis(1))
                    .unwrap()
            )
        );
        assert!(!bound.is_stale(now));
    }

    #[test]
    fn the_older_observation_decides_staleness() {
        let now = Instant::now();
        let old = now
            .checked_sub(MAX_OBSERVATION_AGE + Duration::from_secs(1))
            .unwrap();
        for (primary_at, secondary_at) in [(old, now), (now, old)] {
            let bound = WitnessedLedgerBound::bind(
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
            .ensure_fresh(budget(Duration::from_secs(5)))
            .unwrap();
    }

    #[test]
    fn an_elapsed_deadline_refuses_signing() {
        let error = pair(1000, 1000)
            .unwrap()
            .ensure_fresh(budget(Duration::ZERO))
            .unwrap_err();
        assert_eq!(
            error.wire_code(),
            "smart_account.ledger_witness_unavailable"
        );
        assert_eq!(reason_of(&error), reason::DEADLINE_ELAPSED);
    }

    #[test]
    fn a_stale_pair_refuses_signing() {
        let error = aged_pair(MAX_OBSERVATION_AGE + Duration::from_secs(1))
            .ensure_fresh(budget(Duration::from_secs(5)))
            .unwrap_err();
        assert_eq!(
            error.wire_code(),
            "smart_account.ledger_witness_unavailable"
        );
        assert_eq!(reason_of(&error), reason::STALE);
    }

    /// A pair as the acquisition loop receives it.
    fn classified(primary: u32, secondary: u32) -> Result<WitnessedLedgerBound, PairRefusal> {
        let now = Instant::now();
        WitnessedLedgerBound::bind_classified(
            observed_at(primary, PRIMARY, now),
            observed_at(secondary, SECONDARY, now),
        )
    }

    /// An otherwise valid pair that is stale on arrival.
    fn stale() -> Result<WitnessedLedgerBound, PairRefusal> {
        Ok(aged_pair(MAX_OBSERVATION_AGE + Duration::from_secs(1)))
    }

    /// A budget no acquisition test exhausts.
    fn ample() -> PreSubmitBudget {
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
            (bound.lower(), bound.higher()),
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
            error.wire_code(),
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
        assert_eq!(error.wire_code(), "simulation.divergence.ledger_skew");
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
            assert_eq!((bound.lower(), bound.higher()), (1002, 1003), "{first:?}");
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
        assert_eq!((bound.lower(), bound.higher()), (1010, 1011));
    }

    /// Each refusal other than skew and staleness ends the acquisition on the
    /// pair that produced it, with its own reason and code.
    #[tokio::test]
    async fn terminal_pair_failures_do_not_retry() {
        let now = Instant::now();
        let mut other_chain = observed_at(1000, SECONDARY, now);
        other_chain.chain_id = None;
        let cases = [
            (
                "invalid height",
                WitnessedLedgerBound::bind_classified(
                    observed_at(0, PRIMARY, now),
                    observed_at(1000, SECONDARY, now),
                ),
                reason::HEIGHT_OUT_OF_BOUNDS,
                "simulation.divergence.ledger_skew",
            ),
            (
                "chain mismatch",
                WitnessedLedgerBound::bind_classified(observed_at(1000, PRIMARY, now), other_chain),
                reason::CHAIN,
                "simulation.divergence.ledger_skew",
            ),
            (
                "same host",
                WitnessedLedgerBound::bind_classified(
                    observed_at(1000, PRIMARY, now),
                    observed_at(1000, "https://primary.example:8443", now),
                ),
                reason::SAME_HOST,
                "smart_account.ledger_witness_unavailable",
            ),
        ];
        // Every case is judged before the test fails, so a failure names each
        // case that broke.
        let mut broken = Vec::new();
        let mut judge = |case: &str,
                         result: Result<WitnessedLedgerBound, SaError>,
                         expected,
                         code,
                         pairs: Vec<usize>| {
            match result {
                Ok(_) => broken.push(format!("{case}: a pair bound")),
                Err(error) => {
                    if reason_of(&error) != expected || error.wire_code() != code {
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
            error.wire_code(),
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
            error.wire_code(),
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
            matches!(error, SaError::LedgerWitnessMismatch { .. }),
            "{error:?}"
        );
        assert_eq!(error.wire_code(), "simulation.divergence.ledger_skew");
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
        assert_eq!((bound.primary.ledger, bound.secondary.ledger), (1003, 1004));
        assert_eq!(bound.signature_expiration_ledger().unwrap(), 1103);
    }

    /// A pair whose observations arrived `primary_age` and `secondary_age`
    /// before now.
    fn classified_aged(
        primary: u32,
        secondary: u32,
        primary_age: Duration,
        secondary_age: Duration,
    ) -> Result<WitnessedLedgerBound, PairRefusal> {
        let now = Instant::now();
        WitnessedLedgerBound::bind_classified(
            observed_at(primary, PRIMARY, now.checked_sub(primary_age).unwrap()),
            observed_at(
                secondary,
                SECONDARY,
                now.checked_sub(secondary_age).unwrap(),
            ),
        )
    }

    /// Each pair read again announces itself once, after the pair it
    /// replaces, with the trigger, the discarded heights, their ages, the
    /// remaining budget, and the redacted authorities.
    #[test]
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
    ) -> Result<WitnessedLedgerBound, SaError> {
        witness_signing_ledger(&WitnessRequest {
            primary,
            secondary_rpc_url,
            network_passphrase: TESTNET_PASSPHRASE,
            budget: budget(WITNESS_DEADLINE),
        })
        .await
    }

    /// One witness call with `primary` as the primary and `secondary` on a
    /// host apart from it.
    async fn witness(
        primary: &Endpoint,
        secondary: &Endpoint,
    ) -> Result<WitnessedLedgerBound, SaError> {
        let client = StellarRpcClient::new(&primary.server.uri()).unwrap();
        witness_through(&client, &second_loopback_host(&secondary.server.uri())).await
    }

    /// No height request starts before both identities have been answered,
    /// whichever identity is slow, and the two heights are in flight at the
    /// same time.
    #[tokio::test]
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
    async fn every_reread_replaces_both_heights() {
        let primary = Endpoint::start(Script::heights(vec![Height::At(1000)])).await;
        let secondary = Endpoint::start(Script::heights(vec![
            Height::At(1003),
            Height::At(1003),
            Height::At(1002),
        ]))
        .await;

        let bound = witness(&primary, &secondary).await.unwrap();

        assert_eq!((bound.lower(), bound.higher()), (1000, 1002));
        assert_eq!(primary.count("getNetwork"), 1);
        assert_eq!(secondary.count("getNetwork"), 1);
        assert_eq!(primary.count("getLatestLedger"), 3);
        assert_eq!(secondary.count("getLatestLedger"), 3);
    }

    /// A second witness call checks both identities again. A refused
    /// identity, of another network or unreadable, is asked once and starts
    /// no height on either endpoint.
    #[tokio::test]
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
                error.wire_code(),
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
    fn a_simulated_height_is_checked_against_the_range_of_the_pair() {
        let bound = pair(1000, 1002).unwrap();
        for inside in [998, 1000, 1002, 1004] {
            bound.check_simulation_height(inside).unwrap();
        }
        for outside in [997, 1005, 1_000_000] {
            let error = bound.check_simulation_height(outside).unwrap_err();
            assert_eq!(error.wire_code(), "simulation.divergence.ledger_skew");
            assert_eq!(reason_of(&error), reason::SIMULATED_HEIGHT);
        }
    }

    #[test]
    fn a_usable_secondary_passes_the_local_check() {
        assert_eq!(
            checked_secondary_rpc_url(PRIMARY, Some(SECONDARY), TESTNET_PASSPHRASE).unwrap(),
            SECONDARY
        );
    }

    #[test]
    fn an_unusable_secondary_refuses_locally_with_its_fixed_reason() {
        for (primary, secondary, expected) in [
            (PRIMARY, None, reason::SECONDARY_ABSENT),
            ("not a url", Some(SECONDARY), reason::PRIMARY_URL_INVALID),
            (PRIMARY, Some("not a url"), reason::SECONDARY_URL_INVALID),
            (
                PRIMARY,
                Some("ftp://other.example"),
                reason::SECONDARY_URL_INVALID,
            ),
            (PRIMARY, Some(PRIMARY), reason::SAME_HOST),
            (
                PRIMARY,
                Some("https://PRIMARY.example/rpc"),
                reason::SAME_HOST,
            ),
            (
                PRIMARY,
                Some("https://primary.example:8443"),
                reason::SAME_HOST,
            ),
            (PRIMARY, Some("http://primary.example."), reason::SAME_HOST),
        ] {
            let error =
                checked_secondary_rpc_url(primary, secondary, TESTNET_PASSPHRASE).unwrap_err();
            assert_eq!(
                error.wire_code(),
                "smart_account.ledger_witness_unavailable",
                "{secondary:?}"
            );
            assert_eq!(reason_of(&error), expected, "{secondary:?}");
        }
    }

    #[test]
    fn a_refusal_never_echoes_the_endpoint() {
        let secret = "SENTINEL-CREDENTIAL";
        let secondary = format!("https://user:{secret}@primary.example/{secret}?k={secret}");
        let error =
            checked_secondary_rpc_url(PRIMARY, Some(&secondary), TESTNET_PASSPHRASE).unwrap_err();
        assert!(!error.to_string().contains(secret), "{error}");
        assert!(!format!("{error:?}").contains(secret), "{error:?}");
    }

    #[test]
    fn a_failed_observation_maps_to_its_refusal() {
        let mismatch = WalletError::Network(NetworkError::EndpointNetworkMismatch {
            expected: "SENTINEL-EXPECTED".to_owned(),
            server: ReportedPassphrase::from_reported("SENTINEL-REPORTED"),
        });
        let refusal = observation_refusal(
            &mismatch,
            reason::SECONDARY_WRONG_NETWORK,
            reason::SECONDARY_UNREADABLE,
        );
        assert_eq!(reason_of(&refusal), reason::SECONDARY_WRONG_NETWORK);
        assert!(!refusal.to_string().contains("SENTINEL"), "{refusal}");

        let mainnet = WalletError::Network(NetworkError::MainnetWriteForbidden);
        assert!(matches!(
            observation_refusal(
                &mainnet,
                reason::SECONDARY_WRONG_NETWORK,
                reason::SECONDARY_UNREADABLE
            ),
            SaError::MainnetWriteForbidden
        ));
    }
}
