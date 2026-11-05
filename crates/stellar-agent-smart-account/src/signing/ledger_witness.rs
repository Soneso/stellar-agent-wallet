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
use stellar_agent_network::{SigningLedgerObservation, StellarRpcClient, WebAuthnAssertion};
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
const MAX_OBSERVATION_AGE: Duration = Duration::from_secs(10);

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

impl WitnessedLedgerBound {
    /// Binds a pair of observations, or refuses it.
    fn bind(primary: ObservedLedger, secondary: ObservedLedger) -> Result<Self, SaError> {
        for observation in [&primary, &secondary] {
            validate_latest_ledger(observation.ledger)
                .map_err(|_| mismatch(reason::HEIGHT_OUT_OF_BOUNDS))?;
        }
        // Both observations pass `endpoint_identity(expected_passphrase)` with
        // the passphrase of one request, and `bind` is the one constructor of
        // a bound. The check refuses a mixed pair whichever caller binds it.
        if primary.chain_id != secondary.chain_id {
            return Err(mismatch(reason::CHAIN));
        }
        if same_provider_host(&primary.authority, &secondary.authority) {
            return Err(unavailable(reason::SAME_HOST));
        }
        if primary.ledger.abs_diff(secondary.ledger) > MAX_SIGNING_LEDGER_SKEW {
            return Err(mismatch(reason::SKEW));
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
/// Both endpoints are asked at the same time and under the one deadline of
/// `request.budget`. A pair that comes back already stale is read again as a
/// pair: a fresh height is never combined with a retained one.
///
/// # Errors
///
/// - [`SaError::MainnetWriteForbidden`] when an endpoint reports the mainnet
///   passphrase.
/// - [`SaError::LedgerWitnessUnavailable`] when an endpoint cannot be read in
///   time, serves another network, or stays stale.
/// - [`SaError::LedgerWitnessMismatch`] when a height is out of bounds or the
///   pair differs by more than [`MAX_SIGNING_LEDGER_SKEW`].
pub(crate) async fn witness_signing_ledger(
    request: &WitnessRequest<'_>,
) -> Result<WitnessedLedgerBound, SaError> {
    let secondary = StellarRpcClient::new(request.secondary_rpc_url)
        .map_err(|_| unavailable(reason::SECONDARY_CLIENT))?;
    let bound = acquire_fresh_pair(|| observe_pair(request, &secondary)).await?;
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

/// Runs `acquire`, and once more when its pair is stale on arrival.
async fn acquire_fresh_pair<F, Fut>(mut acquire: F) -> Result<WitnessedLedgerBound, SaError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<WitnessedLedgerBound, SaError>>,
{
    let bound = acquire().await?;
    if !bound.is_stale(Instant::now()) {
        return Ok(bound);
    }
    let bound = acquire().await?;
    if bound.is_stale(Instant::now()) {
        return Err(unavailable(reason::STALE));
    }
    Ok(bound)
}

/// Reads both endpoints once and binds the answers.
async fn observe_pair(
    request: &WitnessRequest<'_>,
    secondary: &StellarRpcClient,
) -> Result<WitnessedLedgerBound, SaError> {
    let deadline = request.budget.deadline;
    let (primary_observation, secondary_observation) = tokio::join!(
        request
            .primary
            .signing_ledger_observation(request.network_passphrase, deadline),
        secondary.signing_ledger_observation(request.network_passphrase, deadline),
    );
    let primary = primary_observation.map_err(|error| {
        observation_refusal(
            &error,
            reason::PRIMARY_WRONG_NETWORK,
            reason::PRIMARY_UNREADABLE,
        )
    })?;
    let secondary = secondary_observation.map_err(|error| {
        observation_refusal(
            &error,
            reason::SECONDARY_WRONG_NETWORK,
            reason::SECONDARY_UNREADABLE,
        )
    })?;
    WitnessedLedgerBound::bind(primary.into(), secondary.into())
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

    use stellar_agent_core::error::ReportedPassphrase;
    use stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE;

    use super::*;

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

    #[tokio::test]
    async fn a_fresh_pair_is_acquired_once() {
        let calls = Cell::new(0);
        acquire_fresh_pair(|| {
            calls.set(calls.get() + 1);
            async { pair(1000, 1000) }
        })
        .await
        .unwrap();
        assert_eq!(calls.get(), 1);
    }

    #[tokio::test]
    async fn a_stale_pair_is_reacquired_as_a_pair() {
        let calls = Cell::new(0);
        let bound = acquire_fresh_pair(|| {
            calls.set(calls.get() + 1);
            let attempt = calls.get();
            async move {
                if attempt == 1 {
                    Ok(aged_pair(MAX_OBSERVATION_AGE + Duration::from_secs(1)))
                } else {
                    pair(1004, 1005)
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
    async fn a_pair_stale_twice_refuses() {
        let calls = Cell::new(0);
        let error = acquire_fresh_pair(|| {
            calls.set(calls.get() + 1);
            async { Ok(aged_pair(MAX_OBSERVATION_AGE + Duration::from_secs(1))) }
        })
        .await
        .unwrap_err();
        assert_eq!(calls.get(), 2);
        assert_eq!(reason_of(&error), reason::STALE);
    }

    #[tokio::test]
    async fn a_failed_reacquisition_keeps_its_refusal() {
        let calls = Cell::new(0);
        let error = acquire_fresh_pair(|| {
            calls.set(calls.get() + 1);
            let attempt = calls.get();
            async move {
                if attempt == 1 {
                    Ok(aged_pair(MAX_OBSERVATION_AGE + Duration::from_secs(1)))
                } else {
                    pair(1000, 1003)
                }
            }
        })
        .await
        .unwrap_err();
        assert_eq!(reason_of(&error), reason::SKEW);
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
