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

#[cfg(test)]
use std::time::Duration;

use async_trait::async_trait;
use stellar_agent_core::error::WalletError;
#[cfg(test)]
use stellar_agent_core::profile::caip2::Caip2;
use stellar_agent_network::signing::ledger_witness::{LedgerWitnessCapability, LedgerWitnessError};
use stellar_agent_network::signing::{
    MessagePayload, Signer, SmartAccountAuthDigest, SorobanAuthPayload, TxSigningPayload,
};
use stellar_agent_network::{StellarRpcClient, WebAuthnAssertion};
use tokio::time::Instant;

use crate::SaError;
use crate::managers::auth_entry::PreSubmitBudget;
use crate::managers::rules::AUTH_VALIDITY_LEDGERS;

/// Largest difference, in ledgers and in either order, between the primary's
/// and the secondary's latest ledger that a signing path accepts.
///
/// Mirrors the size of the oracle lag tolerance `MAX_ORACLE_LAG_LEDGERS` of
/// `stellar_agent_network::cross_check::soroban`. That constant is private and
/// asymmetric: the primary may lead by it, and an oracle ahead is bounded by
/// expiry alone. This one is symmetric, because either endpoint here can be
/// the dishonest one.
pub use stellar_agent_network::signing::ledger_witness::MAX_SIGNING_LEDGER_SKEW;

/// Longest age of an observation a signature may rest on: two ledger closes
/// at the network's five-second cadence, the span the skew tolerance admits.
#[cfg(test)]
pub(crate) use stellar_agent_network::signing::ledger_witness::MAX_OBSERVATION_AGE;

/// The fixed reason of a refusal: `LedgerWitnessUnavailable` or
/// `LedgerWitnessMismatch` never echoes endpoint input, which can hold a
/// credential.
mod reason {
    #[cfg(test)]
    pub(super) const SECONDARY_ABSENT: &str = "no secondary RPC endpoint is configured";
    #[cfg(test)]
    pub(super) const PRIMARY_URL_INVALID: &str = "the primary RPC URL is not a usable endpoint URL";
    #[cfg(test)]
    pub(super) const SECONDARY_URL_INVALID: &str =
        "the secondary RPC URL is not a usable endpoint URL";
    #[cfg(test)]
    pub(super) const SAME_HOST: &str =
        "no secondary RPC endpoint on a host other than the primary's is configured";
    pub(super) const SECONDARY_CLIENT: &str = "the secondary RPC client could not be built";
    #[cfg(test)]
    pub(super) const SECONDARY_WRONG_NETWORK: &str =
        "the secondary RPC endpoint serves another network";
    pub(super) const STALE: &str = "the ledger observations are stale";
    pub(super) const DEADLINE_ELAPSED: &str = "the pre-submit deadline elapsed";
    #[cfg(test)]
    pub(super) const SKEW: &str = "the endpoints' latest ledgers differ by more than the tolerance";
    pub(super) const SIMULATED_HEIGHT: &str =
        "the simulated ledger height disagrees with the ledger observations";
    pub(super) const EXPIRY_OVERFLOW: &str = "the signature expiration ledger overflows";
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
    capability: LedgerWitnessCapability,
}

impl WitnessedLedgerBound {
    /// Returns the acquired capability for durable progress.
    pub(crate) fn capability(&self) -> LedgerWitnessCapability {
        self.capability.clone()
    }

    /// The lower member of the pair: the height a limit on an authorization
    /// is measured from.
    pub(crate) fn lower(&self) -> u32 {
        self.capability.lower()
    }

    /// The higher member of the pair: the height an authorization must still
    /// be valid at.
    pub(crate) fn higher(&self) -> u32 {
        self.capability.upper()
    }

    /// The expiry every signature of this attempt carries.
    ///
    /// # Errors
    ///
    /// [`SaError::LedgerWitnessMismatch`] when the sum overflows.
    pub(crate) fn signature_expiration_ledger(&self) -> Result<u32, SaError> {
        expiry_beyond(self.lower())
    }

    /// Whether the older observation exceeds the network freshness limit at
    /// `now`.
    pub(crate) fn is_stale(&self, now: Instant) -> bool {
        self.capability.is_stale(now)
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
    stellar_agent_network::signing::ledger_witness::checked_secondary_rpc_url(
        primary_rpc_url,
        secondary_rpc_url,
        network_passphrase,
    )
    .map_err(map_witness_error)
}

/// Observes the latest ledger on both endpoints and binds the pair.
///
/// Both endpoint identities complete before either height request starts.
/// The two height requests run concurrently under the same deadline, that of
/// `request.budget`. Each witness call checks both identities once. Each
/// repeated acquisition replaces both heights and their receipt times. A
/// stale or skewed pair permits another acquisition while the count and
/// deadline allow it. At most three pairs are read. The accepted pair passes
/// every identity, height, skew, and freshness check.
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
    let capability = LedgerWitnessCapability::acquire(
        request.primary,
        &secondary,
        request.network_passphrase,
        request.budget.deadline,
    )
    .await
    .map_err(map_witness_error)?;
    Ok(WitnessedLedgerBound { capability })
}

fn map_witness_error(error: LedgerWitnessError) -> SaError {
    match error {
        LedgerWitnessError::Unavailable { reason } => unavailable(reason),
        LedgerWitnessError::Mismatch { reason } => mismatch(reason),
        LedgerWitnessError::MainnetWriteForbidden => SaError::MainnetWriteForbidden,
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

    use stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE;

    use super::*;

    const PRIMARY: &str = "https://primary.example";
    const SECONDARY: &str = "https://secondary.example";

    fn pair(primary: u32, secondary: u32) -> Result<WitnessedLedgerBound, SaError> {
        pair_at(primary, secondary, Instant::now())
    }

    fn pair_at(primary: u32, secondary: u32, at: Instant) -> Result<WitnessedLedgerBound, SaError> {
        LedgerWitnessCapability::for_test(
            stellar_agent_network::policy_state::ChainScope::for_chain(Caip2::Testnet),
            [PRIMARY, SECONDARY],
            [primary, secondary],
            [at, at],
            [0, 0],
            Instant::now() + Duration::from_secs(3600),
        )
        .map(|capability| WitnessedLedgerBound { capability })
        .map_err(map_witness_error)
    }

    fn aged_pair(age: Duration) -> WitnessedLedgerBound {
        pair_at(1000, 1000, Instant::now().checked_sub(age).unwrap()).unwrap()
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
        let refusal = map_witness_error(LedgerWitnessError::Unavailable {
            reason: reason::SECONDARY_WRONG_NETWORK,
        });
        assert_eq!(reason_of(&refusal), reason::SECONDARY_WRONG_NETWORK);
        assert_eq!(
            refusal.wire_code(),
            "smart_account.ledger_witness_unavailable"
        );
        let refusal = map_witness_error(LedgerWitnessError::Mismatch {
            reason: reason::SKEW,
        });
        assert_eq!(reason_of(&refusal), reason::SKEW);
        assert_eq!(refusal.wire_code(), "simulation.divergence.ledger_skew");
        assert!(matches!(
            map_witness_error(LedgerWitnessError::MainnetWriteForbidden),
            SaError::MainnetWriteForbidden
        ));
    }
}
