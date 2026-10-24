//! Independent oracle witnesses for classic transaction decisions and for
//! Soroban simulations.

mod classic;
mod digest;
pub mod inputs;
mod soroban;
pub use inputs::*;

use crate::{
    client::StellarRpcClient,
    context::NetworkContext,
    redact_url_authority,
    retry::rejected_status,
    rpc_endpoint::{is_credential_error, profile_rpc_client},
};
use serde::{Deserialize, Serialize};
use std::{future::Future, time::Duration};
use stellar_agent_core::{
    audit_log::CrossCheckRecord,
    cross_check::{
        CrossCheckRequirement, CrossCheckSkip, CrossCheckValue, ThresholdSet, WitnessEntry,
        cross_check_requirement,
    },
    error::{NetworkError, WalletError, WitnessUnavailableReason as Reason},
    profile::{
        caip2::Caip2,
        schema::{Profile, ProviderRole, same_provider_host, same_provider_operator},
    },
};
use stellar_rpc_client::SimulateTransactionResponse;
use stellar_xdr::TransactionEnvelope;
use tokio::time::{Instant, sleep, timeout_at};

const WITNESS_ATTEMPT_BUDGET: Duration = Duration::from_secs(15);
const WITNESS_READ_ATTEMPTS: u32 = 3;
const WITNESS_RETRY_BACKOFF: Duration = Duration::from_secs(7);

/// Evidence of a completed comparison against an identified oracle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossCheckWitness {
    authority: String,
    oracle_ledger: u32,
    inputs_digest: [u8; 32],
    kinds: Vec<WitnessEntry>,
}

impl CrossCheckWitness {
    /// Creates synthetic evidence for tests without making an oracle request.
    #[cfg(feature = "test-helpers")]
    #[must_use]
    pub fn for_tests(
        authority: &str,
        oracle_ledger: u32,
        inputs_digest: [u8; 32],
        kinds: Vec<WitnessEntry>,
    ) -> Self {
        let mut kinds = kinds;
        kinds.sort();
        kinds.dedup();
        Self {
            authority: redact_url_authority(authority),
            oracle_ledger,
            inputs_digest,
            kinds,
        }
    }

    /// Oracle endpoint authority.
    #[must_use]
    pub fn authority(&self) -> &str {
        &self.authority
    }
    /// Ledger reported by the checked answer.
    #[must_use]
    pub fn oracle_ledger(&self) -> u32 {
        self.oracle_ledger
    }
    /// Lowercase hexadecimal SHA-256 inputs digest.
    #[must_use]
    pub fn inputs_digest_hex(&self) -> String {
        crate::submit::bytes_to_hex(&self.inputs_digest)
    }
    /// Distinct entry kinds covered by the comparison.
    #[must_use]
    pub fn kinds(&self) -> &[WitnessEntry] {
        &self.kinds
    }
    /// Bounded audit representation of this witness.
    #[must_use]
    pub fn record(&self) -> CrossCheckRecord {
        CrossCheckRecord {
            provider: self
                .authority
                .chars()
                .take(stellar_agent_core::audit_log::schema::RECORDED_STR_MAX)
                .collect(),
            ledger: self.oracle_ledger,
            inputs_digest: self.inputs_digest_hex(),
            kinds: self.kinds.clone(),
        }
    }
}

/// The result of applying the requirement rule and obtaining any required witness.
#[derive(Debug, Clone)]
pub enum CrossCheckOutcome {
    /// The oracle agrees with all supplied observations.
    Passed(CrossCheckWitness),
    /// Testnet continues without a comparison for this reason.
    Skipped(CrossCheckSkip),
    /// The value is below threshold and no memo observation requires comparison.
    NotRequired,
}

impl CrossCheckOutcome {
    /// The witness, if an oracle comparison passed.
    #[must_use]
    pub fn witness(&self) -> Option<&CrossCheckWitness> {
        match self {
            Self::Passed(witness) => Some(witness),
            _ => None,
        }
    }
    /// The operator-facing result representation.
    #[must_use]
    pub fn view(&self) -> CrossCheckView {
        let (status, reason, provider, ledger) = match self {
            Self::Passed(w) => (
                "passed",
                None,
                Some(w.authority.clone()),
                Some(w.oracle_ledger),
            ),
            Self::Skipped(reason) => (
                "skipped",
                Some(match reason {
                    CrossCheckSkip::OracleNotConfigured => "oracle_not_configured",
                    CrossCheckSkip::NoThresholdForAsset => "no_threshold_for_asset",
                }),
                None,
                None,
            ),
            Self::NotRequired => ("not_required", Some("below_threshold"), None, None),
        };
        CrossCheckView {
            status: status.to_owned(),
            reason: reason.map(str::to_owned),
            provider,
            ledger,
        }
    }
}

/// JSON and text view of a cross-check outcome.
///
/// The view owns its strings, so a result that carries it deserializes from
/// its own JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossCheckView {
    /// `passed`, `skipped`, or `not_required`.
    pub status: String,
    /// Why no comparison took place.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Redacted oracle authority when the comparison passed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// Checked oracle ledger.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ledger: Option<u32>,
}

impl CrossCheckView {
    /// Renders the outcome as one operator-facing line.
    #[must_use]
    pub fn text_line(&self) -> String {
        match (
            self.status.as_str(),
            self.reason.as_deref(),
            self.provider.as_deref(),
            self.ledger,
        ) {
            ("passed", _, Some(authority), Some(n)) => {
                format!("Cross-check: passed (oracle {authority}, ledger {n})")
            }
            ("skipped", Some("no_threshold_for_asset"), _, _) => {
                "Cross-check: skipped (no threshold for asset)".to_owned()
            }
            ("skipped", _, _, _) => "Cross-check: skipped (oracle not configured)".to_owned(),
            _ => "Cross-check: not required (below threshold)".to_owned(),
        }
    }
}

/// One oracle client and its safe endpoint authority.
pub struct OracleEndpoint {
    client: StellarRpcClient,
    authority: String,
}

impl OracleEndpoint {
    /// Builds a credential-bound oracle client without sending a request.
    ///
    /// # Errors
    /// Preserves credential refusals; classifies other construction failures as unavailable.
    pub fn from_profile(profile: &Profile) -> Result<Option<Self>, WalletError> {
        let Some(url) = &profile.oracle_provider_url else {
            return Ok(None);
        };
        let authority = redact_url_authority(url.as_str());
        let client =
            profile_rpc_client(profile, ProviderRole::Oracle, url.as_str()).map_err(|error| {
                if is_credential_error(&error) {
                    error
                } else {
                    unavailable(Reason::ClientConstruction {
                        authority: authority.clone(),
                    })
                }
            })?;
        Ok(Some(Self { client, authority }))
    }
}

#[derive(Clone, Copy)]
pub(crate) struct WitnessTiming {
    pub attempt_budget: Duration,
    pub retry_backoff: Duration,
}

fn unavailable(reason: Reason) -> WalletError {
    NetworkError::WitnessUnavailable { reason }.into()
}

fn identity_error(error: WalletError, authority: &str, chain: Caip2) -> WalletError {
    let authority = authority.to_owned();
    match error {
        WalletError::Network(NetworkError::EndpointNetworkMismatch { .. }) => {
            unavailable(Reason::IdentityNetworkMismatch { authority })
        }
        WalletError::Network(NetworkError::EndpointIdentityUnavailable { .. }) => {
            unavailable(Reason::IdentityUnavailable { authority })
        }
        WalletError::Network(NetworkError::UnsupportedProtocolVersion { .. }) => {
            unavailable(Reason::IdentityProtocolUnsupported { authority })
        }
        WalletError::Network(NetworkError::MainnetWriteForbidden) if chain != Caip2::Mainnet => {
            unavailable(Reason::IdentityNetworkMismatch { authority })
        }
        other => other,
    }
}

/// How a failed oracle read ends the attempt loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadFailure {
    /// HTTP 401 or 403: the oracle refused the credential, and the same
    /// request gets the same answer.
    Credential(u16),
    /// The request did not complete: a connection failure, a timeout, or an
    /// HTTP 429 or 5xx answer. Another attempt can succeed.
    Transport,
    /// The oracle returns an unusable answer. Examples include a body that
    /// is not JSON or exceeds the size limit, a JSON-RPC error object, a
    /// mismatched response id, or any other status. Repeating the request
    /// only spends the deadline on the same answer.
    InvalidAnswer,
}

impl ReadFailure {
    fn label(self) -> &'static str {
        match self {
            Self::Credential(_) => "credential",
            Self::Transport => "transport",
            Self::InvalidAnswer => "invalid_answer",
        }
    }
}

fn classify_read(error: &stellar_rpc_client::Error) -> ReadFailure {
    use jsonrpsee_core::{ClientError, http_helpers::HttpError};
    use jsonrpsee_http_client::transport::Error as HttpTransportError;
    if let Some(status) = rejected_status(error) {
        return match status {
            401 | 403 => ReadFailure::Credential(status),
            429 | 500..=599 => ReadFailure::Transport,
            _ => ReadFailure::InvalidAnswer,
        };
    }
    match error {
        // The HTTP transport reads the whole body before the JSON-RPC layer
        // sees it. It reports a body that is not JSON as `Malformed` and an
        // oversized body as `TooLarge`. Both indicate unusable answers.
        stellar_rpc_client::Error::JsonRpc(ClientError::Transport(source)) => {
            match source.downcast_ref::<HttpTransportError>() {
                Some(HttpTransportError::Http(HttpError::Malformed | HttpError::TooLarge)) => {
                    ReadFailure::InvalidAnswer
                }
                _ => ReadFailure::Transport,
            }
        }
        stellar_rpc_client::Error::JsonRpc(ClientError::RequestTimeout)
        | stellar_rpc_client::Error::TransactionSubmissionTimeout => ReadFailure::Transport,
        _ => ReadFailure::InvalidAnswer,
    }
}

/// Applies the requirement rule and compares the primary observations with the oracle.
///
/// # Errors
/// Refuses unavailable witnesses, credential failures, and any field disagreement before signing.
pub async fn obtain_classic_witness(
    profile: &Profile,
    context: &NetworkContext,
    value: CrossCheckValue<'_>,
    inputs: impl Into<ClassicInputs>,
    tool: &'static str,
) -> Result<CrossCheckOutcome, WalletError> {
    obtain_classic_witness_with_timing(
        profile,
        context,
        value,
        inputs.into(),
        tool,
        WitnessTiming {
            attempt_budget: WITNESS_ATTEMPT_BUDGET,
            retry_backoff: WITNESS_RETRY_BACKOFF,
        },
    )
    .await
}

pub(crate) async fn obtain_classic_witness_with_timing(
    profile: &Profile,
    context: &NetworkContext,
    value: CrossCheckValue<'_>,
    inputs: ClassicInputs,
    tool: &'static str,
    timing: WitnessTiming,
) -> Result<CrossCheckOutcome, WalletError> {
    match cross_check_requirement(
        context.chain_id,
        value,
        &ThresholdSet::from_profile(profile),
        profile.oracle_provider_url.is_some(),
        inputs.memo_check(),
    )? {
        CrossCheckRequirement::NotRequired => return Ok(CrossCheckOutcome::NotRequired),
        CrossCheckRequirement::Skipped(reason) => {
            warn_skipped(tool, reason);
            return Ok(CrossCheckOutcome::Skipped(reason));
        }
        CrossCheckRequirement::Required => {}
    }
    let oracle = required_oracle(profile, context, tool)?;
    let observations = inputs.observations()?;
    let keys = classic::keys(&observations);
    let client = &oracle.client;
    let keys = keys.as_slice();
    let answer = read_with_retries(&oracle, context, timing, tool, move || {
        client.witness_ledger_entries(keys)
    })
    .await?;
    let ledger = classic::compare_answer(&observations, keys, answer, &oracle.authority)?;
    let mut kinds: Vec<_> = observations.iter().map(|o| o.kind).collect();
    kinds.dedup();
    let inputs_digest = digest::inputs_digest(&observations)?;
    Ok(CrossCheckOutcome::Passed(CrossCheckWitness {
        authority: oracle.authority,
        oracle_ledger: ledger,
        inputs_digest,
        kinds,
    }))
}

/// Logs a skipped witness on the `policy.cross_check` target.
fn warn_skipped(tool: &'static str, reason: CrossCheckSkip) {
    tracing::warn!(target: "policy.cross_check", tool, ?reason,
        "cross-check skipped; configure the oracle and asset threshold in the profile");
}

/// Builds the oracle of a required witness and logs a shared provider.
///
/// The oracle shares the primary's provider host, or its provider record names
/// the primary's operator: the witness still runs on a second client, and the
/// WARN on the `policy.cross_check` target says that it is degraded to
/// single-RPC verification.
///
/// # Errors
/// [`OracleEndpoint::from_profile`]'s refusal, or
/// `network.witness_unavailable` when the profile names no oracle.
fn required_oracle(
    profile: &Profile,
    context: &NetworkContext,
    tool: &'static str,
) -> Result<OracleEndpoint, WalletError> {
    let oracle = OracleEndpoint::from_profile(profile)?
        .ok_or_else(|| unavailable(Reason::OracleNotConfigured))?;
    if same_provider_host(
        profile
            .oracle_provider_url
            .as_ref()
            .map_or("", |url| url.as_str()),
        &context.rpc_url,
    ) {
        tracing::warn!(target: "policy.cross_check", tool,
            "oracle_provider_url shares the provider host of rpc_url; \
             cross-check is degraded to single-RPC verification");
    }
    if let Some(providers) = &profile.providers
        && let (Some(primary), Some(oracle)) = (&providers.primary, &providers.oracle)
        && same_provider_operator(&oracle.operator, &primary.operator)
    {
        tracing::warn!(target: "policy.cross_check", tool,
            "oracle provider record names the primary's operator; cross-check is degraded \
             to single-RPC verification");
    }
    Ok(oracle)
}

/// Identifies the oracle, then runs `read` on it under the witness attempt
/// policy, and returns the first answer.
///
/// The identity check runs once, before the first read, inside the first
/// attempt's budget. Each attempt has its own deadline. A transport fault is
/// retried up to the attempt limit after the backoff; a credential refusal
/// and an unusable answer end the loop at once, and an elapsed deadline
/// refuses. The answer is returned unjudged: a comparison that disagrees
/// never repeats the read.
///
/// # Errors
/// `network.witness_unavailable` with the identity, deadline, transport, or
/// answer reason; `network.rpc_credential_refused` for HTTP 401 or 403;
/// the identity check's mainnet refusal on a mainnet profile.
async fn read_with_retries<T, F, Fut>(
    oracle: &OracleEndpoint,
    context: &NetworkContext,
    timing: WitnessTiming,
    tool: &'static str,
    mut read: F,
) -> Result<T, WalletError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, stellar_rpc_client::Error>>,
{
    let mut deadline = Instant::now() + timing.attempt_budget;
    oracle
        .client
        .endpoint_identity(context.network_passphrase(), deadline)
        .await
        .map_err(|error| identity_error(error, &oracle.authority, context.chain_id))?;
    let mut attempt = 1;
    loop {
        let response = timeout_at(deadline, read()).await.map_err(|_| {
            unavailable(Reason::DeadlineExhausted {
                authority: oracle.authority.clone(),
                seconds: timing.attempt_budget.as_secs(),
            })
        })?;
        let error = match response {
            Ok(answer) => return Ok(answer),
            Err(error) => error,
        };
        let failure = classify_read(&error);
        let status = rejected_status(&error);
        tracing::debug!(tool, authority = %oracle.authority, classification = failure.label(),
            ?status, attempt, "oracle witness read failed");
        match failure {
            ReadFailure::Credential(status) => {
                return Err(NetworkError::RpcCredentialRejected {
                    url: oracle.authority.clone(),
                    status,
                }
                .into());
            }
            ReadFailure::InvalidAnswer => {
                return Err(unavailable(Reason::InvalidAnswer {
                    authority: oracle.authority.clone(),
                }));
            }
            ReadFailure::Transport if attempt >= WITNESS_READ_ATTEMPTS => {
                return Err(unavailable(Reason::Transport {
                    authority: oracle.authority.clone(),
                    attempts: attempt,
                }));
            }
            ReadFailure::Transport => {}
        }
        sleep(timing.retry_backoff).await;
        attempt += 1;
        deadline = Instant::now() + timing.attempt_budget;
    }
}

/// The witness requirement of one Soroban payment, prepared before the
/// signer is read.
///
/// A `Required` value holds the oracle client, built from the profile without
/// a request, so a payment flow that receives it builds no client of its own.
/// The variants carry the outcome without a request where no comparison runs.
#[allow(
    clippy::large_enum_variant,
    reason = "one value per payment, built once and borrowed by the flow; a box adds an \
              allocation and no saving"
)]
pub enum SorobanCrossCheck {
    /// The value is below its threshold.
    NotRequired,
    /// Testnet continues without a comparison for this reason.
    Skipped(CrossCheckSkip),
    /// The oracle simulates the payment before it is signed.
    Required {
        /// The oracle client and its safe authority.
        oracle: OracleEndpoint,
        /// The chain and the passphrase the oracle's identity is checked
        /// against.
        context: NetworkContext,
        /// Tool name for the log events of the witness.
        tool: &'static str,
    },
}

/// The primary's simulation of one unsigned Soroban transaction, which the
/// oracle simulates again.
#[derive(Clone, Copy)]
pub struct SorobanWitnessInputs<'a> {
    /// The unsigned envelope the primary simulated.
    pub envelope: &'a TransactionEnvelope,
    /// The primary's answer. It holds exactly one result, and its
    /// `latest_ledger` is the ledger the payment's expiration derives from.
    pub primary: &'a SimulateTransactionResponse,
    /// The signature expiration ledger derived from the primary's ledger.
    pub expiration_ledger: u32,
    /// The highest minimum resource fee the flow accepts, in stroops.
    pub resource_fee_ceiling: u64,
}

impl SorobanCrossCheck {
    /// Applies the requirement rule to `value` and builds the oracle client
    /// when the witness is required, without sending a request.
    ///
    /// A skipped witness logs its reason, and a required one logs an oracle
    /// that shares the primary's provider, on the `policy.cross_check` target.
    ///
    /// # Errors
    /// The rule's mainnet refusals; `network.witness_unavailable` with
    /// `ClientConstruction` for an oracle client that cannot be built; a
    /// credential error of the oracle's provider record with its own code.
    pub fn prepare(
        profile: &Profile,
        context: &NetworkContext,
        value: CrossCheckValue<'_>,
        tool: &'static str,
    ) -> Result<Self, WalletError> {
        match cross_check_requirement(
            context.chain_id,
            value,
            &ThresholdSet::from_profile(profile),
            profile.oracle_provider_url.is_some(),
            false,
        )? {
            CrossCheckRequirement::NotRequired => Ok(Self::NotRequired),
            CrossCheckRequirement::Skipped(reason) => {
                warn_skipped(tool, reason);
                Ok(Self::Skipped(reason))
            }
            CrossCheckRequirement::Required => Ok(Self::Required {
                oracle: required_oracle(profile, context, tool)?,
                context: context.clone(),
                tool,
            }),
        }
    }

    /// Obtains the witness: the oracle simulates the same unsigned envelope,
    /// and its answer is compared with the primary's.
    ///
    /// `NotRequired` and `Skipped` return their outcome without a request.
    /// The oracle's answer is never signed and never replaces the primary's.
    ///
    /// # Errors
    /// `simulation.divergence` when the answers disagree;
    /// `network.witness_unavailable` and `network.rpc_credential_refused` as
    /// the classic witness reports them.
    pub async fn witness(
        &self,
        inputs: SorobanWitnessInputs<'_>,
    ) -> Result<CrossCheckOutcome, WalletError> {
        self.witness_with_timing(
            inputs,
            WitnessTiming {
                attempt_budget: WITNESS_ATTEMPT_BUDGET,
                retry_backoff: WITNESS_RETRY_BACKOFF,
            },
        )
        .await
    }

    pub(crate) async fn witness_with_timing(
        &self,
        inputs: SorobanWitnessInputs<'_>,
        timing: WitnessTiming,
    ) -> Result<CrossCheckOutcome, WalletError> {
        let (oracle, context, tool) = match self {
            Self::NotRequired => return Ok(CrossCheckOutcome::NotRequired),
            Self::Skipped(reason) => return Ok(CrossCheckOutcome::Skipped(*reason)),
            Self::Required {
                oracle,
                context,
                tool,
            } => (oracle, context, *tool),
        };
        let primary = soroban::Primary::decode(&inputs)?;
        let client = &oracle.client;
        let envelope = inputs.envelope;
        let answer = read_with_retries(oracle, context, timing, tool, move || {
            client.witness_simulate(envelope)
        })
        .await?;
        soroban::compare(&primary, &inputs, &answer, &oracle.authority)?;
        Ok(CrossCheckOutcome::Passed(CrossCheckWitness {
            authority: oracle.authority.clone(),
            oracle_ledger: answer.latest_ledger,
            inputs_digest: digest::soroban_inputs_digest(
                inputs.envelope,
                &primary.auth,
                inputs.primary.latest_ledger,
            )?,
            kinds: vec![WitnessEntry::SorobanSimulation],
        }))
    }
}

/// Log capture for the witness tests.
#[cfg(test)]
pub(super) mod log_capture {
    use std::future::Future;
    use tracing::instrument::WithSubscriber;

    /// Runs `future` under a fmt subscriber at `level` that writes into a
    /// buffer, and returns the output with the captured text.
    ///
    /// `tracing` caches each callsite's interest for the whole process. With
    /// one registered dispatcher, `tracing` computes a callsite's interest
    /// from the first thread that reaches it. A neighboring test without a
    /// subscriber can therefore cache the callsite as disabled before this
    /// capture. An inert dispatcher kept alive for the whole capture makes
    /// `tracing` compute every interest from the registered dispatchers, which
    /// include this capture's; the rebuild refreshes callsites cached before
    /// the capture registered.
    pub(crate) async fn capture_logs<F: Future>(
        level: tracing::Level,
        future: F,
    ) -> (F::Output, String) {
        let capture = stellar_agent_test_support::CaptureWriter::new();
        let inert = stellar_agent_test_support::inert_dispatcher();
        let dispatch = tracing::Dispatch::new(
            tracing_subscriber::fmt()
                .with_writer(capture.clone())
                .with_ansi(false)
                .without_time()
                .with_max_level(level)
                .finish(),
        );
        tracing::callsite::rebuild_interest_cache();
        let output = future.with_subscriber(dispatch).await;
        drop(inert);
        (output, capture.captured_str())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test assertions")]
    use super::*;
    #[test]
    fn skipped_without_threshold_renders_its_own_line() {
        let view = CrossCheckOutcome::Skipped(CrossCheckSkip::NoThresholdForAsset).view();
        assert_eq!(
            view.text_line(),
            "Cross-check: skipped (no threshold for asset)"
        );
        assert_eq!(
            serde_json::to_value(view).ok(),
            Some(serde_json::json!({
            "status": "skipped", "reason": "no_threshold_for_asset"}))
        );
        assert_eq!(
            CrossCheckOutcome::NotRequired.view().text_line(),
            "Cross-check: not required (below threshold)"
        );
    }
    #[test]
    fn text_line_renders_the_four_forms() {
        let passed = CrossCheckOutcome::Passed(CrossCheckWitness {
            authority: "https://oracle.example:8443".to_owned(),
            oracle_ledger: 4_242,
            inputs_digest: [0; 32],
            kinds: vec![WitnessEntry::SourceAccount],
        });
        let cases = [
            (
                passed,
                "Cross-check: passed (oracle https://oracle.example:8443, ledger 4242)",
                serde_json::json!({"status": "passed",
                    "provider": "https://oracle.example:8443", "ledger": 4_242}),
            ),
            (
                CrossCheckOutcome::Skipped(CrossCheckSkip::OracleNotConfigured),
                "Cross-check: skipped (oracle not configured)",
                serde_json::json!({"status": "skipped", "reason": "oracle_not_configured"}),
            ),
            (
                CrossCheckOutcome::Skipped(CrossCheckSkip::NoThresholdForAsset),
                "Cross-check: skipped (no threshold for asset)",
                serde_json::json!({"status": "skipped", "reason": "no_threshold_for_asset"}),
            ),
            (
                CrossCheckOutcome::NotRequired,
                "Cross-check: not required (below threshold)",
                serde_json::json!({"status": "not_required", "reason": "below_threshold"}),
            ),
        ];
        for (outcome, line, json) in cases {
            let view = outcome.view();
            assert_eq!(view.text_line(), line);
            assert_eq!(serde_json::to_value(&view).unwrap(), json);
            let back: CrossCheckView = serde_json::from_value(json).unwrap();
            assert_eq!(back, view);
            assert_eq!(back.text_line(), line);
            assert_eq!(
                outcome.witness().is_some(),
                matches!(outcome, CrossCheckOutcome::Passed(_))
            );
        }
    }

    /// Captures the WARN lines one witness decision emits on a testnet profile
    /// without an oracle.
    async fn skip_warnings(value: CrossCheckValue<'_>) -> (CrossCheckOutcome, String) {
        let profile = Profile::builder_testnet("signer", "witness", "nonce", "witness").build();
        assert!(profile.oracle_provider_url.is_none());
        let source = AccountObservation {
            account_id: stellar_strkey::ed25519::PublicKey([7; 32])
                .to_string()
                .to_string(),
            sequence: 42,
            native_balance: 100_000_000_000,
            subentry_count: 0,
            flags: None,
        };
        let (outcome, logs) = log_capture::capture_logs(
            tracing::Level::WARN,
            obtain_classic_witness(
                &profile,
                &NetworkContext::from_profile(&profile),
                value,
                CreateAccountWitnessInputs { source },
                "test_witness",
            ),
        )
        .await;
        (outcome.unwrap(), logs)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn skipped_outcome_warns_with_the_reason() {
        let text = "cross-check skipped; configure the oracle and asset threshold in the profile";
        let (outcome, logs) = skip_warnings(CrossCheckValue::Unvalued).await;
        assert!(matches!(
            outcome,
            CrossCheckOutcome::Skipped(CrossCheckSkip::OracleNotConfigured)
        ));
        assert_eq!(logs.lines().count(), 1, "{logs}");
        for expected in [
            " WARN ",
            "policy.cross_check",
            text,
            "tool=\"test_witness\"",
            "reason=OracleNotConfigured",
        ] {
            assert!(logs.contains(expected), "{expected}: {logs}");
        }
        let credit = stellar_agent_core::asset_id::CanonicalAsset::classic(
            "USD",
            &stellar_strkey::ed25519::PublicKey([9; 32]).to_string(),
        )
        .unwrap();
        let (outcome, logs) = skip_warnings(CrossCheckValue::Amount {
            asset: &credit,
            base_units: i128::MAX,
        })
        .await;
        assert!(matches!(
            outcome,
            CrossCheckOutcome::Skipped(CrossCheckSkip::NoThresholdForAsset)
        ));
        assert_eq!(logs.lines().count(), 1, "{logs}");
        for expected in ["policy.cross_check", text, "reason=NoThresholdForAsset"] {
            assert!(logs.contains(expected), "{expected}: {logs}");
        }
        let (outcome, logs) = skip_warnings(CrossCheckValue::Amount {
            asset: &stellar_agent_core::asset_id::CanonicalAsset::Native,
            base_units: 1,
        })
        .await;
        assert!(matches!(outcome, CrossCheckOutcome::NotRequired));
        assert!(logs.is_empty(), "{logs}");
    }

    fn transport_error(
        error: jsonrpsee_http_client::transport::Error,
    ) -> stellar_rpc_client::Error {
        stellar_rpc_client::Error::JsonRpc(jsonrpsee_core::ClientError::Transport(Box::new(error)))
    }

    #[test]
    fn read_classification_separates_answers_from_transport_faults() {
        use jsonrpsee_core::http_helpers::HttpError;
        use jsonrpsee_http_client::transport::Error as HttpTransportError;
        let rejected = |status_code| transport_error(HttpTransportError::Rejected { status_code });
        let cases = [
            (rejected(401), ReadFailure::Credential(401)),
            (rejected(403), ReadFailure::Credential(403)),
            (rejected(429), ReadFailure::Transport),
            (rejected(500), ReadFailure::Transport),
            (rejected(503), ReadFailure::Transport),
            (rejected(404), ReadFailure::InvalidAnswer),
            (
                transport_error(HttpTransportError::Http(HttpError::Malformed)),
                ReadFailure::InvalidAnswer,
            ),
            (
                transport_error(HttpTransportError::Http(HttpError::TooLarge)),
                ReadFailure::InvalidAnswer,
            ),
            (
                transport_error(HttpTransportError::Http(HttpError::Stream(Box::new(
                    std::io::Error::from(std::io::ErrorKind::ConnectionRefused),
                )))),
                ReadFailure::Transport,
            ),
            (
                stellar_rpc_client::Error::JsonRpc(jsonrpsee_core::ClientError::RequestTimeout),
                ReadFailure::Transport,
            ),
            (
                stellar_rpc_client::Error::JsonRpc(jsonrpsee_core::ClientError::ParseError(
                    serde_json::from_str::<serde_json::Value>("hostile-body").unwrap_err(),
                )),
                ReadFailure::InvalidAnswer,
            ),
            (
                stellar_rpc_client::Error::InvalidResponse,
                ReadFailure::InvalidAnswer,
            ),
        ];
        for (error, expected) in cases {
            assert_eq!(classify_read(&error), expected, "{error:?}");
        }
    }

    #[test]
    fn unsupported_identity_protocol_maps_to_witness_unavailable() {
        let error = identity_error(
            NetworkError::UnsupportedProtocolVersion {
                protocol_version: 99,
                supported_min: 1,
                supported_max: 28,
            }
            .into(),
            "https://oracle.example",
            Caip2::Testnet,
        );
        assert!(matches!(
            error,
            WalletError::Network(NetworkError::WitnessUnavailable {
                reason: Reason::IdentityProtocolUnsupported { .. }
            })
        ));
        let error = identity_error(
            NetworkError::MainnetWriteForbidden.into(),
            "https://oracle.example",
            Caip2::Mainnet,
        );
        assert!(matches!(
            error,
            WalletError::Network(NetworkError::MainnetWriteForbidden)
        ));
    }
}
