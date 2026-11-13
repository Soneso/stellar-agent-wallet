//! Transaction submission and confirmation polling.
//!
//! `submit_transaction_and_wait` accepts an already-signed, base64-encoded
//! `TransactionEnvelope` XDR string, submits it via `stellar-rpc-client`
//! `sendTransaction`, and polls `getTransaction` every 2 seconds until the
//! transaction is confirmed (`SUCCESS`) or the timeout elapses.
//!
//! # Signing discipline
//!
//! The signing key is NOT accepted here. Signing is performed by
//! `ClassicOpBuilder::build_and_sign` before this function is called.
//! This function receives already-signed XDR bytes and submits them as-is.
//! Retries reuse those bytes — the signing key is never re-invoked.
//!
//! # Retry policy
//!
//! `send_transaction` is wrapped in a bounded exponential-backoff retry
//! (up to `RetryPolicy::default()` attempts) for transient transport errors
//! (`TransactionSubmissionTimeout`, `JsonRpc(_)`).
//! `TransactionSubmissionFailed` is NOT retried — it is indistinguishable from
//! a genuine on-chain rejection at this call site.
//!
//! The `getTransaction` poll loop tolerates transient `JsonRpc(_)` errors by
//! treating them like `NOT_FOUND` — the poll falls through to the deadline
//! check and sleeps `POLL_INTERVAL`, rather than propagating an immediate
//! `RpcUnreachable`.  This means a transient 429 on a poll does not abort the
//! entire submission.
//!
//! # Deadlines
//!
//! The reads before the send, the endpoint identity probe and the signer-set
//! read, share [`PRE_SEND_BUDGET`], which starts when the first of them
//! starts. A read the budget cuts refuses with `network.pre_send_timeout`,
//! and nothing is sent. The caller's `timeout` is armed when the send phase
//! begins, right after the pre-send record, and bounds exactly the send and
//! the confirmation poll: each poll request is cut at the deadline, each
//! sleep between polls ends at it at the latest, and an answer that completes
//! after it is not accepted.
//!
//! `submit_transaction_and_wait_sent_by` adds a send-by instant: the reads
//! end at it when it comes before the budget's end, and no send attempt
//! starts after it, so a caller whose signature rests on a deadline sends
//! nothing after it. The send phase keeps the submission's own timeout.
//!
//! A `sendTransaction` answer of `TRY_AGAIN_LATER` resends the same bytes
//! under the same backoff, while neither the send-by instant nor the send
//! deadline has passed.
//!
//! Retry-After limitation: `stellar-rpc-client` surfaces no typed `Retry-After`
//! header; blind backoff is used instead.  Retry-After / transport-429-on-send
//! is not currently honoured.
//!
//! # RPC transport
//!
//! Submission uses `sendTransaction` / `getTransaction` RPC only (no Horizon).
//! The retry layer applies bounded exponential backoff for transient failures.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use stellar_agent_core::envelope_decode::TRANSACTION_ENVELOPE_XDR_FORM;
use stellar_agent_core::error::{
    LedgerError, NetworkError, ProtocolError, SubmissionError, WalletError,
};
use stellar_xdr::{
    InnerTransactionResultResult, OperationResult, OperationResultTr, PaymentResult, ReadXdr,
    TransactionEnvelope, TransactionResult, TransactionResultResult,
};

use crate::client::{RpcEndpoint, StellarRpcClient, rpc_unreachable, unexpected_status};
use crate::endpoint_identity::MainnetOracle;
use crate::mainnet::authorization::MainnetTxSignAuthorization;
use crate::mainnet::consumed::AuthorizationConsumed;
use crate::mainnet::refusal::AuthorizedPathError;
use crate::mainnet::{AuthorizationDomain, MainnetConsumer, MainnetPrecondition};
use crate::retry::{
    RetryPolicy, StartedByError, is_retryable_poll_error, is_retryable_send_error,
    retry_with_backoff_started_by,
};
use crate::signing::verify_binding::{
    grant_signer_signed, reject_v0_envelope, verify_signature_network_binding,
};
use crate::submission_record::{SubmissionIntent, SubmissionOutcome, SubmissionRecorder};
use crate::transaction_record::TransactionRecord;

pub(crate) use stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE;

// ─────────────────────────────────────────────────────────────────────────────
// Poll interval
// ─────────────────────────────────────────────────────────────────────────────

/// How often to poll `getTransaction` for status.
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// How long the reads before a send may take together, counted from the
/// start of the first.
///
/// The endpoint identity probe and the signer-set read run under this one
/// fixed budget, never under the caller's timeout, which bounds only the
/// send and the confirmation poll. A short timeout therefore cannot refuse a
/// submission before its send. A read the budget cuts, or one that fails at
/// or after its end, refuses with [`NetworkError::PreSendTimeout`], and
/// nothing is sent. The CLI value verbs check their endpoint under the same
/// budget.
pub const PRE_SEND_BUDGET: Duration = Duration::from_secs(30);

// ─────────────────────────────────────────────────────────────────────────────
// SubmissionResult
// ─────────────────────────────────────────────────────────────────────────────

/// The result of a successful transaction submission and ledger confirmation.
///
/// All fields are non-secret public identifiers / attribution. `tx_hash` is the
/// canonical 64-character hex representation of the SHA-256 transaction hash;
/// `signer_kind` is non-secret signer attribution (no key material).
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmissionResult {
    /// The transaction hash (64-character hex string).
    pub tx_hash: String,

    /// The ledger sequence number in which the transaction was included.
    pub ledger: u32,

    /// The kind of signer that produced the submitted envelope signature, when
    /// the signing path is known at the submit call site.
    pub signer_kind: Option<SubmissionSignerKind>,
}

/// Non-secret signer attribution for successful transaction submission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubmissionSignerKind {
    /// A software ed25519 signing key held in process memory signed the envelope.
    Software,
    /// A platform keyring-backed software key signed the envelope.
    Keyring,
    /// A hardware signer signed the envelope.
    Hardware,
}

// ─────────────────────────────────────────────────────────────────────────────
// submit_transaction_and_wait
// ─────────────────────────────────────────────────────────────────────────────

/// Submits a signed `TransactionEnvelope` and polls until confirmed.
///
/// `envelope_xdr` must be a base64-encoded, already-signed
/// `TransactionEnvelope`. The function decodes it, calls `sendTransaction`,
/// then polls `getTransaction` every 2 seconds until the status is
/// `"SUCCESS"` or the `timeout` has elapsed.
///
/// `timeout` bounds the send and the confirmation poll, and nothing before
/// them. The endpoint identity probe and the signer-set fetch that precede
/// the send run under [`PRE_SEND_BUDGET`], and each of their retries is cut
/// off at its end. The deadline is armed when the send phase begins, right
/// after the pre-send record. A status that arrives after it is not
/// accepted, and the call returns the timeout.
///
/// # Which network the transaction reaches
///
/// `network_passphrase` is the caller's declaration, not the authority. A
/// declared mainnet passphrase, and a URL matching a known mainnet host, are
/// refused immediately at no network cost. Otherwise the endpoint is asked
/// which network it serves and must agree with the declaration, and every
/// signature on the envelope must verify under that network's id. An envelope
/// signed for one network therefore cannot be submitted under another's
/// passphrase, and an endpoint that turns out to serve mainnet is refused
/// however the call was declared.
///
/// # Errors
///
/// - [`WalletError::Protocol`] wrapping [`ProtocolError::XdrCodecFailed`] if
///   `envelope_xdr` cannot be decoded or is a legacy `TxV0` envelope.
/// - [`WalletError::Network`] wrapping [`NetworkError::RpcUnreachable`] or
///   [`NetworkError::RpcTimeout`] on transport errors.
/// - [`WalletError::Network`] wrapping [`NetworkError::MainnetWriteForbidden`]
///   if `network_passphrase` matches the mainnet passphrase, the URL appears
///   to target mainnet, or the endpoint reports the mainnet passphrase.
/// - [`WalletError::Network`] wrapping
///   [`NetworkError::EndpointNetworkMismatch`] if the endpoint serves a
///   different network, or [`NetworkError::EndpointIdentityUnavailable`] if
///   its identity cannot be established.
/// - [`WalletError::Network`] wrapping [`NetworkError::PreSendTimeout`] if a
///   read before the send does not answer within [`PRE_SEND_BUDGET`].
/// - [`WalletError::Network`] wrapping
///   [`NetworkError::EnvelopeSignedForMainnet`],
///   [`NetworkError::EnvelopeSignatureUnverifiable`] or
///   [`NetworkError::EnvelopeUnsigned`] if the envelope's signatures are not
///   bound to the network the endpoint serves.
/// - [`WalletError::Submission`] wrapping [`SubmissionError::TxMalformed`]
///   if the network rejects the transaction immediately.
/// - [`WalletError::Submission`] wrapping [`SubmissionError::TxTimeout`] if the
///   transaction is not confirmed within `timeout`.
/// - [`WalletError::Ledger`] wrapping [`LedgerError::InsufficientBalance`],
///   [`LedgerError::TrustlineMissing`], or [`LedgerError::OpFailed`] on
///   on-chain failure.
///
/// # Panics
///
/// Never panics.
///
/// # Examples
///
/// ```no_run
/// use std::time::Duration;
/// use stellar_agent_network::{StellarRpcClient, submit::submit_transaction_and_wait};
///
/// # async fn run() -> Result<(), stellar_agent_core::WalletError> {
/// let client = StellarRpcClient::new("https://soroban-testnet.stellar.org")?;
/// let result = submit_transaction_and_wait(
///     &client,
///     "AAAAAA...", // base64 signed envelope
///     Duration::from_secs(60),
///     "Test SDF Network ; September 2015",
///     Some(stellar_agent_network::SubmissionSignerKind::Software),
///     None, // no durable-submission recorder
/// ).await?;
/// println!("confirmed in ledger {}", result.ledger);
/// # Ok(()) }
/// ```
pub async fn submit_transaction_and_wait(
    client: &StellarRpcClient,
    envelope_xdr: &str,
    timeout: Duration,
    network_passphrase: &str,
    signer_kind: Option<SubmissionSignerKind>,
    recorder: Option<&dyn SubmissionRecorder>,
) -> Result<SubmissionResult, WalletError> {
    submit_unauthorized(
        client,
        envelope_xdr,
        None,
        timeout,
        network_passphrase,
        signer_kind,
        recorder,
        None,
    )
    .await
    .map_err(|error| error.into_wallet_error(client, timeout))
}

/// The step of a submission at which its send-by instant passed.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreSendStage {
    /// The probe that asks the endpoint which network it serves.
    EndpointIdentity,
    /// The signer-set read that binds the envelope's signatures to that
    /// network.
    SignatureBinding,
    /// The instant immediately before a `sendTransaction` attempt, after the
    /// pre-send record: the first send and every resend of the same bytes.
    Send,
}

impl PreSendStage {
    /// A stable label for the stage.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::EndpointIdentity => "send_endpoint_identity",
            Self::SignatureBinding => "send_signature_binding",
            Self::Send => "send_transaction",
        }
    }
}

/// Why [`submit_transaction_and_wait_sent_by`] returned without a result.
#[derive(Debug)]
pub enum SentByError {
    /// The send-by instant passed at `stage`, before a `sendTransaction`
    /// attempt, and no attempt starts after it.
    ///
    /// Before the first attempt nothing was sent and `sent_tx_hash` is
    /// `None`. A read the instant cuts leaves nothing recorded. After the
    /// pre-send record the recorder is told [`SubmissionOutcome::NotSent`],
    /// and the wallet's recorder releases the reservation, closes the
    /// pending row and removes the receipt, so the sequence is free again. A
    /// submission of a bound signed intent is told
    /// [`SubmissionOutcome::Rejected`] instead, and its record is retained.
    /// Before a resend the earlier send may have reached the network:
    /// `sent_tx_hash` names the transaction, and its record stands unresolved
    /// for reconciliation.
    Elapsed {
        /// The step the instant passed at.
        stage: PreSendStage,
        /// The hash of the transaction an earlier attempt sent, whose outcome
        /// is unknown; `None` when nothing was sent.
        sent_tx_hash: Option<String>,
    },
    /// Every other failure, as [`submit_transaction_and_wait`] reports it.
    Failed(WalletError),
}

impl From<WalletError> for SentByError {
    fn from(error: WalletError) -> Self {
        Self::Failed(error)
    }
}

impl SentByError {
    /// The wallet error for this failure. A send-by instant that passed
    /// before anything was sent reads as the submission's timeout at
    /// `client`; one that passed after a send reads as the unresolved
    /// [`SubmissionError::TxTimeout`] of the transaction sent.
    fn into_wallet_error(self, client: &StellarRpcClient, timeout: Duration) -> WalletError {
        match self {
            Self::Elapsed {
                sent_tx_hash: None, ..
            } => send_by_elapsed(&client.url, timeout),
            Self::Elapsed {
                sent_tx_hash: Some(tx_hash),
                ..
            } => WalletError::Submission(SubmissionError::TxTimeout {
                tx_hash,
                seconds: timeout.as_secs(),
            }),
            Self::Failed(error) => error,
        }
    }
}

/// The timeout error of a submission at `url` whose send-by instant passed.
fn send_by_elapsed(url: &RpcEndpoint, timeout: Duration) -> WalletError {
    WalletError::Network(NetworkError::RpcTimeout {
        url: url.authority(),
        timeout_secs: timeout.as_secs(),
    })
}

/// A supplied exposure requires a recorder and binds before the pending row and send.
/// Binding and envelope cancellation retain the admitted intent's charge.
///
/// Submits a signed `TransactionEnvelope` only while `send_by` has not
/// passed, and polls until confirmed.
///
/// [`submit_transaction_and_wait`] with one more bound: the endpoint
/// identity probe and the signer-set fetch end at the earlier of `send_by`
/// and the end of [`PRE_SEND_BUDGET`], an answer that completes at or after
/// that instant is not read, and `send_by` is checked again immediately
/// before every `sendTransaction` attempt, after the pre-send record: the
/// first send and every resend of the same bytes after a transport failure
/// or a `TRY_AGAIN_LATER` answer. A sleep between attempts ends at `send_by`
/// at the latest. A caller whose signature rests on a deadline passes that
/// deadline, so nothing it signed is sent after it. An attempt that started
/// before the instant, and the confirmation poll, run under `timeout`, armed
/// when the send phase begins, as in [`submit_transaction_and_wait`].
///
/// # Errors
///
/// - [`SentByError::Failed`] with `submission.intent_record_unavailable` and
///   class `missing_recorder` when exposure has no recorder. This refusal
///   precedes envelope decoding and network access.
/// - [`SentByError::Elapsed`] when `send_by` passes before a
///   `sendTransaction` attempt. Before the first attempt nothing was sent.
///   A read the instant cuts records nothing. After the pre-send record the
///   recorder is told [`SubmissionOutcome::NotSent`] with the code of
///   [`NetworkError::RpcTimeout`], and the wallet's recorder unwinds the
///   record; under `exposure` it is told [`SubmissionOutcome::Rejected`]
///   with that code, and the record is retained. Before a resend it is told
///   [`SubmissionOutcome::TransportAfterSend`]: the earlier send's outcome is
///   unknown, the error names its transaction hash, and the record is
///   retained for reconciliation.
/// - [`SentByError::Failed`] with every error of
///   [`submit_transaction_and_wait`].
///
/// # Panics
///
/// Never panics.
#[allow(
    clippy::too_many_arguments,
    reason = "the submission seam carries its exposure and recorder together"
)]
pub async fn submit_transaction_and_wait_sent_by(
    client: &StellarRpcClient,
    envelope_xdr: &str,
    send_by: tokio::time::Instant,
    timeout: Duration,
    network_passphrase: &str,
    signer_kind: Option<SubmissionSignerKind>,
    recorder: Option<&dyn SubmissionRecorder>,
    exposure: Option<&crate::ExposedIntent>,
) -> Result<SubmissionResult, SentByError> {
    submit_unauthorized(
        client,
        envelope_xdr,
        Some(send_by),
        timeout,
        network_passphrase,
        signer_kind,
        recorder,
        exposure,
    )
    .await
}

/// The fixed name of the endpoint identity probe in a
/// [`NetworkError::PreSendTimeout`] refusal.
pub(crate) const IDENTITY_PROBE_READ: &str = "endpoint identity probe";

/// The fixed name of the signer-set read in a
/// [`NetworkError::PreSendTimeout`] refusal.
pub(crate) const SIGNER_SET_READ: &str = "signer-set read";

/// The bound of the reads before one send: [`PRE_SEND_BUDGET`] from the
/// instant the first read starts, or `send_by` when that comes first.
///
/// Each read runs under the earlier of the two instants and receives it as
/// its own deadline. No read starts at or after it, a read in flight is cut
/// at it, and an answer that completes at or after it is not read, so a read
/// that fails at or after the instant refuses as a cut one does. A cut at the
/// budget's end refuses with [`NetworkError::PreSendTimeout`] naming the read;
/// a cut at an earlier `send_by` is [`SentByError::Elapsed`].
pub(crate) struct PreSendBudget {
    send_by: Option<tokio::time::Instant>,
    start: BudgetStart,
}

/// Which instant ended a read before the send.
enum ReadCut {
    /// The send-by instant, at or before the budget's end.
    SendBy,
    /// The end of [`PRE_SEND_BUDGET`].
    Budget,
}

/// The instant the first read of a budget starts, from which
/// [`PRE_SEND_BUDGET`] runs.
struct BudgetStart(std::sync::OnceLock<tokio::time::Instant>);

impl BudgetStart {
    fn new() -> Self {
        Self(std::sync::OnceLock::new())
    }

    /// The end of [`PRE_SEND_BUDGET`]; the first call starts the budget.
    fn budget_end(&self) -> tokio::time::Instant {
        *self.0.get_or_init(tokio::time::Instant::now) + PRE_SEND_BUDGET
    }
}

/// A read that `end` cut.
struct ReadElapsed;

/// Runs `step` with `end` as its deadline.
///
/// # Errors
///
/// [`ReadElapsed`] when the read did not start before `end`, ran past it, or
/// completed at or after it.
async fn run_until<T, F, Fut>(
    end: tokio::time::Instant,
    step: F,
) -> Result<Result<T, WalletError>, ReadElapsed>
where
    F: FnOnce(tokio::time::Instant) -> Fut,
    Fut: std::future::Future<Output = Result<T, WalletError>>,
{
    if tokio::time::Instant::now() >= end {
        return Err(ReadElapsed);
    }
    let answer = tokio::time::timeout_at(end, step(end)).await;
    // Tokio polls the read before its deadline timer, so an answer can
    // complete at the deadline; it is not read.
    if tokio::time::Instant::now() >= end {
        return Err(ReadElapsed);
    }
    answer.map_err(|_| ReadElapsed)
}

impl PreSendBudget {
    /// A budget whose reads also end at `send_by`, when there is one. The
    /// budget starts with the first read.
    pub(crate) fn new(send_by: Option<tokio::time::Instant>) -> Self {
        Self {
            send_by,
            start: BudgetStart::new(),
        }
    }

    /// The instant the reads end at, and which bound it is.
    fn end(&self) -> (tokio::time::Instant, ReadCut) {
        let budget_end = self.start.budget_end();
        match self.send_by {
            Some(send_by) if send_by <= budget_end => (send_by, ReadCut::SendBy),
            _ => (budget_end, ReadCut::Budget),
        }
    }

    /// Runs the read `read` of `stage` under the budget.
    ///
    /// # Errors
    ///
    /// [`SentByError::Elapsed`] at `stage` when `send_by` cut the read;
    /// [`NetworkError::PreSendTimeout`] naming `read` when the budget's end
    /// cut it; the read's own error when it failed before either instant.
    pub(crate) async fn read<T, F, Fut>(
        &self,
        stage: PreSendStage,
        read: &'static str,
        step: F,
    ) -> Result<T, SentByError>
    where
        F: FnOnce(tokio::time::Instant) -> Fut,
        Fut: std::future::Future<Output = Result<T, WalletError>>,
    {
        let (end, cut) = self.end();
        match run_until(end, step).await {
            Ok(answer) => Ok(answer?),
            Err(ReadElapsed) => match cut {
                ReadCut::SendBy => Err(SentByError::Elapsed {
                    stage,
                    sent_tx_hash: None,
                }),
                ReadCut::Budget => Err(SentByError::Failed(pre_send_timeout(read))),
            },
        }
    }
}

/// The bound of the reads before one send of a submission without a send-by
/// instant: [`PRE_SEND_BUDGET`] from the instant the first read starts, under
/// the rules of [`PreSendBudget`].
pub(crate) struct UnboundedPreSendBudget {
    start: BudgetStart,
}

impl UnboundedPreSendBudget {
    /// A budget that starts with the first read.
    pub(crate) fn new() -> Self {
        Self {
            start: BudgetStart::new(),
        }
    }

    /// Runs the read `read` under the budget.
    ///
    /// # Errors
    ///
    /// [`NetworkError::PreSendTimeout`] naming `read` when the budget cut the
    /// read; the read's own error when it failed before.
    pub(crate) async fn read<T, F, Fut>(
        &self,
        read: &'static str,
        step: F,
    ) -> Result<T, WalletError>
    where
        F: FnOnce(tokio::time::Instant) -> Fut,
        Fut: std::future::Future<Output = Result<T, WalletError>>,
    {
        run_until(self.start.budget_end(), step)
            .await
            .unwrap_or_else(|ReadElapsed| Err(pre_send_timeout(read)))
    }
}

/// The refusal of a read the pre-send budget cut.
fn pre_send_timeout(read: &'static str) -> WalletError {
    WalletError::Network(NetworkError::PreSendTimeout {
        read: read.to_owned(),
        budget_secs: PRE_SEND_BUDGET.as_secs(),
    })
}

/// Runs one submission around its send: `pre_send` takes the reads under a
/// [`PreSendBudget`] bounded by `send_by` and writes the pre-send record;
/// `send_phase` then sends and polls under the send deadline.
///
/// The send deadline is armed when `pre_send` returns, so `timeout` bounds
/// exactly the send and the confirmation poll: neither the reads nor the
/// record spend it.
async fn budgeted_submission<R, T, E, Reads, ReadsFut, SendPhase, SendFut>(
    send_by: Option<tokio::time::Instant>,
    timeout: Duration,
    pre_send: Reads,
    send_phase: SendPhase,
) -> Result<T, E>
where
    Reads: FnOnce(PreSendBudget) -> ReadsFut,
    ReadsFut: std::future::Future<Output = Result<R, E>>,
    SendPhase: FnOnce(R, tokio::time::Instant) -> SendFut,
    SendFut: std::future::Future<Output = Result<T, E>>,
{
    let prepared = pre_send(PreSendBudget::new(send_by)).await?;
    let send_deadline = tokio::time::Instant::now() + timeout;
    send_phase(prepared, send_deadline).await
}

/// A send-by instant, and the same instant in Unix milliseconds on the clock
/// of [`crate::mainnet::clock::now_ms`], the form a
/// [`SubmissionIntent`] carries.
#[derive(Clone, Copy)]
struct SendBy {
    at: tokio::time::Instant,
    unix_ms: u64,
}

impl SendBy {
    /// The caller's instant `at`, read against the clock now.
    ///
    /// # Errors
    ///
    /// `wallet.clock_error` when the clock cannot be read.
    fn from_instant(at: tokio::time::Instant) -> Result<Self, WalletError> {
        let now_ms = crate::mainnet::clock::now_ms()?;
        let ahead = at.saturating_duration_since(tokio::time::Instant::now());
        Ok(Self {
            at,
            unix_ms: now_ms.saturating_add(u64::try_from(ahead.as_millis()).unwrap_or(u64::MAX)),
        })
    }
}

/// The recorder the send phase of a bound signed intent reports to.
///
/// A bound intent's admission links its charge to the record, so a send-by
/// refusal before the first attempt keeps the record: the unsent report
/// reaches the inner recorder as [`SubmissionOutcome::Rejected`] with the
/// same code and detail. Every other call is the inner recorder's.
struct BoundIntentRecorder<'r>(&'r dyn SubmissionRecorder);

#[async_trait::async_trait]
impl SubmissionRecorder for BoundIntentRecorder<'_> {
    async fn admit_signed_intent(
        &self,
        plan: &crate::SignedIntentPlan,
    ) -> Result<crate::IntentProof, WalletError> {
        self.0.admit_signed_intent(plan).await
    }

    async fn cancel_unexposed(&self, proof: crate::IntentProof) -> Result<(), WalletError> {
        self.0.cancel_unexposed(proof).await
    }

    async fn pre_send_bound(
        &self,
        intent: &SubmissionIntent,
        binding: &crate::IntentBinding<'_>,
    ) -> Result<(), WalletError> {
        self.0.pre_send_bound(intent, binding).await
    }

    async fn pre_send(&self, intent: &SubmissionIntent) -> Result<(), WalletError> {
        self.0.pre_send(intent).await
    }

    async fn pre_send_authorized(
        &self,
        intent: &SubmissionIntent,
        grant: MainnetSubmitGrant,
    ) -> Result<AuthorizationConsumed, WalletError> {
        self.0.pre_send_authorized(intent, grant).await
    }

    async fn outcome(&self, intent: &SubmissionIntent, outcome: &SubmissionOutcome) {
        match outcome {
            SubmissionOutcome::NotSent { code, error } => {
                self.0
                    .outcome(
                        intent,
                        &SubmissionOutcome::Rejected {
                            code: code.clone(),
                            error: error.clone(),
                        },
                    )
                    .await;
            }
            other => self.0.outcome(intent, other).await,
        }
    }
}

/// The unauthorized submission, with the pre-send steps bounded by
/// `send_by` when there is one.
#[allow(
    clippy::too_many_arguments,
    reason = "the submission seam carries its exposure and recorder together"
)]
async fn submit_unauthorized(
    client: &StellarRpcClient,
    envelope_xdr: &str,
    send_by: Option<tokio::time::Instant>,
    timeout: Duration,
    network_passphrase: &str,
    signer_kind: Option<SubmissionSignerKind>,
    recorder: Option<&dyn SubmissionRecorder>,
    exposure: Option<&crate::ExposedIntent>,
) -> Result<SubmissionResult, SentByError> {
    if exposure.is_some() && recorder.is_none() {
        return Err(crate::signed_intent::unavailable("missing_recorder").into());
    }
    // Mainnet write is structurally forbidden at the submit layer: the
    // passphrase comparison is the primary check and the URL heuristic the
    // defence-in-depth layer, both before any decode or RPC call.
    refuse_mainnet_write(network_passphrase, client.url.as_str()).map_err(WalletError::Network)?;

    // Decode the base64 XDR envelope. The envelope is caller-supplied and
    // untrusted; bounded limits prevent a deeply nested auth-invocation tree
    // from exhausting the stack.
    let envelope = TransactionEnvelope::from_xdr_base64(
        envelope_xdr,
        stellar_agent_xdr_limits::untrusted_decode_limits(envelope_xdr.len()),
    )
    .map_err(|_| {
        WalletError::Protocol(ProtocolError::XdrCodecFailed {
            detail: format!(
                "failed to decode TransactionEnvelope from base64 XDR: \
                 {TRANSACTION_ENVELOPE_XDR_FORM}"
            ),
        })
    })?;

    crate::signing::envelope_signing::refuse_muxed_contract(&envelope)?;

    // A legacy V0 envelope has no SEP-23 tagged-transaction form, so neither
    // the signing path nor binding verification can construct a payload for
    // it. Refused here so it costs no round trip.
    reject_v0_envelope(&envelope)?;
    let envelope = &envelope;

    // A bound signed intent keeps its record when nothing is sent; every
    // other submission's unsent report unwinds it.
    let bound = recorder.filter(|_| exposure.and_then(crate::ExposedIntent::intent_id).is_some());
    let bound = bound.map(BoundIntentRecorder);
    let send_recorder: Option<&dyn SubmissionRecorder> = match &bound {
        Some(bound) => Some(bound),
        None => recorder,
    };

    budgeted_submission(
        send_by,
        timeout,
        |budget| async move {
            // Ask the endpoint which network it serves and which protocol it
            // runs, on the client instance that will send. The target network
            // is a property of the endpoint; the caller's declaration is only
            // a claim about it, and the two must be shown to agree before
            // anything is sent.
            budget
                .read(
                    PreSendStage::EndpointIdentity,
                    IDENTITY_PROBE_READ,
                    |deadline| client.endpoint_identity(network_passphrase, deadline),
                )
                .await?;

            // With the endpoint's network established, verify that the
            // envelope's signatures were produced for that network. This is
            // what stops an envelope signed for one network from being
            // relayed to another. The response's ledger is the endpoint's view
            // of the chain immediately before the send, which is what a later
            // reconciliation compares against the endpoint's retention floor.
            let submission_ledger = budget
                .read(
                    PreSendStage::SignatureBinding,
                    SIGNER_SET_READ,
                    |deadline| {
                        verify_signature_network_binding(
                            client,
                            envelope,
                            network_passphrase,
                            deadline,
                        )
                    },
                )
                .await?;

            // The transaction hash is a property of the envelope, not of the
            // endpoint: it is computable from the bytes about to be sent.
            // Computing it here means the wallet polls, records and reports
            // the hash of what it signed, and can tell when the endpoint
            // describes something else.
            let tx_hash_hex = compute_local_tx_hash_hex(envelope, network_passphrase)?;
            let local_hash_bytes = tx_hash_bytes(&tx_hash_hex)?;

            let (source, sequence) = replay_identity(envelope)?;
            let send_by = send_by.map(SendBy::from_instant).transpose()?;
            let intent = SubmissionIntent {
                chain_scope: crate::policy_state::ChainScope::from_passphrase(network_passphrase)
                    .map_err(WalletError::from)?,
                envelope_hash: envelope_hash_hex(envelope_xdr),
                tx_hash: tx_hash_hex,
                source,
                sequence,
                max_time: crate::idempotent_submit::extract_max_time(envelope),
                submission_ledger,
                submission_anchor: None,
                send_by_ms: send_by.map(|send_by| send_by.unix_ms),
            };

            // The record is written before the send, so a submission whose
            // outcome never comes back is still one the wallet remembers.
            if let Some(rec) = recorder {
                if let Some(exposure) = exposure {
                    rec.pre_send_bound(&intent, &crate::IntentBinding::new(exposure, envelope))
                        .await?;
                } else {
                    rec.pre_send(&intent).await?;
                }
            }
            Ok((intent, local_hash_bytes))
        },
        |(intent, local_hash_bytes), send_deadline| async move {
            // The send-by instant is checked immediately before every send
            // attempt, the first one right after the record.
            send_and_confirm(
                client,
                envelope,
                &intent,
                local_hash_bytes,
                send_by,
                send_deadline,
                timeout,
                send_recorder,
                signer_kind,
                FailureWitness::Primary,
            )
            .await
        },
    )
    .await
}

/// The authority a mainnet submission is sent under.
///
/// Consumed by [`submit_authorized_transaction_and_wait`]: the submit hands
/// it to the recorder, whose consumption of the authorization in the ledger is
/// what the send depends on.
#[non_exhaustive]
#[derive(Debug)]
pub enum MainnetSubmitGrant {
    /// A classic transaction signed under its transaction authorization.
    Tx(MainnetTxSignAuthorization),
}

/// Submits a signed mainnet `Tx` envelope under a grant and polls until
/// confirmed.
///
/// The mainnet counterpart of [`submit_transaction_and_wait`], with the
/// reads under [`PRE_SEND_BUDGET`] and `timeout` bounding the send and the
/// confirmation poll in the same way. In order:
///
/// 1. The local gate, before any request: `network_passphrase` and the bound
///    chain must be mainnet's, `consumer` the bound consuming verb, the grant
///    unexpired on the clock of [`crate::mainnet::clock::now_ms`], and the
///    client's authority and identity the bound endpoint. The endpoint
///    binding is the authority on the endpoint, so the URL heuristic of
///    [`refuse_mainnet_write`] does not apply.
/// 2. The envelope is decoded. Its send-by instant is its `maxTime` less
///    [`MAINNET_SEND_MARGIN_SECONDS`](crate::mainnet::resolve::MAINNET_SEND_MARGIN_SECONDS):
///    an envelope without a deadline, and one whose send-by instant the
///    gate's clock reading has reached, are refused before any request. A
///    legacy `TxV0` envelope is refused, and only a `Tx` envelope is sent
///    under a transaction grant.
/// 3. The endpoint must report the mainnet passphrase.
/// 4. Every signature must verify under the mainnet network id, as
///    [`submit_transaction_and_wait`] requires for its network, and one of
///    them must be the bound signer's.
/// 5. The transaction hash recomputed under the mainnet passphrase must be
///    the bound one.
/// 6. The recorder consumes the grant
///    ([`SubmissionRecorder::pre_send_authorized`]); the proof it returns must
///    name this envelope, its transaction content, and the grant's
///    authorization.
/// 7. The envelope is sent once, through the retry of transport failures and
///    `TRY_AGAIN_LATER` answers that resends the same bytes, and the
///    confirmation is polled. No attempt starts after the send-by instant,
///    which also ends the reads of steps 3 and 4 when it comes before the
///    budget's end.
///
/// # Negative answers need the oracle
///
/// A negative answer of `client` alone settles nothing, because a primary
/// endpoint that reports a failure for a transaction that applies would
/// erase a real debit from the operator's spending window:
///
/// - A `FAILED` confirmation is checked against `oracle`: one `getNetwork`
///   that has to report the mainnet passphrase, then one `getTransaction`
///   for the same hash, both bounded by the remaining deadline. Only the
///   oracle's own `FAILED` is reported to the recorder as
///   [`SubmissionOutcome::OnChainFailed`], with the oracle's result code, and
///   that failure is returned. The wallet's
///   [`WalletSubmissionRecorder`](crate::submission_record::WalletSubmissionRecorder)
///   retains the reservation, the receipt and the pending audit row for that
///   report too. Any other oracle answer, an oracle error, or no answer
///   before the deadline records [`SubmissionOutcome::TransportAfterSend`]
///   and returns [`SubmissionError::TxTimeout`]. So do an oracle that reports
///   another network or whose identity cannot be read, and a missing oracle
///   (`oracle` is `None`). The reservation, the receipt and the pending audit
///   row stand. The reservation ends at its accounting horizon
///   or, without an execution bound, at an operator clear.
/// - A `sendTransaction` refusal is never confirmed, since a refused
///   transaction has no record an oracle could report. It records
///   [`SubmissionOutcome::TransportAfterSend`] naming the refusal and
///   returns [`SubmissionError::TxTimeout`] the same way.
///
/// A refusal of the consumption proof before the send is still reported as
/// rejected: nothing was sent. A send-by instant that passes after the
/// consumption and before the first attempt is reported as
/// [`SubmissionOutcome::NotSent`]: the wallet's recorder releases the
/// converted holds, closes the pending row and removes the receipt, and the
/// used authorization stays used.
///
/// Compiled in every build; without mainnet writes no grant exists, so the
/// function cannot be called.
///
/// # Errors
///
/// - [`WalletError::Network`] wrapping
///   [`NetworkError::MainnetAuthorizationRefused`] if a check of the grant
///   fails, the envelope is a fee bump, its deadline is missing or within the
///   send margin, the send-by instant passes before the first attempt, the
///   bound signer did not sign, or the recorder's proof does not match. The
///   broken precondition is logged.
/// - [`WalletError::Network`] wrapping
///   [`NetworkError::EndpointNetworkMismatch`] if the endpoint does not serve
///   mainnet, and the other errors of [`submit_transaction_and_wait`] for the
///   identity probe, the signature binding, the send, and the poll, except
///   that a send refusal and an unconfirmed `FAILED` confirmation return
///   [`SubmissionError::TxTimeout`] as described above.
/// - The recorder's refusal from
///   [`SubmissionRecorder::pre_send_authorized`].
///
/// # Panics
///
/// Never panics.
#[allow(
    clippy::too_many_arguments,
    reason = "the inputs of submit_transaction_and_wait plus the oracle, the consuming verb and \
              the grant"
)]
pub async fn submit_authorized_transaction_and_wait(
    client: &StellarRpcClient,
    oracle: Option<&StellarRpcClient>,
    envelope_xdr: &str,
    timeout: Duration,
    network_passphrase: &str,
    signer_kind: Option<SubmissionSignerKind>,
    recorder: &dyn SubmissionRecorder,
    consumer: MainnetConsumer,
    grant: MainnetSubmitGrant,
) -> Result<SubmissionResult, WalletError> {
    authorized_submission(
        client,
        oracle,
        envelope_xdr,
        timeout,
        network_passphrase,
        signer_kind,
        recorder,
        consumer,
        grant,
    )
    .await
    .map_err(|error| error.report("submit_authorized_transaction_and_wait"))
}

/// [`submit_authorized_transaction_and_wait`] with the broken precondition
/// kept for the caller.
#[allow(
    clippy::too_many_arguments,
    reason = "the inputs of submit_authorized_transaction_and_wait"
)]
pub(crate) async fn authorized_submission(
    client: &StellarRpcClient,
    oracle: Option<&StellarRpcClient>,
    envelope_xdr: &str,
    timeout: Duration,
    network_passphrase: &str,
    signer_kind: Option<SubmissionSignerKind>,
    recorder: &dyn SubmissionRecorder,
    consumer: MainnetConsumer,
    grant: MainnetSubmitGrant,
) -> Result<SubmissionResult, AuthorizedPathError> {
    let MainnetSubmitGrant::Tx(authorization) = &grant;
    let authority = client.url.authority();
    let now_ms = crate::mainnet::clock::now_ms()?;
    mainnet_submit_gate(
        network_passphrase,
        &authority,
        client.id(),
        consumer,
        authorization,
        now_ms,
    )?;

    let envelope = TransactionEnvelope::from_xdr_base64(
        envelope_xdr,
        stellar_agent_xdr_limits::untrusted_decode_limits(envelope_xdr.len()),
    )
    .map_err(|_| {
        WalletError::Protocol(ProtocolError::XdrCodecFailed {
            detail: format!(
                "failed to decode TransactionEnvelope from base64 XDR: \
                 {TRANSACTION_ENVELOPE_XDR_FORM}"
            ),
        })
    })?;
    crate::signing::envelope_signing::refuse_muxed_contract(&envelope)?;
    // No send attempt starts within the send margin of the envelope's
    // deadline. A deadline the margin already reaches refuses here, before
    // anything is read, recorded or consumed.
    let send_by_ms = authorized_send_by_ms(&envelope)?;
    let Some(ahead_ms) = send_by_ms.checked_sub(now_ms).filter(|ms| *ms > 0) else {
        return Err(AuthorizedPathError::Refused(
            MainnetPrecondition::DeadlineWithinMargin,
        ));
    };
    let send_by = SendBy {
        at: tokio::time::Instant::now() + Duration::from_millis(ahead_ms),
        unix_ms: send_by_ms,
    };
    reject_v0_envelope(&envelope)?;
    if !matches!(envelope, TransactionEnvelope::Tx(_)) {
        return Err(AuthorizedPathError::Refused(
            MainnetPrecondition::BindingMismatch,
        ));
    }
    let envelope = &envelope;
    let send_by_at = Some(send_by.at);

    budgeted_submission(
        send_by_at,
        timeout,
        |budget| async move {
            let MainnetSubmitGrant::Tx(authorization) = &grant;
            // The probe's contribution is the passphrase: the endpoint
            // binding was compared against this client's authority and
            // identity above.
            budget
                .read(
                    PreSendStage::EndpointIdentity,
                    IDENTITY_PROBE_READ,
                    |deadline| client.mainnet_endpoint_identity(deadline),
                )
                .await
                .map_err(|error| authorized_send_by_error(error, client, timeout))?;
            let submission_ledger = budget
                .read(
                    PreSendStage::SignatureBinding,
                    SIGNER_SET_READ,
                    |deadline| {
                        verify_signature_network_binding(
                            client,
                            envelope,
                            MAINNET_PASSPHRASE,
                            deadline,
                        )
                    },
                )
                .await
                .map_err(|error| authorized_send_by_error(error, client, timeout))?;
            if !grant_signer_signed(envelope, &authorization.signer_public_key())? {
                return Err(AuthorizedPathError::Refused(
                    MainnetPrecondition::SignerKeyMismatch,
                ));
            }

            let tx_hash_hex = compute_local_tx_hash_hex(envelope, MAINNET_PASSPHRASE)?;
            let local_hash_bytes = tx_hash_bytes(&tx_hash_hex)?;
            authorization.check_tx_hash(&local_hash_bytes)?;

            let (source, sequence) = replay_identity(envelope)?;
            #[cfg(feature = "mainnet-write")]
            let submission_anchor = authorization.0.header.submission_anchor.clone();
            #[cfg(not(feature = "mainnet-write"))]
            let submission_anchor = None;
            let intent = SubmissionIntent {
                chain_scope: crate::policy_state::ChainScope::for_chain(
                    stellar_agent_core::profile::caip2::Caip2::Mainnet,
                ),
                envelope_hash: envelope_hash_hex(envelope_xdr),
                tx_hash: tx_hash_hex,
                source,
                sequence,
                max_time: crate::idempotent_submit::extract_max_time(envelope),
                submission_ledger,
                submission_anchor,
                send_by_ms: Some(send_by.unix_ms),
            };
            let authorization_id = authorization.id();

            // The consumption is the record: it runs once, before the send
            // and its retries.
            let proof = recorder.pre_send_authorized(&intent, grant).await?;
            if let Err(precondition) = proof_matches(&proof, &intent, authorization_id) {
                recorder
                    .outcome(
                        &intent,
                        &SubmissionOutcome::Rejected {
                            code: WalletError::Network(NetworkError::MainnetAuthorizationRefused)
                                .code()
                                .to_owned(),
                            error: format!(
                                "the consumption proof does not name this submission ({})",
                                precondition.label()
                            ),
                        },
                    )
                    .await;
                return Err(AuthorizedPathError::Refused(precondition));
            }
            Ok((intent, local_hash_bytes))
        },
        |(intent, local_hash_bytes), send_deadline| async move {
            send_and_confirm(
                client,
                envelope,
                &intent,
                local_hash_bytes,
                send_by_at,
                send_deadline,
                timeout,
                Some(recorder),
                signer_kind,
                FailureWitness::Oracle(oracle),
            )
            .await
            .map_err(|error| authorized_send_by_error(error, client, timeout))
        },
    )
    .await
}

/// The instant after which no send attempt of the mainnet `envelope`
/// starts, in Unix milliseconds: its `maxTime` less
/// [`MAINNET_SEND_MARGIN_SECONDS`](crate::mainnet::resolve::MAINNET_SEND_MARGIN_SECONDS),
/// saturating at zero.
///
/// # Errors
///
/// [`MainnetPrecondition::DeadlineMissing`] for an envelope without a
/// deadline.
fn authorized_send_by_ms(envelope: &TransactionEnvelope) -> Result<u64, AuthorizedPathError> {
    let max_time = crate::idempotent_submit::extract_max_time(envelope);
    if max_time == 0 {
        return Err(AuthorizedPathError::Refused(
            MainnetPrecondition::DeadlineMissing,
        ));
    }
    Ok(max_time
        .saturating_mul(1000)
        .saturating_sub(crate::mainnet::resolve::MAINNET_SEND_MARGIN_SECONDS.saturating_mul(1000)))
}

/// The authorized path's form of a send-by refusal. Before anything was sent
/// the send margin refused the send
/// ([`MainnetPrecondition::DeadlineWithinMargin`]), not the timeout at
/// `client`; every other error is the wallet error of
/// [`SentByError::into_wallet_error`].
fn authorized_send_by_error(
    error: SentByError,
    client: &StellarRpcClient,
    timeout: Duration,
) -> AuthorizedPathError {
    match error {
        SentByError::Elapsed {
            sent_tx_hash: None, ..
        } => AuthorizedPathError::Refused(MainnetPrecondition::DeadlineWithinMargin),
        other => AuthorizedPathError::Wallet(other.into_wallet_error(client, timeout)),
    }
}

/// Which negative answers of the endpoint a submission was sent to are
/// reported to the recorder as definitive.
///
/// A report retains exposure: the wallet's recorder keeps the receipt, the
/// pending audit row and the reservation for every outcome it receives.
#[derive(Clone, Copy)]
enum FailureWitness<'a> {
    /// The endpoint's own `FAILED` confirmation and its own send refusal are
    /// reported as definitive.
    Primary,
    /// A mainnet submission: a `FAILED` confirmation is reported as failed on
    /// chain only when this oracle reports `FAILED` for the same hash, and a
    /// send refusal is reported as an unknown outcome. `None` is a profile
    /// without an oracle, whose negative answers are therefore reported as
    /// unknown outcomes.
    Oracle(Option<&'a StellarRpcClient>),
}

/// The local gate of a mainnet submission, before any request: the chain,
/// the consuming verb, the expiry at `now_ms`, and the endpoint, in that
/// order.
pub(crate) fn mainnet_submit_gate(
    network_passphrase: &str,
    authority: &str,
    client_id: u64,
    consumer: MainnetConsumer,
    authorization: &MainnetTxSignAuthorization,
    now_ms: u64,
) -> Result<(), AuthorizedPathError> {
    let chain = stellar_agent_core::profile::caip2::Caip2::from_passphrase(network_passphrase)
        .ok_or(AuthorizedPathError::Refused(
            MainnetPrecondition::ChainNotMainnet,
        ))?;
    authorization.check_chain(chain)?;
    authorization.check_consumer(consumer)?;
    authorization.check_not_expired(now_ms)?;
    authorization.check_endpoint(Some((authority, client_id)))?;
    Ok(())
}

/// Requires the consumption proof to name the submission's envelope hash, its
/// transaction content digest, and the granted authorization.
///
/// # Errors
///
/// The precondition the proof breaks.
fn proof_matches(
    proof: &AuthorizationConsumed,
    intent: &SubmissionIntent,
    authorization_id: crate::mainnet::AuthorizationId,
) -> Result<(), MainnetPrecondition> {
    let envelope_hash =
        tx_hash_bytes(&intent.envelope_hash).map_err(|_| MainnetPrecondition::BindingMismatch)?;
    let tx_hash =
        tx_hash_bytes(&intent.tx_hash).map_err(|_| MainnetPrecondition::BindingMismatch)?;
    let content =
        crate::mainnet::digest::content_digest(AuthorizationDomain::Transaction, &tx_hash);
    if *proof.envelope_hash() != envelope_hash {
        return Err(MainnetPrecondition::BindingMismatch);
    }
    if *proof.content_digest() != content {
        return Err(MainnetPrecondition::ContentDigest);
    }
    if proof.authorization_id() != authorization_id {
        return Err(MainnetPrecondition::UnknownAuthorization);
    }
    Ok(())
}

/// Sends the recorded envelope once, through the retry of transport failures
/// and `TRY_AGAIN_LATER` answers that resends the same bytes, compares the
/// endpoint's hash with the local one, and polls for the confirmation.
/// `witness` decides how a negative answer is reported.
///
/// With `send_by`, no attempt starts at or after it, the first included;
/// [`refuse_past_send_by`] reports a refused attempt to the recorder.
#[allow(
    clippy::too_many_arguments,
    reason = "the facts both submit paths established before the send"
)]
async fn send_and_confirm(
    client: &StellarRpcClient,
    envelope: &TransactionEnvelope,
    intent: &SubmissionIntent,
    local_hash_bytes: [u8; 32],
    send_by: Option<tokio::time::Instant>,
    send_deadline: tokio::time::Instant,
    timeout: Duration,
    recorder: Option<&dyn SubmissionRecorder>,
    signer_kind: Option<SubmissionSignerKind>,
    witness: FailureWitness<'_>,
) -> Result<SubmissionResult, SentByError> {
    let tx_hash = stellar_xdr::Hash(local_hash_bytes);
    send_and_confirm_through(
        |envelope| client.send_transaction_response(envelope),
        || client.get_transaction_record(&tx_hash),
        &client.url,
        SendPhase {
            envelope,
            intent,
            send_by,
            send_deadline,
            timeout,
            recorder,
            signer_kind,
            witness,
        },
    )
    .await
}

/// What [`send_and_confirm_through`] sends and settles.
struct SendPhase<'a> {
    envelope: &'a TransactionEnvelope,
    intent: &'a SubmissionIntent,
    send_by: Option<tokio::time::Instant>,
    send_deadline: tokio::time::Instant,
    timeout: Duration,
    recorder: Option<&'a dyn SubmissionRecorder>,
    signer_kind: Option<SubmissionSignerKind>,
    witness: FailureWitness<'a>,
}

/// [`send_and_confirm`] through `send`, which issues one `sendTransaction`
/// for the envelope it is handed and returns the endpoint's answer, and
/// `poll`, which issues one `getTransaction` for the transaction. `url` is
/// the endpoint both reach.
///
/// The status of each answer is read by
/// [`accepted_hash`](crate::client::accepted_hash): `ERROR` is the endpoint's
/// refusal, `TRY_AGAIN_LATER` resends the same bytes under the retry's backoff
/// while neither `send_by` nor the send deadline has passed, and every other
/// status is an accepted send. A send that ends without an
/// accepted status, a `TRY_AGAIN_LATER` that outlasts the attempts or the
/// deadline included, records [`SubmissionOutcome::TransportAfterSend`].
async fn send_and_confirm_through<'e, S, SF, P, PF>(
    mut send: S,
    poll: P,
    url: &RpcEndpoint,
    phase: SendPhase<'e>,
) -> Result<SubmissionResult, SentByError>
where
    S: FnMut(&'e TransactionEnvelope) -> SF,
    SF: std::future::Future<
            Output = Result<stellar_rpc_client::SendTransactionResponse, stellar_rpc_client::Error>,
        >,
    P: FnMut() -> PF,
    PF: std::future::Future<Output = Result<TransactionRecord, stellar_rpc_client::Error>>,
{
    let SendPhase {
        envelope,
        intent,
        send_by,
        send_deadline,
        timeout,
        recorder,
        signer_kind,
        witness,
    } = phase;
    let retry_policy = RetryPolicy::default();
    let redacted = redact_tx_hash(&intent.tx_hash);

    // Submit via `sendTransaction`, with bounded exponential-backoff retry for
    // transient transport errors and `TRY_AGAIN_LATER` answers.
    //
    // Safety: retrying the same signed envelope is safe because the receipt
    // the recorder wrote before the send is keyed on the envelope hash and
    // the submission's `(source, sequence)`: a retried send that already
    // landed is caught by that record, and a second submission for the same
    // sequence is refused before it is built. Do NOT remove or bypass the
    // recorder when using this retry.
    //
    // `TransactionSubmissionFailed` is NOT retried — it wraps both genuine
    // on-chain rejections AND transport-429-on-send, and those are
    // indistinguishable here without fragile Display-string matching.
    // Retry-After / transport-429-on-send is not currently honoured; blind backoff is used instead.
    let server_tx_hash = retry_with_backoff_started_by(
        &retry_policy,
        send_deadline,
        send_by,
        is_retryable_send_error,
        || {
            let answer = send(envelope);
            async move { lose_send_answer(answer.await.and_then(crate::client::accepted_hash)) }
        },
    )
    .await;

    let server_tx_hash = match server_tx_hash {
        Ok(h) => h,
        Err(StartedByError::StartByPassed { attempts }) => {
            return Err(
                refuse_past_send_by(url, intent, attempts, timeout, recorder, witness).await,
            );
        }
        Err(StartedByError::Failed(e)) => {
            return Err(SentByError::Failed(
                handle_send_failure(recorder, intent, &e, url, timeout.as_secs(), witness).await,
            ));
        }
    };

    // The endpoint reporting a different hash means it is not describing the
    // transaction that was sent. The receipt stays keyed on the local hash and
    // stays pending: what the endpoint did with the bytes is unknown.
    let server_tx_hash_hex = bytes_to_hex(&server_tx_hash.0);
    if server_tx_hash_hex != intent.tx_hash {
        let err = WalletError::Submission(SubmissionError::HashMismatch {
            local: intent.tx_hash.clone(),
            server: server_tx_hash_hex.clone(),
        });
        if let Some(rec) = recorder {
            rec.outcome(
                intent,
                &SubmissionOutcome::TransportAfterSend {
                    error: format!(
                        "the endpoint reported transaction hash {} for a transaction whose local hash is {}",
                        redact_tx_hash(&server_tx_hash_hex),
                        redacted
                    ),
                },
            )
            .await;
        }
        return Err(SentByError::Failed(err));
    }

    tracing::info!(tx_hash = %redacted, "submit_transaction_and_wait: transaction submitted");

    Ok(poll_for_confirmation(
        poll,
        url,
        send_deadline,
        timeout.as_secs(),
        intent,
        recorder,
        signer_kind,
        witness,
    )
    .await?)
}

/// Reports a submission whose send-by instant passed before a
/// `sendTransaction` attempt, after `attempts` earlier attempts, to the
/// recorder, and returns the refusal.
///
/// Before the first attempt nothing was sent: the submission is reported as
/// [`SubmissionOutcome::NotSent`], under the timeout code at `url`, or under
/// the mainnet authorization refusal on the authorized path, which is the
/// code its caller receives. The wallet's
/// [`WalletSubmissionRecorder`](crate::submission_record::WalletSubmissionRecorder)
/// then releases the reservation, closes the pending row and removes the
/// receipt. After an attempt the earlier send may have reached the network,
/// so it is reported as an unknown outcome, the refusal names the transaction
/// hash a reconciliation reads, and the record is retained.
async fn refuse_past_send_by(
    url: &RpcEndpoint,
    intent: &SubmissionIntent,
    attempts: u32,
    timeout: Duration,
    recorder: Option<&dyn SubmissionRecorder>,
    witness: FailureWitness<'_>,
) -> SentByError {
    let (outcome, sent_tx_hash) = if attempts == 0 {
        let code = match witness {
            FailureWitness::Primary => send_by_elapsed(url, timeout).code(),
            FailureWitness::Oracle(_) => {
                WalletError::Network(NetworkError::MainnetAuthorizationRefused).code()
            }
        };
        (
            SubmissionOutcome::NotSent {
                code: code.to_owned(),
                error: "the send-by deadline passed before sendTransaction; nothing was sent"
                    .to_owned(),
            },
            None,
        )
    } else {
        (
            SubmissionOutcome::TransportAfterSend {
                error: "the send-by deadline passed before a resend; the answer to the \
                        earlier send is unknown"
                    .to_owned(),
            },
            Some(intent.tx_hash.clone()),
        )
    };
    if let Some(rec) = recorder {
        rec.outcome(intent, &outcome).await;
    }
    SentByError::Elapsed {
        stage: PreSendStage::Send,
        sent_tx_hash,
    }
}

#[cfg(feature = "test-hooks")]
thread_local! {
    /// The accepted sends on this thread whose answer is still to be lost.
    static LOST_SEND_ANSWERS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Discards the endpoint's answer to the next `count` accepted sends on the
/// calling thread and reports a transport timeout in its place, so the resend
/// of the same envelope after a lost answer is reachable from a test.
///
/// No endpoint answer makes the RPC client report a retryable send error: it
/// reports every failed request as a submission failure. The toggle stands in
/// for a transport that lost the answer after the endpoint took the bytes;
/// the retry that follows it is the production one.
///
/// A test sets it on a current-thread runtime, where its own submission
/// sends. The count is per thread, so tests running in parallel do not
/// disturb each other.
///
/// Only compiled when the `test-hooks` Cargo feature is enabled. Never include
/// `test-hooks` in production or release builds.
#[cfg(feature = "test-hooks")]
#[doc(hidden)]
pub fn lose_send_answers_on_this_thread(count: usize) {
    LOST_SEND_ANSWERS.with(|lost| lost.set(count));
}

/// The send's answer, or a transport timeout in its place while answers on
/// this thread are to be lost under `test-hooks`.
#[allow(
    clippy::result_large_err,
    reason = "passes the RPC client's own send result through to its retry classification"
)]
fn lose_send_answer(
    answer: Result<stellar_xdr::Hash, stellar_rpc_client::Error>,
) -> Result<stellar_xdr::Hash, stellar_rpc_client::Error> {
    #[cfg(feature = "test-hooks")]
    if answer.is_ok()
        && LOST_SEND_ANSWERS.with(|lost| match lost.get().checked_sub(1) {
            Some(left) => {
                lost.set(left);
                true
            }
            None => false,
        })
    {
        return Err(stellar_rpc_client::Error::TransactionSubmissionTimeout);
    }
    answer
}

/// Polls `getTransaction` through `poll` until an answer ends the poll or
/// `send_deadline` passes, and reports the outcome to `recorder`.
///
/// `poll` issues one `getTransaction` request for the submitted transaction.
/// Each poll reads the raw answer: status, ledger and created-at are read as
/// received, and the result XDR is decoded only for a `FAILED` transaction, so
/// an answer whose meta the wallet cannot decode still confirms.
///
/// The deadline bounds every step. No poll request starts at or past it, an
/// in-flight request is cut at it, and each sleep between polls ends at it at
/// the latest. Tokio polls a request before its deadline timer, so an answer
/// can complete after the deadline; the deadline is therefore checked again
/// before the answer is read or any record changes. Every deadline exit
/// records [`SubmissionOutcome::Timeout`] and returns
/// [`SubmissionError::TxTimeout`]: an answer that arrives too late is not
/// accepted, and the hash it names is reconciled later.
///
/// Transient `JsonRpc(_)` errors are treated like `NOT_FOUND`: logged at debug
/// level and followed by the next poll, so a transient rate-limit does not
/// abort the submission. Every path ends at the deadline at the latest, even
/// when every poll errors.
///
/// A `FAILED` answer is reported as [`settle_failed_answer`] decides under
/// `witness`; the record and its reservation stand.
///
/// Keep in sync with the poll loop in `idempotent_submit.rs`: any change to
/// the deadline or retryable-error treatment here must be mirrored there.
#[allow(
    clippy::too_many_arguments,
    reason = "the poll seam plus the facts the record settles against"
)]
async fn poll_for_confirmation<P, F>(
    mut poll: P,
    url: &RpcEndpoint,
    send_deadline: tokio::time::Instant,
    timeout_secs: u64,
    intent: &SubmissionIntent,
    recorder: Option<&dyn SubmissionRecorder>,
    signer_kind: Option<SubmissionSignerKind>,
    witness: FailureWitness<'_>,
) -> Result<SubmissionResult, WalletError>
where
    P: FnMut() -> F,
    F: std::future::Future<Output = Result<TransactionRecord, stellar_rpc_client::Error>>,
{
    let redacted = redact_tx_hash(&intent.tx_hash);
    loop {
        // A sleep that reached the deadline ends the loop here, before another
        // request starts.
        if tokio::time::Instant::now() >= send_deadline {
            return Err(record_timeout(recorder, intent, timeout_secs).await);
        }
        // A request the endpoint holds open is cut at the deadline rather than
        // left to the transport's own 60 s bound.
        let Ok(poll_result) = tokio::time::timeout_at(send_deadline, poll()).await else {
            return Err(record_timeout(recorder, intent, timeout_secs).await);
        };
        // An answer that completed at or after the deadline is not read.
        if tokio::time::Instant::now() >= send_deadline {
            return Err(record_timeout(recorder, intent, timeout_secs).await);
        }

        let record = match poll_result {
            Ok(r) => r,
            Err(ref e) if is_retryable_poll_error(e) => {
                // Treat transient transport error as NOT_FOUND: log at debug
                // and poll again after the interval. The scrub bounds the error
                // display, which limits log volume from a hostile endpoint.
                let url_authority = url.authority();
                tracing::debug!(
                    tx_hash = %redacted,
                    rpc_url = %url_authority,
                    error = %url.scrub_display(e),
                    "submit_transaction_and_wait: transient getTransaction error \
                     (treating as NOT_FOUND, continuing poll)"
                );
                sleep_before_next_poll(POLL_INTERVAL, send_deadline).await;
                continue;
            }
            Err(e) => {
                // The bytes are already away, so the outcome is unknown and
                // the caller gets the shape the recovery protocol is written
                // against: the transaction hash, and a verb that settles it.
                // Without a recorder there is nothing to settle, so the
                // transport failure is reported as itself.
                let Some(rec) = recorder else {
                    return Err(map_rpc_error_generic(&e, url, timeout_secs));
                };
                rec.outcome(
                    intent,
                    &SubmissionOutcome::TransportAfterSend {
                        error: format!(
                            "the confirmation poll could not reach the endpoint: {}",
                            url.scrub_display(&e)
                        ),
                    },
                )
                .await;
                return Err(WalletError::Submission(SubmissionError::TxTimeout {
                    tx_hash: intent.tx_hash.clone(),
                    seconds: timeout_secs,
                }));
            }
        };

        match record.status() {
            "SUCCESS" => {
                let ledger = record.ledger().unwrap_or(0);
                tracing::info!(
                    tx_hash = %redacted,
                    ledger,
                    "submit_transaction_and_wait: confirmed"
                );
                if let Some(rec) = recorder {
                    rec.outcome(
                        intent,
                        &SubmissionOutcome::Success {
                            ledger,
                            created_at: record.created_at(),
                        },
                    )
                    .await;
                }
                return Ok(SubmissionResult {
                    tx_hash: intent.tx_hash.clone(),
                    ledger,
                    signer_kind,
                });
            }

            "FAILED" => {
                return Err(settle_failed_answer(
                    &record,
                    witness,
                    send_deadline,
                    timeout_secs,
                    intent,
                    recorder,
                )
                .await);
            }

            // NOT_FOUND: transaction not yet in a ledger. Continue polling.
            "NOT_FOUND" => {}

            other => {
                let Some(rec) = recorder else {
                    return Err(WalletError::Network(unexpected_status(url, "", other)));
                };
                rec.outcome(
                    intent,
                    &SubmissionOutcome::TransportAfterSend {
                        error: format!(
                            "the endpoint reported an unexpected transaction status: {}",
                            url.scrub(other)
                        ),
                    },
                )
                .await;
                return Err(WalletError::Submission(SubmissionError::TxTimeout {
                    tx_hash: intent.tx_hash.clone(),
                    seconds: timeout_secs,
                }));
            }
        }

        sleep_before_next_poll(POLL_INTERVAL, send_deadline).await;
    }
}

/// Reports a `FAILED` confirmation answer to the recorder, and builds the
/// error the caller returns.
///
/// Under [`FailureWitness::Primary`] the answer is reported as failed on
/// chain, and the failure it maps to is returned. Under
/// [`FailureWitness::Oracle`] the answer is a claim the oracle is consulted
/// about. Only the oracle's own `FAILED` for the same hash is reported as
/// failed on chain, under the code mapped from the oracle's record. Anything
/// else is reported as an unknown outcome, as for a lost answer, and the
/// caller gets the timeout shape. The wallet's
/// [`WalletSubmissionRecorder`](crate::submission_record::WalletSubmissionRecorder)
/// retains the reservation, the receipt and the pending audit row for every
/// one of these reports.
async fn settle_failed_answer(
    record: &TransactionRecord,
    witness: FailureWitness<'_>,
    send_deadline: tokio::time::Instant,
    timeout_secs: u64,
    intent: &SubmissionIntent,
    recorder: Option<&dyn SubmissionRecorder>,
) -> WalletError {
    let redacted = redact_tx_hash(&intent.tx_hash);
    let confirmed = match witness {
        FailureWitness::Primary => Ok(map_failed_record(record)),
        FailureWitness::Oracle(oracle) => oracle_failed_answer(oracle, intent, send_deadline)
            .await
            .map(|oracle_record| map_failed_record(&oracle_record)),
    };
    let err = match confirmed {
        Ok(err) => err,
        Err(unconfirmed) => {
            tracing::warn!(
                tx_hash = %redacted,
                reason = %unconfirmed,
                "submit_transaction_and_wait: the endpoint reported the transaction failed and \
                 the oracle did not confirm it; the record stands"
            );
            if let Some(rec) = recorder {
                rec.outcome(
                    intent,
                    &SubmissionOutcome::TransportAfterSend {
                        error: format!(
                            "the endpoint reported the transaction FAILED and the oracle did not \
                             confirm it: {unconfirmed}"
                        ),
                    },
                )
                .await;
            }
            return WalletError::Submission(SubmissionError::TxTimeout {
                tx_hash: intent.tx_hash.clone(),
                seconds: timeout_secs,
            });
        }
    };
    tracing::warn!(
        tx_hash = %redacted,
        error = %err,
        "submit_transaction_and_wait: transaction failed on-chain"
    );
    if let Some(rec) = recorder {
        rec.outcome(
            intent,
            &SubmissionOutcome::OnChainFailed {
                code: err.code().to_owned(),
            },
        )
        .await;
    }
    err
}

/// Asks `oracle` for the submission's transaction, bounded by `deadline`,
/// and returns its answer when that answer is `FAILED`.
///
/// The oracle's answer counts only once the oracle reports the mainnet
/// passphrase: its identity is checked first, within the same deadline, and
/// an oracle that serves another network or whose identity cannot be read
/// confirms nothing.
///
/// # Errors
///
/// Why the oracle did not confirm the failure, as non-secret text: no oracle,
/// a failed identity check, no answer before the deadline, a read error, or
/// an answer other than `FAILED`.
async fn oracle_failed_answer(
    oracle: Option<&StellarRpcClient>,
    intent: &SubmissionIntent,
    deadline: tokio::time::Instant,
) -> Result<TransactionRecord, String> {
    let Some(oracle) = oracle else {
        return Err("the profile names no oracle".to_owned());
    };
    let oracle = MainnetOracle::verify(oracle, deadline)
        .await
        .map_err(|e| format!("the oracle did not establish that it serves mainnet: {e}"))?;
    oracle_failed_record(oracle, intent, deadline).await
}

/// Reads the verified oracle's answer for the submission's transaction,
/// bounded by `deadline`, and returns it when it is `FAILED`.
///
/// An answer that completes at or after the deadline is not read, as in the
/// confirmation poll.
///
/// # Errors
///
/// As [`oracle_failed_answer`], without the identity cases.
async fn oracle_failed_record(
    oracle: MainnetOracle<'_>,
    intent: &SubmissionIntent,
    deadline: tokio::time::Instant,
) -> Result<TransactionRecord, String> {
    let oracle = oracle.client();
    let hash = tx_hash_bytes(&intent.tx_hash).map_err(|e| e.to_string())?;
    let answer = tokio::time::timeout_at(
        deadline,
        oracle.get_transaction_record(&stellar_xdr::Hash(hash)),
    )
    .await;
    if tokio::time::Instant::now() >= deadline {
        return Err("the oracle did not answer before the submission deadline".to_owned());
    }
    match answer {
        Err(_) => Err("the oracle did not answer before the submission deadline".to_owned()),
        Ok(Err(e)) => Err(format!(
            "the oracle could not be read: {}",
            oracle.url.scrub_display(&e)
        )),
        Ok(Ok(record)) if record.status() == "FAILED" => Ok(record),
        Ok(Ok(record)) => Err(format!(
            "the oracle reported {}",
            oracle.url.scrub(record.status())
        )),
    }
}

/// Sleeps `interval` before the next confirmation poll, or until `deadline`
/// when that comes first.
///
/// A poll interval never carries a submission past its deadline: the loop
/// that sleeps here checks the deadline before its next request.
pub(crate) async fn sleep_before_next_poll(interval: Duration, deadline: tokio::time::Instant) {
    tokio::time::sleep_until(deadline.min(tokio::time::Instant::now() + interval)).await;
}

/// Reports a timeout to `recorder` for a submission whose confirmation never
/// arrived, and builds the timeout the caller returns.
///
/// The transaction was accepted for inclusion and may still apply, so the
/// receipt, the pending audit row and the window reservation all stand. The
/// agent resolves it by reconciling the hash, never by re-simulating.
async fn record_timeout(
    recorder: Option<&dyn SubmissionRecorder>,
    intent: &SubmissionIntent,
    seconds: u64,
) -> WalletError {
    if let Some(rec) = recorder {
        rec.outcome(
            intent,
            &SubmissionOutcome::Timeout {
                tx_hash: intent.tx_hash.clone(),
            },
        )
        .await;
    }
    WalletError::Submission(SubmissionError::TxTimeout {
        tx_hash: intent.tx_hash.clone(),
        seconds,
    })
}

/// Reports a send that did not return a transaction hash to the recorder, and
/// builds the error the caller returns.
///
/// Two classes, and they return different errors:
///
/// - The endpoint refused the bytes with a real `TransactionResult`. The
///   submission is reported as rejected, and the caller gets the refusal
///   itself, with its result code. The bytes left the wallet, so the wallet's
///   [`WalletSubmissionRecorder`](crate::submission_record::WalletSubmissionRecorder)
///   retains the reservation, the receipt and the pending audit row.
/// - Anything else left the outcome unknown. The layer cannot tell a refused
///   connection from a lost response, and by this point the same client has
///   already answered the identity probe and the signer fetch, so the failure
///   is mid-flight rather than a dead endpoint. The record stands and the
///   caller gets the timeout shape, which is what the agent's recovery
///   protocol is written against.
///
/// Under [`FailureWitness::Oracle`] a refusal settles nothing either: it is
/// the endpoint's word alone, and no oracle can confirm it because a refused
/// transaction has no record. It is recorded as an unknown outcome naming
/// the refusal, and the caller gets the timeout shape.
async fn handle_send_failure(
    recorder: Option<&dyn SubmissionRecorder>,
    intent: &SubmissionIntent,
    error: &stellar_rpc_client::Error,
    url: &RpcEndpoint,
    timeout_secs: u64,
    witness: FailureWitness<'_>,
) -> WalletError {
    let mapped = map_send_error(error, url, timeout_secs);
    let definitive = is_definitive_send_refusal(error);

    let Some(rec) = recorder else {
        return mapped;
    };

    if definitive && matches!(witness, FailureWitness::Oracle(_)) {
        tracing::warn!(
            tx_hash = %redact_tx_hash(&intent.tx_hash),
            code = mapped.code(),
            "submit_transaction_and_wait: the endpoint refused the send; without an independent \
             witness the record stands"
        );
        rec.outcome(
            intent,
            &SubmissionOutcome::TransportAfterSend {
                error: format!(
                    "the endpoint refused the send with {}, which no independent answer \
                     confirms: {}",
                    mapped.code(),
                    url.scrub_display(error)
                ),
            },
        )
        .await;
        return WalletError::Submission(SubmissionError::TxTimeout {
            tx_hash: intent.tx_hash.clone(),
            seconds: timeout_secs,
        });
    }

    if definitive {
        rec.outcome(
            intent,
            &SubmissionOutcome::Rejected {
                code: mapped.code().to_owned(),
                error: url.scrub_display(error),
            },
        )
        .await;
        return mapped;
    }

    rec.outcome(
        intent,
        &SubmissionOutcome::TransportAfterSend {
            error: format!(
                "the send did not complete and the endpoint's answer is unknown: {}",
                url.scrub_display(error)
            ),
        },
    )
    .await;
    WalletError::Submission(SubmissionError::TxTimeout {
        tx_hash: intent.tx_hash.clone(),
        seconds: timeout_secs,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Hex-encodes a byte slice (lowercase).
///
/// Single canonical definition shared with `idempotent_submit.rs` and
/// `fee_bump_retry.rs`.
pub(crate) fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// The marker `stellar-rpc-client` puts on a `sendTransaction` failure where
/// no response body was read.
///
/// `stellar_rpc_client::Error::TransactionSubmissionFailed` carries two
/// unrelated conditions: a request that never produced a response, which the
/// client prefixes with this marker, and an endpoint that answered
/// `status: "ERROR"` with a decoded `TransactionResult`, whose message is that
/// result. The two return different errors to the caller, so they have to be
/// told apart.
const SEND_NO_RESPONSE_MARKER: &str = "No status yet:";

/// Returns true when the send step's failure is the endpoint's own verdict on
/// the transaction.
///
/// The test is negative on purpose. A failure the layer cannot positively
/// attribute to a verdict is treated as one whose outcome is unknown, which is
/// the direction that keeps a transaction that may have been queued recorded.
/// A lost response classified as a verdict reports a refusal code instead of
/// the timeout shape for a transaction that can still apply.
///
/// # Dependency coupling
///
/// The marker is the dependency's own wording, not a contract it publishes:
/// `stellar-rpc-client`'s `send_transaction` builds it at
/// `src/lib.rs`, in the arm that wraps a `jsonrpsee` request failure, while
/// the arm that wraps an endpoint verdict carries the decoded
/// `TransactionResult` instead. A version bump that rewords either arm
/// reclassifies every transport failure as a verdict, which reports a
/// refusal code instead of the timeout shape for a transaction that may have
/// been queued.
///
/// Both sides are pinned against the real client by
/// `a_transport_failure_after_the_record_returns_the_timeout_shape` and
/// `a_refused_send_retains_the_reservation_and_sequence`
/// (`tests/network/submission_record_integration.rs`), which drive a mocked endpoint
/// through the real client. A reword fails those two rather than silently
/// reclassifying submissions, so a `stellar-rpc-client` bump that turns them
/// red is reporting this coupling, not a flake.
fn is_definitive_send_refusal(error: &stellar_rpc_client::Error) -> bool {
    match error {
        stellar_rpc_client::Error::TransactionSubmissionFailed(detail) => {
            !detail.contains(SEND_NO_RESPONSE_MARKER)
        }
        _ => false,
    }
}

/// Computes the canonical transaction hash from a decoded envelope.
///
/// `SHA-256(network_id ‖ tagged transaction)`, the same preimage the signing
/// path builds, so it needs no round trip. A fee-bump hashes its OUTER
/// transaction: that is what `getTransaction` is polled by, and stellar-rpc
/// indexes a fee-bump under both its outer and inner hash.
///
/// # Errors
///
/// - [`WalletError::Protocol`] wrapping [`ProtocolError::XdrCodecFailed`] for
///   a legacy `TxV0` envelope, which has no tagged-transaction form, or if the
///   payload cannot be encoded.
pub(crate) fn compute_local_tx_hash_hex(
    envelope: &TransactionEnvelope,
    network_passphrase: &str,
) -> Result<String, WalletError> {
    use sha2::{Digest as _, Sha256};
    use stellar_xdr::{
        Hash, Limits, TransactionSignaturePayload, TransactionSignaturePayloadTaggedTransaction,
        WriteXdr,
    };

    let tagged_transaction = match envelope {
        TransactionEnvelope::Tx(v1) => {
            TransactionSignaturePayloadTaggedTransaction::Tx(v1.tx.clone())
        }
        TransactionEnvelope::TxFeeBump(fb) => {
            TransactionSignaturePayloadTaggedTransaction::TxFeeBump(fb.tx.clone())
        }
        TransactionEnvelope::TxV0(_) => {
            return Err(WalletError::Protocol(ProtocolError::XdrCodecFailed {
                detail: "a legacy TxV0 envelope has no tagged-transaction form and cannot be \
                         hashed or signed"
                    .to_owned(),
            }));
        }
    };

    let payload = TransactionSignaturePayload {
        network_id: Hash(Sha256::digest(network_passphrase.as_bytes()).into()),
        tagged_transaction,
    };
    let payload_bytes = payload.to_xdr(Limits::none()).map_err(|e| {
        WalletError::Protocol(ProtocolError::XdrCodecFailed {
            detail: format!("failed to encode TransactionSignaturePayload: {e}"),
        })
    })?;

    Ok(bytes_to_hex(&Sha256::digest(&payload_bytes)))
}

/// Returns the `(source account, sequence)` pair the network enforces replay
/// protection on.
///
/// A fee-bump's replay identity is its INNER transaction's: the fee source
/// consumes no sequence of its own.
///
/// A muxed source resolves to its underlying account. The mux id selects a
/// sub-account for memo purposes; the sequence number, the signer set and the
/// ledger entry all belong to the `G...` account beneath it, which is what the
/// network enforces replay protection on.
///
/// # Errors
///
/// - [`WalletError::Protocol`] wrapping [`ProtocolError::XdrCodecFailed`] for
///   a legacy `TxV0` envelope.
pub(crate) fn replay_identity(
    envelope: &TransactionEnvelope,
) -> Result<(String, i64), WalletError> {
    let tx = match envelope {
        TransactionEnvelope::Tx(v1) => &v1.tx,
        TransactionEnvelope::TxFeeBump(fb) => {
            let stellar_xdr::FeeBumpTransactionInnerTx::Tx(inner) = &fb.tx.inner_tx;
            &inner.tx
        }
        TransactionEnvelope::TxV0(_) => {
            return Err(WalletError::Protocol(ProtocolError::XdrCodecFailed {
                detail: "a legacy TxV0 envelope is refused before the replay identity is read"
                    .to_owned(),
            }));
        }
    };

    let key = match &tx.source_account {
        stellar_xdr::MuxedAccount::Ed25519(uint256) => uint256.0,
        stellar_xdr::MuxedAccount::MuxedEd25519(med) => med.ed25519.0,
    };

    Ok((
        format!("{}", stellar_strkey::ed25519::PublicKey(key)),
        tx.seq_num.0,
    ))
}

/// `SHA-256` over the signed envelope XDR, the identity of these exact bytes.
///
/// This is the key the submission receipt and the window reservation are
/// stored under, so a caller that needs to name a submission in a response or
/// an operator verb derives it the same way here.
#[must_use]
pub fn envelope_hash_hex(envelope_xdr: &str) -> String {
    use sha2::{Digest as _, Sha256};
    bytes_to_hex(&Sha256::digest(envelope_xdr.as_bytes()))
}

/// Parses a 64-character hex transaction hash into its raw bytes.
fn tx_hash_bytes(hex: &str) -> Result<[u8; 32], WalletError> {
    stellar_agent_core::hex::decode_hex32(hex).map_err(|e| {
        WalletError::Protocol(ProtocolError::XdrCodecFailed {
            detail: format!("computed transaction hash is not 32 hex-encoded bytes: {e}"),
        })
    })
}

/// Returns true if the URL appears to target Stellar mainnet / pubnet.
///
/// Best-effort heuristic for the second-layer mainnet guard. Catches
/// programmatic callers that supply a mainnet RPC URL regardless of how
/// the network passphrase is configured.
fn is_mainnet_url(url: &str) -> bool {
    let lower = url.to_lowercase();
    // Known SDF mainnet RPC hostnames.
    lower.contains("mainnet.stellar")
        || lower.contains("horizon.stellar.org")
        || lower.contains("pubnet")
}

/// Refuses a ledger write declared for mainnet or aimed at a mainnet-pattern
/// endpoint.
///
/// Two local checks run, and either one refuses:
///
/// - `network_passphrase` equals the mainnet passphrase. This is the primary
///   check, and it holds for any provider whatever its hostname.
/// - `rpc_url` matches a known mainnet host pattern (`mainnet.stellar`,
///   `horizon.stellar.org`, or `pubnet`, compared case-insensitively). This
///   heuristic complements the passphrase check for a mainnet endpoint paired
///   with another network's passphrase.
///
/// Neither check establishes which network an endpoint serves. The endpoint
/// probe in the submit path of [`submit_transaction_and_wait`] remains the
/// check that an endpoint is what it claims. The function performs no I/O.
///
/// # Errors
///
/// [`NetworkError::MainnetWriteForbidden`] if either check holds.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::error::NetworkError;
/// use stellar_agent_network::refuse_mainnet_write;
///
/// let testnet = "Test SDF Network ; September 2015";
/// let mainnet = "Public Global Stellar Network ; September 2015";
/// assert!(refuse_mainnet_write(testnet, "https://soroban-testnet.stellar.org").is_ok());
/// assert!(matches!(
///     refuse_mainnet_write(mainnet, "https://soroban-testnet.stellar.org"),
///     Err(NetworkError::MainnetWriteForbidden)
/// ));
/// assert!(matches!(
///     refuse_mainnet_write(testnet, "https://rpc.pubnet.example.org"),
///     Err(NetworkError::MainnetWriteForbidden)
/// ));
/// ```
pub fn refuse_mainnet_write(network_passphrase: &str, rpc_url: &str) -> Result<(), NetworkError> {
    if network_passphrase == MAINNET_PASSPHRASE {
        return Err(NetworkError::MainnetWriteForbidden);
    }
    if is_mainnet_url(rpc_url) {
        return Err(NetworkError::MainnetWriteForbidden);
    }
    Ok(())
}

/// Redacts a transaction hash to first-8-last-8 format for log emission.
///
/// Exported so `stellar-agent-cli` can reuse this without maintaining a
/// duplicate implementation.
pub fn redact_tx_hash(hash: &str) -> String {
    if hash.len() > 16 {
        format!("{}...{}", &hash[..8], &hash[hash.len() - 8..])
    } else {
        hash.to_owned()
    }
}

/// Maps a `sendTransaction` RPC error to a [`WalletError`].
///
/// `timeout_secs` is the actual caller-configured timeout, used in the
/// `RpcTimeout` variant so the value is accurate rather than hardcoded.
///
/// Every text field is scrubbed with [`RpcEndpoint::scrub`] before it enters
/// the error, because the client's submission-failure message and the error
/// display both carry server text.
fn map_send_error(
    e: &stellar_rpc_client::Error,
    url: &RpcEndpoint,
    timeout_secs: u64,
) -> WalletError {
    use stellar_rpc_client::Error as RpcErr;
    match e {
        RpcErr::TransactionSubmissionFailed(msg) => {
            WalletError::Submission(SubmissionError::TxMalformed {
                detail: url.scrub(msg),
            })
        }
        RpcErr::TransactionSubmissionTimeout => WalletError::Network(NetworkError::RpcTimeout {
            url: url.authority(),
            timeout_secs,
        }),
        RpcErr::Xdr(_) => WalletError::Protocol(ProtocolError::XdrCodecFailed {
            detail: url.scrub_display(e),
        }),
        _ => WalletError::Network(rpc_unreachable(url, "", e)),
    }
}

/// Maps a generic RPC error to [`WalletError`].
///
/// `timeout_secs` is the actual caller-configured timeout, used in the
/// `RpcTimeout` variant so the value is accurate rather than hardcoded.
///
/// Every text field takes the error display scrubbed with
/// [`RpcEndpoint::scrub`], because that display can carry server text.
fn map_rpc_error_generic(
    e: &stellar_rpc_client::Error,
    url: &RpcEndpoint,
    timeout_secs: u64,
) -> WalletError {
    use stellar_rpc_client::Error as RpcErr;
    match e {
        RpcErr::TransactionSubmissionTimeout => WalletError::Network(NetworkError::RpcTimeout {
            url: url.authority(),
            timeout_secs,
        }),
        RpcErr::Xdr(_) => WalletError::Protocol(ProtocolError::XdrCodecFailed {
            detail: url.scrub_display(e),
        }),
        _ => WalletError::Network(rpc_unreachable(url, "", e)),
    }
}

/// Maps a `FAILED` `getTransaction` answer to its typed [`WalletError`].
///
/// Decodes the answer's result XDR and delegates to [`map_failed_result`].
/// A result that does not decode yields [`LedgerError::OpFailed`] with op
/// `unknown` and a reason naming the undecodable result, the variant
/// [`map_failed_result`] gives an absent result, so the stable code stays
/// `ledger.op_failed`. The reason is the display of the typed decode error
/// [`TransactionRecord::result`] returns: wallet-formatted text around the
/// XDR decoder's own error message, which carries no bytes from the response,
/// so its length is bounded by construction. A `FAILED` status is definitive either way: the
/// transaction did not apply, and the caller neither retries nor waits.
///
/// Every `FAILED` arm that reads a `getTransaction` answer calls this, so the
/// returned error and a receipt's `Failed { code }` derive from one path.
pub(crate) fn map_failed_record(record: &TransactionRecord) -> WalletError {
    match record.result() {
        Ok(result) => map_failed_result(result.as_ref()),
        Err(e) => WalletError::Ledger(LedgerError::OpFailed {
            op: "unknown".to_owned(),
            result_code: format!("undecodable result XDR: {e}"),
        }),
    }
}

/// Maps a `getTransaction` FAILED response's `TransactionResult` to a typed
/// [`WalletError`].
///
/// # TxBadSeq typed mapping
///
/// `TransactionResultResult::TxBadSeq` is mapped to
/// [`SubmissionError::SequenceNumberStale`] (code
/// `submission.sequence_number_stale`).  This typed arm is matched before
/// the catch-all `other => OpFailed` branch so that callers can match the
/// stable error code rather than relying on Display-string substring matching.
///
/// # TxFeeBumpInnerFailed typed mapping
///
/// `TransactionResultResult::TxFeeBumpInnerFailed(pair)` is mapped to
/// [`SubmissionError::FeeBumpInnerRejected`] (code
/// `submission.feebump_inner_rejected`).  The inner result code is the
/// `InnerTransactionResultResult` variant NAME only (no op-level detail);
/// the inner tx hash is redacted to first-8-last-8.
///
/// `TransactionResultResult::TxFeeBumpInnerSuccess(pair)` maps defensively to
/// `OpFailed` — the inner tx applied, so this is not a rejection path.
///
/// Every `FAILED` arm reaches this through [`map_failed_record`], which
/// decodes the answer's result XDR first, so the receipt's `Failed { code }`
/// string and the returned `WalletError` are always derived from the same
/// XDR path.
pub(crate) fn map_failed_result(result: Option<&TransactionResult>) -> WalletError {
    let Some(result) = result else {
        return WalletError::Ledger(LedgerError::OpFailed {
            op: "unknown".to_owned(),
            result_code: "unknown (no result XDR)".to_owned(),
        });
    };

    match &result.result {
        TransactionResultResult::TxSuccess(_ops) => {
            // Shouldn't reach here if status == FAILED, but handle defensively.
            WalletError::Ledger(LedgerError::OpFailed {
                op: "unknown".to_owned(),
                result_code: "FAILED_with_TxSuccess_result (unexpected)".to_owned(),
            })
        }
        // Typed TxBadSeq arm: maps to SequenceNumberStale so callers can match
        // the stable code "submission.sequence_number_stale" rather than
        // substring-matching Debug output.
        TransactionResultResult::TxBadSeq => {
            WalletError::Submission(SubmissionError::SequenceNumberStale)
        }
        TransactionResultResult::TxFailed(ops) => {
            // Inspect the first operation result using typed enum matching.
            // Avoids fragile Debug-string inspection.
            if let Some(first_op) = ops.first() {
                map_operation_result(first_op)
            } else {
                WalletError::Ledger(LedgerError::OpFailed {
                    op: "unknown".to_owned(),
                    result_code: "TxFailed (no op results)".to_owned(),
                })
            }
        }
        // Fee-bump inner-failed arm: maps to FeeBumpInnerRejected.
        //
        // `InnerTransactionResultPair.result.result` carries the
        // `InnerTransactionResultResult` discriminant.  We emit ONLY the
        // variant NAME — no op-level detail — to avoid leaking secret
        // operation inputs.
        //
        // `TxFeeBumpInnerSuccess` is the corresponding success case; its
        // presence in the FAILED status branch should not occur in practice
        // but we map it defensively.
        TransactionResultResult::TxFeeBumpInnerFailed(pair) => {
            let inner_result_code = inner_result_code_name(&pair.result.result);
            let inner_tx_hash_redacted = redact_tx_hash(&bytes_to_hex(&pair.transaction_hash.0));
            WalletError::Submission(SubmissionError::FeeBumpInnerRejected {
                inner_result_code,
                inner_tx_hash_redacted,
            })
        }
        // Fee-bump inner-success in FAILED branch: against stellar-rpc 26.x, inner-applied
        // fee-bumps surface as status:SUCCESS, never FAILED (stellar-go confirms this).
        // Mapped defensively to OpFailed to avoid silently masking an unexpected
        // protocol change. Retention/reorg handling prevents double-apply on a genuine retry.
        TransactionResultResult::TxFeeBumpInnerSuccess(_pair) => {
            WalletError::Ledger(LedgerError::OpFailed {
                op: "fee_bump".to_owned(),
                result_code: "FAILED_with_TxFeeBumpInnerSuccess_result (unexpected)".to_owned(),
            })
        }
        other => WalletError::Ledger(LedgerError::OpFailed {
            op: "unknown".to_owned(),
            result_code: format!("{other:?}"),
        }),
    }
}

/// Returns the public enum-variant NAME of an [`InnerTransactionResultResult`]
/// discriminant without including any operation-level detail.
///
/// The variant name is a public protocol constant; the `OperationResult`
/// payloads inside `TxSuccess`/`TxFailed` may embed account IDs or amounts
/// that must not appear in error messages.
///
/// # Stable wire contract
///
/// The strings returned by this function are surfaced in
/// [`SubmissionError::FeeBumpInnerRejected`]'s `inner_result_code` field,
/// which is part of the stable wire contract for that error variant.  Callers
/// and downstream tools may match on these strings; rename only with a
/// `Changed` CHANGELOG entry and a major-version bump.
fn inner_result_code_name(result: &InnerTransactionResultResult) -> String {
    // Match each variant and return its canonical XDR-spec name.
    // The names are the exact discriminant strings used in the XDR union definition.
    match result {
        InnerTransactionResultResult::TxSuccess(_) => "TxSuccess",
        InnerTransactionResultResult::TxFailed(_) => "TxFailed",
        InnerTransactionResultResult::TxTooEarly => "TxTooEarly",
        InnerTransactionResultResult::TxTooLate => "TxTooLate",
        InnerTransactionResultResult::TxMissingOperation => "TxMissingOperation",
        InnerTransactionResultResult::TxBadSeq => "TxBadSeq",
        InnerTransactionResultResult::TxBadAuth => "TxBadAuth",
        InnerTransactionResultResult::TxInsufficientBalance => "TxInsufficientBalance",
        InnerTransactionResultResult::TxNoAccount => "TxNoAccount",
        InnerTransactionResultResult::TxInsufficientFee => "TxInsufficientFee",
        InnerTransactionResultResult::TxBadAuthExtra => "TxBadAuthExtra",
        InnerTransactionResultResult::TxInternalError => "TxInternalError",
        InnerTransactionResultResult::TxNotSupported => "TxNotSupported",
        InnerTransactionResultResult::TxBadSponsorship => "TxBadSponsorship",
        InnerTransactionResultResult::TxBadMinSeqAgeOrGap => "TxBadMinSeqAgeOrGap",
        InnerTransactionResultResult::TxMalformed => "TxMalformed",
        InnerTransactionResultResult::TxSorobanInvalid => "TxSorobanInvalid",
        InnerTransactionResultResult::TxFrozenKeyAccessed => "TxFrozenKeyAccessed",
    }
    .to_owned()
}

/// Maps a single [`OperationResult`] to a typed [`WalletError`] ledger error.
///
/// Uses typed enum matching on `OperationResultTr::Payment(PaymentResult::*)`
/// so the mapping is stable against upstream XDR Debug-format changes.
fn map_operation_result(op: &OperationResult) -> WalletError {
    match op {
        OperationResult::OpInner(OperationResultTr::Payment(payment_result)) => {
            match payment_result {
                PaymentResult::Underfunded => {
                    WalletError::Ledger(LedgerError::InsufficientBalance {
                        asset: "XLM".to_owned(),
                        have: "unknown".to_owned(),
                        need: "unknown".to_owned(),
                    })
                }
                PaymentResult::NoTrust => WalletError::Ledger(LedgerError::TrustlineMissing {
                    asset: "unknown".to_owned(),
                    account: "destination".to_owned(),
                }),
                PaymentResult::SrcNoTrust => WalletError::Ledger(LedgerError::TrustlineMissing {
                    asset: "unknown".to_owned(),
                    account: "source".to_owned(),
                }),
                PaymentResult::NoDestination => {
                    WalletError::Ledger(LedgerError::DestinationInvalid {
                        destination: "unknown".to_owned(),
                    })
                }
                other => WalletError::Ledger(LedgerError::OpFailed {
                    op: "Payment".to_owned(),
                    result_code: format!("{other:?}"),
                }),
            }
        }
        OperationResult::OpBadAuth => WalletError::Ledger(LedgerError::OpFailed {
            op: "unknown".to_owned(),
            result_code: "op_bad_auth".to_owned(),
        }),
        OperationResult::OpNoAccount => WalletError::Ledger(LedgerError::OpFailed {
            op: "unknown".to_owned(),
            result_code: "op_no_account".to_owned(),
        }),
        other => WalletError::Ledger(LedgerError::OpFailed {
            op: "unknown".to_owned(),
            result_code: format!("{other:?}"),
        }),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics and unwraps are acceptable in unit tests"
    )]

    use super::*;
    use crate::poll_test_support::{answer, assert_answer_wins_at_deadline};
    use crate::redact::rpc_error_fixtures::{
        ENDPOINT, ENDPOINT_AUTHORITY, ERROR_OBJECTS, assert_scrubbed, call_client_error,
        call_error, xdr_error,
    };

    /// An envelope that fails to decode is refused by its accepted form, with
    /// no decoder diagnostic, for malformed base64 and for malformed XDR.
    #[tokio::test]
    async fn undecodable_envelope_reports_the_accepted_form() {
        use base64::Engine as _;
        let client = StellarRpcClient::new("http://127.0.0.1:9").unwrap();
        let xdr = base64::engine::general_purpose::STANDARD.encode([0xAA_u8; 64]);
        for envelope in ["~", xdr.as_str()] {
            let error = submit_transaction_and_wait(
                &client,
                envelope,
                Duration::from_secs(1),
                "Test SDF Network ; September 2015",
                None,
                None,
            )
            .await
            .unwrap_err();
            assert_eq!(error.code(), "protocol.xdr_codec_failed");
            let text = error.to_string();
            assert_eq!(
                text,
                "XDR codec operation failed: failed to decode TransactionEnvelope from base64 \
                 XDR: must be base64-encoded TransactionEnvelope XDR"
            );
            assert!(!format!("{error:?}").contains("Invalid symbol"));
        }
    }

    #[tokio::test]
    async fn muxed_contract_submit_refuses_before_network() {
        let endpoint = format!("http://{}:9", std::net::Ipv4Addr::LOCALHOST);
        let client = StellarRpcClient::new(&endpoint).unwrap();
        let encoded = stellar_agent_test_support::xdr_fixtures::muxed_contract_envelope();
        let error = submit_transaction_and_wait(
            &client,
            &encoded,
            Duration::from_secs(1),
            "Test SDF Network ; September 2015",
            None,
            None,
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), "protocol.xdr_codec_failed");
        assert!(
            error
                .to_string()
                .ends_with("a muxed contract address (W) is not accepted on this path")
        );
    }

    #[cfg(feature = "mainnet-write")]
    #[tokio::test]
    #[serial_test::serial]
    async fn muxed_contract_authorized_submit_refuses_without_recording() {
        use crate::mainnet::{MainnetConsumer, test_support::AuthorizedSubmissionFixture};
        let f = AuthorizedSubmissionFixture::new("muxed", 1_800_000_000_000);
        let endpoint = format!("http://{}:9", std::net::Ipv4Addr::LOCALHOST);
        let client = StellarRpcClient::new(&endpoint).unwrap();
        let (id, grant) = f.grant(&f.envelope(1, 1_800_000_120), &client, None, "nonce");
        let before = std::fs::read(f.window_store_path()).unwrap();
        let recorder = f.recorder(None, f.writer());
        let result = submit_authorized_transaction_and_wait(
            &client,
            None,
            &stellar_agent_test_support::xdr_fixtures::muxed_contract_envelope(),
            Duration::from_secs(1),
            "Public Global Stellar Network ; September 2015",
            None,
            &recorder,
            MainnetConsumer::CliPay,
            grant,
        )
        .await;
        assert_eq!(result.unwrap_err().code(), "protocol.xdr_codec_failed");
        assert!(f.is_open(id));
        assert_eq!(std::fs::read(f.window_store_path()).unwrap(), before);
    }

    /// The send step's failure message, in the form the RPC client renders a
    /// JSON-RPC error object it got instead of a status, keeps its own wording
    /// and only the echoed host and port.
    #[test]
    fn map_send_error_scrubs_a_submission_failure_message() {
        for (case, raw) in ERROR_OBJECTS {
            let msg = format!("No status yet:\n {:#?}", call_client_error(raw));
            let e = stellar_rpc_client::Error::TransactionSubmissionFailed(msg);
            match map_send_error(&e, &RpcEndpoint::plain(ENDPOINT), 30) {
                WalletError::Submission(SubmissionError::TxMalformed { detail }) => {
                    assert!(
                        detail.starts_with(&format!("\"{SEND_NO_RESPONSE_MARKER} ")),
                        "{case}: the detail quotes the message without a prefix: {detail}"
                    );
                    assert_scrubbed(case, &detail);
                }
                other => panic!("{case}: expected TxMalformed, got {other:?}"),
            }
        }
    }

    /// An XDR error on the send step keeps only the echoed host and port.
    #[test]
    fn map_send_error_scrubs_an_xdr_error() {
        match map_send_error(&xdr_error(), &RpcEndpoint::plain(ENDPOINT), 30) {
            WalletError::Protocol(ProtocolError::XdrCodecFailed { detail }) => {
                assert_scrubbed("xdr", &detail);
            }
            other => panic!("expected XdrCodecFailed, got {other:?}"),
        }
    }

    /// Any other send error, here a JSON-RPC error object, keeps only the
    /// echoed host and port in its reason.
    #[test]
    fn map_send_error_scrubs_a_json_rpc_error_object() {
        for (case, raw) in ERROR_OBJECTS {
            match map_send_error(&call_error(raw), &RpcEndpoint::plain(ENDPOINT), 30) {
                WalletError::Network(NetworkError::RpcUnreachable { url, reason }) => {
                    assert_eq!(url, ENDPOINT_AUTHORITY, "{case}");
                    assert_scrubbed(case, &reason);
                }
                other => panic!("{case}: expected RpcUnreachable, got {other:?}"),
            }
        }
    }

    /// An XDR error on the poll step keeps only the echoed host and port.
    #[test]
    fn map_rpc_error_generic_scrubs_an_xdr_error() {
        match map_rpc_error_generic(&xdr_error(), &RpcEndpoint::plain(ENDPOINT), 30) {
            WalletError::Protocol(ProtocolError::XdrCodecFailed { detail }) => {
                assert_scrubbed("xdr", &detail);
            }
            other => panic!("expected XdrCodecFailed, got {other:?}"),
        }
    }

    /// A JSON-RPC error object on the poll step keeps only the echoed host
    /// and port in its reason.
    #[test]
    fn map_rpc_error_generic_scrubs_a_json_rpc_error_object() {
        for (case, raw) in ERROR_OBJECTS {
            match map_rpc_error_generic(&call_error(raw), &RpcEndpoint::plain(ENDPOINT), 30) {
                WalletError::Network(NetworkError::RpcUnreachable { url, reason }) => {
                    assert_eq!(url, ENDPOINT_AUTHORITY, "{case}");
                    assert_scrubbed(case, &reason);
                }
                other => panic!("{case}: expected RpcUnreachable, got {other:?}"),
            }
        }
    }

    #[test]
    fn is_mainnet_url_detects_mainnet() {
        assert!(is_mainnet_url("https://mainnet.stellar.org"));
        assert!(is_mainnet_url("https://soroban.mainnet.stellar.org"));
        assert!(is_mainnet_url("https://pubnet.example.org"));
    }

    #[test]
    fn is_mainnet_url_allows_testnet() {
        assert!(!is_mainnet_url("https://soroban-testnet.stellar.org"));
        assert!(!is_mainnet_url("http://localhost:8000"));
        assert!(!is_mainnet_url("https://horizon-testnet.stellar.org"));
    }

    #[test]
    fn refuse_mainnet_write_refuses_mainnet_passphrase_with_testnet_url() {
        let result =
            refuse_mainnet_write(MAINNET_PASSPHRASE, "https://soroban-testnet.stellar.org");
        assert!(
            matches!(result, Err(NetworkError::MainnetWriteForbidden)),
            "the mainnet passphrase must refuse: {result:?}"
        );
    }

    #[test]
    fn refuse_mainnet_write_refuses_testnet_passphrase_with_mainnet_url() {
        let result = refuse_mainnet_write(
            stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE,
            "https://rpc.pubnet.example.org",
        );
        assert!(
            matches!(result, Err(NetworkError::MainnetWriteForbidden)),
            "a mainnet-pattern URL must refuse: {result:?}"
        );
    }

    #[test]
    fn refuse_mainnet_write_passes_testnet_passphrase_with_testnet_url() {
        let result = refuse_mainnet_write(
            stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE,
            "https://soroban-testnet.stellar.org",
        );
        assert!(result.is_ok(), "testnet inputs must pass: {result:?}");
    }

    #[test]
    fn redact_tx_hash_long() {
        let hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let r = redact_tx_hash(hash);
        assert!(r.starts_with("abcdef01"));
        assert!(r.ends_with("23456789"));
        assert!(r.contains("..."));
    }

    #[test]
    fn redact_tx_hash_short() {
        let hash = "abcd1234";
        assert_eq!(redact_tx_hash(hash), hash);
    }

    #[test]
    fn submission_result_carries_software_signer_kind() {
        let result = SubmissionResult {
            tx_hash: "00".repeat(32),
            ledger: 123,
            signer_kind: Some(SubmissionSignerKind::Software),
        };

        assert_eq!(result.signer_kind, Some(SubmissionSignerKind::Software));
        let json = serde_json::to_value(&result).expect("SubmissionResult serializes");
        assert_eq!(json["signer_kind"], "software");
    }

    #[tokio::test]
    async fn mainnet_passphrase_rejected_at_submit_layer() {
        #[allow(clippy::unwrap_used, reason = "test-only construction")]
        let client = crate::StellarRpcClient::new("https://soroban-testnet.stellar.org").unwrap();
        // Primary guard: passphrase comparison.
        let result = submit_transaction_and_wait(
            &client,
            "AAAAAA==",
            Duration::from_secs(5),
            MAINNET_PASSPHRASE,
            None,
            None,
        )
        .await;
        assert!(
            matches!(
                result,
                Err(WalletError::Network(NetworkError::MainnetWriteForbidden))
            ),
            "mainnet passphrase must be rejected: {result:?}"
        );
    }

    #[tokio::test]
    async fn mainnet_url_rejected_at_submit_layer() {
        // Defence-in-depth URL guard. is_mainnet_url is tested directly above.
        // Verify the guard fires for a mainnet-URL client with testnet passphrase.
        // We cannot easily override the URL field from outside the crate;
        // test is_mainnet_url directly above and rely on integration tests for
        // the full guard stack.
        assert!(is_mainnet_url("https://soroban.mainnet.stellar.org"));
        assert!(!is_mainnet_url("https://soroban-testnet.stellar.org"));
    }

    #[tokio::test]
    async fn invalid_envelope_xdr_returns_protocol_error() {
        #[allow(clippy::unwrap_used, reason = "test-only construction")]
        let client = crate::StellarRpcClient::new("https://soroban-testnet.stellar.org").unwrap();
        let result = submit_transaction_and_wait(
            &client,
            "not-valid-base64-xdr",
            Duration::from_secs(5),
            "Test SDF Network ; September 2015",
            None,
            None,
        )
        .await;
        assert!(
            matches!(result, Err(WalletError::Protocol(_))),
            "invalid XDR must return Protocol error, got: {result:?}"
        );
    }

    /// Typed map for UNDERFUNDED surfaces InsufficientBalance.
    ///
    /// Decodes a known failed TransactionResult with PAYMENT_UNDERFUNDED and
    /// asserts the correct `LedgerError::InsufficientBalance` emerges.
    #[test]
    fn map_operation_result_underfunded_surfaces_insufficient_balance() {
        use stellar_xdr::OperationResultTr;
        let op = OperationResult::OpInner(OperationResultTr::Payment(PaymentResult::Underfunded));
        let err = map_operation_result(&op);
        assert!(
            matches!(
                err,
                WalletError::Ledger(LedgerError::InsufficientBalance { .. })
            ),
            "PAYMENT_UNDERFUNDED must map to InsufficientBalance, got: {err:?}"
        );
    }

    /// Typed map for NO_TRUST surfaces TrustlineMissing.
    #[test]
    fn map_operation_result_no_trust_surfaces_trustline_missing() {
        use stellar_xdr::OperationResultTr;
        let op = OperationResult::OpInner(OperationResultTr::Payment(PaymentResult::NoTrust));
        let err = map_operation_result(&op);
        assert!(
            matches!(
                err,
                WalletError::Ledger(LedgerError::TrustlineMissing { .. })
            ),
            "PAYMENT_NO_TRUST must map to TrustlineMissing, got: {err:?}"
        );
    }

    /// Typed TxBadSeq maps to SubmissionError::SequenceNumberStale (code
    /// "submission.sequence_number_stale").
    ///
    /// Regression lock: `map_failed_result` must NOT fall through to the
    /// `other => OpFailed` arm for `TransactionResultResult::TxBadSeq`.
    /// Callers must be able to match the stable error code without relying on
    /// fragile XDR Debug-format substring matching.
    #[test]
    fn map_failed_result_txbadseq_surfaces_sequence_number_stale() {
        use stellar_agent_core::error::SubmissionError;
        use stellar_xdr::{TransactionResultExt, TransactionResultResult};

        // fee_charged is Uint64 = u64 (type alias, not a newtype).
        let result = TransactionResult {
            fee_charged: 100,
            result: TransactionResultResult::TxBadSeq,
            ext: TransactionResultExt::V0,
        };
        let err = map_failed_result(Some(&result));
        assert!(
            matches!(
                err,
                WalletError::Submission(SubmissionError::SequenceNumberStale)
            ),
            "TxBadSeq TransactionResult must map to SequenceNumberStale, got: {err:?}"
        );
        // WalletError::code() is an inherent method on WalletError.
        assert_eq!(
            err.code(),
            "submission.sequence_number_stale",
            "error code must be submission.sequence_number_stale; got: {}",
            err.code()
        );
    }

    /// `TxFeeBumpInnerFailed` maps to `SubmissionError::FeeBumpInnerRejected` with
    /// code `"submission.feebump_inner_rejected"`, carrying the inner result code
    /// name and a redacted inner tx hash.
    ///
    /// Tests `map_failed_result` with a synthetic `TxFeeBumpInnerFailed` result.
    #[test]
    fn map_failed_result_txfeebump_inner_failed_surfaces_feebump_inner_rejected() {
        use stellar_agent_core::error::SubmissionError;
        use stellar_xdr::{
            Hash, InnerTransactionResult, InnerTransactionResultExt, InnerTransactionResultPair,
            InnerTransactionResultResult, TransactionResultExt, TransactionResultResult,
        };

        // Build a synthetic InnerTransactionResultPair with TxBadAuth inner result.
        let inner_hash = Hash([0xabu8; 32]); // 32 bytes of 0xab
        let pair = InnerTransactionResultPair {
            transaction_hash: inner_hash.clone(),
            result: InnerTransactionResult {
                fee_charged: 100,
                result: InnerTransactionResultResult::TxBadAuth,
                ext: InnerTransactionResultExt::V0,
            },
        };

        let tx_result = TransactionResult {
            fee_charged: 200,
            result: TransactionResultResult::TxFeeBumpInnerFailed(pair),
            ext: TransactionResultExt::V0,
        };

        let err = map_failed_result(Some(&tx_result));

        // Must be FeeBumpInnerRejected, not a generic OpFailed.
        let (inner_result_code, inner_tx_hash_redacted) = match &err {
            WalletError::Submission(SubmissionError::FeeBumpInnerRejected {
                inner_result_code,
                inner_tx_hash_redacted,
            }) => (inner_result_code.as_str(), inner_tx_hash_redacted.as_str()),
            other => {
                panic!("TxFeeBumpInnerFailed must map to FeeBumpInnerRejected, got: {other:?}")
            }
        };

        // inner_result_code must be the public enum name.
        assert_eq!(
            inner_result_code, "TxBadAuth",
            "inner_result_code must be 'TxBadAuth', got: {inner_result_code}"
        );

        // inner_tx_hash_redacted must be first-8-last-8 of the hex-encoded hash.
        // 0xab = 171 decimal → hex "ab"; 32 bytes → 64 hex chars "abab...abab".
        assert!(
            inner_tx_hash_redacted.len() < 64,
            "hash must be redacted, got full-length: {inner_tx_hash_redacted}"
        );
        assert!(
            inner_tx_hash_redacted.starts_with("abababab"),
            "redacted hash must start with first 8 hex chars 'abababab', got: {inner_tx_hash_redacted}"
        );
        assert!(
            inner_tx_hash_redacted.ends_with("abababab"),
            "redacted hash must end with last 8 hex chars 'abababab', got: {inner_tx_hash_redacted}"
        );
        assert!(
            inner_tx_hash_redacted.contains("..."),
            "redacted hash must contain '...', got: {inner_tx_hash_redacted}"
        );

        // Wire code must be the stable feebump_inner_rejected code.
        assert_eq!(
            err.code(),
            "submission.feebump_inner_rejected",
            "wire code must be submission.feebump_inner_rejected, got: {}",
            err.code()
        );
    }

    /// `TxFeeBumpInnerSuccess` in the FAILED-branch `map_failed_result` call maps
    /// to a defensive `LedgerError::OpFailed`, not `FeeBumpInnerRejected`.
    ///
    /// Against stellar-rpc 26.x, `TxFeeBumpInnerSuccess` never appears in a
    /// FAILED-status response: stellar-go classifies an inner-applied fee-bump
    /// as `Successful()` and surfaces it as `status: SUCCESS` (CAP-15
    /// Application-and-Results: "inner applied" ⇒ `txFEE_BUMP_INNER_SUCCESS`).
    ///
    /// The defensive arm is retained as belt-and-suspenders: a structurally-valid
    /// XDR variant that does not currently appear in practice should still map to
    /// a non-success outcome rather than silently recording a false Success.
    /// It MUST NOT map to `FeeBumpInnerRejected` — the inner tx applied, so
    /// `OpFailed` is the correct honest signal.
    #[test]
    fn map_failed_result_txfeebump_inner_success_maps_defensive() {
        use stellar_xdr::{
            Hash, InnerTransactionResult, InnerTransactionResultExt, InnerTransactionResultPair,
            InnerTransactionResultResult, TransactionResultExt, TransactionResultResult,
        };

        let pair = InnerTransactionResultPair {
            transaction_hash: Hash([0u8; 32]),
            result: InnerTransactionResult {
                fee_charged: 100,
                result: InnerTransactionResultResult::TxSuccess(vec![].try_into().unwrap()),
                ext: InnerTransactionResultExt::V0,
            },
        };

        let tx_result = TransactionResult {
            fee_charged: 200,
            result: TransactionResultResult::TxFeeBumpInnerSuccess(pair),
            ext: TransactionResultExt::V0,
        };

        let err = map_failed_result(Some(&tx_result));
        // Must NOT be FeeBumpInnerRejected — the inner tx applied.
        // Maps to the defensive OpFailed arm.
        assert!(
            !matches!(
                err,
                WalletError::Submission(
                    stellar_agent_core::error::SubmissionError::FeeBumpInnerRejected { .. }
                )
            ),
            "TxFeeBumpInnerSuccess must NOT map to FeeBumpInnerRejected, got: {err:?}"
        );
    }

    // ── Confirmation poll deadline ───────────────────────────────────────────

    /// A recorder that keeps every outcome it is handed, in order.
    #[derive(Default)]
    struct Outcomes(std::sync::Mutex<Vec<SubmissionOutcome>>);

    #[async_trait::async_trait]
    impl SubmissionRecorder for Outcomes {
        async fn pre_send(&self, _intent: &SubmissionIntent) -> Result<(), WalletError> {
            Ok(())
        }

        async fn outcome(&self, _intent: &SubmissionIntent, outcome: &SubmissionOutcome) {
            self.0.lock().unwrap().push(outcome.clone());
        }
    }

    fn poll_intent() -> SubmissionIntent {
        SubmissionIntent {
            chain_scope: crate::policy_state::ChainScope::for_chain(
                stellar_agent_core::profile::caip2::Caip2::Testnet,
            ),
            envelope_hash: "ab".repeat(32),
            tx_hash: "cd".repeat(32),
            source: "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL".to_owned(),
            sequence: 1,
            max_time: 0,
            submission_ledger: 1,
            submission_anchor: None,
            send_by_ms: None,
        }
    }

    /// An answer that becomes ready only at the deadline is not accepted: the
    /// poll records the timeout whatever the answer says, and returns
    /// `submission.tx_timeout`.
    ///
    /// Deterministic through the poll seam and a paused clock. The scripted
    /// request completes on the deadline's own timer tick, and Tokio polls the
    /// request before its deadline timer, so the answer comes back through
    /// `timeout_at` as a completed result; the premise check below shows this.
    /// Only the deadline check after the await keeps it from being read.
    #[tokio::test(start_paused = true)]
    async fn an_answer_ready_only_at_the_deadline_is_not_accepted() {
        assert_answer_wins_at_deadline().await;

        for status in ["SUCCESS", "FAILED"] {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
            let intent = poll_intent();
            let recorder = Outcomes::default();
            let polls = std::sync::atomic::AtomicU32::new(0);

            let result = poll_for_confirmation(
                || {
                    polls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    async move {
                        tokio::time::sleep_until(deadline).await;
                        Ok(answer(status))
                    }
                },
                &RpcEndpoint::plain("http://127.0.0.1:9"),
                deadline,
                1,
                &intent,
                Some(&recorder),
                None,
                FailureWitness::Primary,
            )
            .await;

            match result {
                Err(WalletError::Submission(SubmissionError::TxTimeout { tx_hash, seconds })) => {
                    assert_eq!(tx_hash, intent.tx_hash, "{status}");
                    assert_eq!(seconds, 1, "{status}");
                }
                other => panic!("{status} at the deadline must time out; got {other:?}"),
            }
            assert_eq!(
                *recorder.0.lock().unwrap(),
                vec![SubmissionOutcome::Timeout {
                    tx_hash: intent.tx_hash.clone(),
                }],
                "{status}: the timeout is recorded and nothing else"
            );
            assert_eq!(
                polls.load(std::sync::atomic::Ordering::SeqCst),
                1,
                "{status}: one request, then the deadline"
            );
        }
    }

    async fn assert_no_poll_after_deadline(transient: bool) {
        let intent = poll_intent();
        let recorder = Outcomes::default();
        let polls = std::cell::Cell::new(0);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        let result = poll_for_confirmation(
            || {
                polls.set(polls.get() + 1);
                std::future::ready(if transient {
                    Err(stellar_rpc_client::Error::JsonRpc(
                        jsonrpsee_core::ClientError::Custom("transient".into()),
                    ))
                } else {
                    Ok(answer("NOT_FOUND"))
                })
            },
            &RpcEndpoint::plain(ENDPOINT),
            deadline,
            1,
            &intent,
            Some(&recorder),
            None,
            FailureWitness::Primary,
        )
        .await;
        assert_eq!(polls.get(), 1, "no poll starts after the clamped sleep");
        assert!(
            matches!(result,
                Err(WalletError::Submission(SubmissionError::TxTimeout { ref tx_hash, seconds: 1 }))
                    if tx_hash == &intent.tx_hash
            ),
            "the poll ends with the deadline outcome: {result:?}"
        );
        assert_eq!(
            *recorder.0.lock().unwrap(),
            vec![SubmissionOutcome::Timeout {
                tx_hash: intent.tx_hash,
            }]
        );
        assert_eq!(tokio::time::Instant::now(), deadline);
    }

    #[tokio::test(start_paused = true)]
    async fn no_poll_starts_after_the_not_found_sleep_reaches_the_deadline() {
        assert_no_poll_after_deadline(false).await;
    }

    #[tokio::test(start_paused = true)]
    async fn no_poll_starts_after_the_transient_sleep_reaches_the_deadline() {
        assert_no_poll_after_deadline(true).await;
    }

    // ── The pre-send budget ──────────────────────────────────────────────────

    /// The error of a budgeted read sequence whose send phase was never
    /// reached.
    fn not_reached<T>(
        _: T,
        _: tokio::time::Instant,
    ) -> std::future::Ready<Result<(), SentByError>> {
        panic!("the send phase is not reached")
    }

    /// Two reads that each take longer than the caller's one-second timeout
    /// run under the budget, receive its end as their deadline, and the
    /// send phase is reached.
    #[tokio::test(start_paused = true)]
    async fn pre_send_budget_lets_a_read_slower_than_the_timeout_reach_the_send() {
        let start = tokio::time::Instant::now();
        let deadlines = std::sync::Mutex::new(Vec::new());
        let deadlines = &deadlines;
        let reached = budgeted_submission(
            None,
            Duration::from_secs(1),
            |budget| async move {
                budget
                    .read(
                        PreSendStage::EndpointIdentity,
                        IDENTITY_PROBE_READ,
                        |deadline| {
                            deadlines.lock().unwrap().push(deadline);
                            async {
                                tokio::time::sleep(Duration::from_secs(2)).await;
                                Ok(())
                            }
                        },
                    )
                    .await?;
                budget
                    .read(
                        PreSendStage::SignatureBinding,
                        SIGNER_SET_READ,
                        |deadline| {
                            deadlines.lock().unwrap().push(deadline);
                            async {
                                tokio::time::sleep(Duration::from_secs(2)).await;
                                Ok(7_u32)
                            }
                        },
                    )
                    .await
            },
            |ledger, _| async move { Ok::<_, SentByError>(ledger) },
        )
        .await;

        assert_eq!(reached.unwrap(), 7, "the send phase is reached");
        assert_eq!(
            *deadlines.lock().unwrap(),
            [start + PRE_SEND_BUDGET, start + PRE_SEND_BUDGET],
            "both reads end at the budget, counted from the first"
        );
        assert_eq!(tokio::time::Instant::now(), start + Duration::from_secs(4));
    }

    /// The send deadline is armed when the send phase begins, after reads
    /// and a record that together outlast the timeout: it equals the
    /// send-phase start plus the timeout, and the confirmation poll runs
    /// until exactly then.
    #[tokio::test(start_paused = true)]
    async fn pre_send_budget_keeps_the_callers_timeout_for_the_poll() {
        let timeout = Duration::from_secs(3);
        let start = tokio::time::Instant::now();
        let intent = poll_intent();
        let recorder = Outcomes::default();
        let (intent, recorder) = (&intent, &recorder);
        let result = budgeted_submission(
            None,
            timeout,
            |budget| async move {
                budget
                    .read(
                        PreSendStage::EndpointIdentity,
                        IDENTITY_PROBE_READ,
                        |_| async {
                            tokio::time::sleep(Duration::from_secs(4)).await;
                            Ok(())
                        },
                    )
                    .await?;
                // The pre-send record.
                tokio::time::sleep(Duration::from_secs(2)).await;
                Ok(tokio::time::Instant::now())
            },
            |phase_start, send_deadline| async move {
                assert_eq!(send_deadline, phase_start + timeout);
                assert_eq!(send_deadline, start + Duration::from_secs(6) + timeout);
                poll_for_confirmation(
                    || std::future::ready(Ok(answer("NOT_FOUND"))),
                    &RpcEndpoint::plain(ENDPOINT),
                    send_deadline,
                    timeout.as_secs(),
                    intent,
                    Some(recorder),
                    None,
                    FailureWitness::Primary,
                )
                .await
                .map_err(SentByError::Failed)
            },
        )
        .await;

        assert!(
            matches!(
                result,
                Err(SentByError::Failed(WalletError::Submission(
                    SubmissionError::TxTimeout { seconds: 3, .. }
                )))
            ),
            "{result:?}"
        );
        assert_eq!(
            tokio::time::Instant::now(),
            start + Duration::from_secs(6) + timeout,
            "the poll ends at the send deadline"
        );
        assert_eq!(
            *recorder.0.lock().unwrap(),
            vec![SubmissionOutcome::Timeout {
                tx_hash: intent.tx_hash.clone(),
            }]
        );
    }

    /// Asserts that `result` is the budget refusal of `read`.
    fn assert_budget_refusal<T: std::fmt::Debug>(result: Result<T, SentByError>, read: &str) {
        match result {
            Err(SentByError::Failed(error)) => {
                assert_eq!(
                    error.code(),
                    "network.pre_send_timeout",
                    "{read}: {error:?}"
                );
                assert_eq!(
                    error.message(),
                    format!(
                        "the {read} did not answer within the pre-send budget of 30 s; nothing \
                         was sent"
                    )
                );
            }
            other => panic!("{read}: expected the budget refusal, got {other:?}"),
        }
    }

    /// Each read refuses with the budget code when the budget cuts it, and
    /// when it fails with its own error at the budget's end. The message
    /// names the read and the seconds, and nothing after the read runs.
    #[tokio::test(start_paused = true)]
    async fn pre_send_budget_refuses_each_read_with_one_code() {
        for (stage, read) in [
            (PreSendStage::EndpointIdentity, IDENTITY_PROBE_READ),
            (PreSendStage::SignatureBinding, SIGNER_SET_READ),
        ] {
            for fails_late in [false, true] {
                let recorded = std::sync::atomic::AtomicBool::new(false);
                let recorded = &recorded;
                let result = budgeted_submission(
                    None,
                    Duration::from_secs(60),
                    |budget| async move {
                        if stage == PreSendStage::SignatureBinding {
                            budget
                                .read(PreSendStage::EndpointIdentity, IDENTITY_PROBE_READ, |_| {
                                    std::future::ready(Ok(()))
                                })
                                .await?;
                        }
                        budget
                            .read(stage, read, |deadline| async move {
                                if fails_late {
                                    tokio::time::sleep_until(deadline).await;
                                    Err(WalletError::Network(NetworkError::RpcTimeout {
                                        url: ENDPOINT_AUTHORITY.to_owned(),
                                        timeout_secs: 60,
                                    }))
                                } else {
                                    std::future::pending::<Result<(), WalletError>>().await
                                }
                            })
                            .await?;
                        recorded.store(true, std::sync::atomic::Ordering::SeqCst);
                        Ok(())
                    },
                    not_reached,
                )
                .await;
                assert_budget_refusal(result, read);
                assert!(
                    !recorded.load(std::sync::atomic::Ordering::SeqCst),
                    "{read}: nothing is recorded"
                );
            }
        }
    }

    /// A send-by instant before the budget's end ends the reads instead:
    /// the read receives it as its deadline, and its cut is the send-by
    /// refusal at the read's stage. A send-by instant after the budget's
    /// end leaves the budget's refusal.
    #[tokio::test(start_paused = true)]
    async fn pre_send_budget_ends_at_an_earlier_send_by() {
        let start = tokio::time::Instant::now();
        let send_by = start + Duration::from_secs(5);
        let result = budgeted_submission(
            Some(send_by),
            Duration::from_secs(60),
            |budget| async move {
                budget
                    .read(
                        PreSendStage::EndpointIdentity,
                        IDENTITY_PROBE_READ,
                        |deadline| {
                            assert_eq!(deadline, send_by);
                            async {
                                tokio::time::sleep(Duration::from_secs(10)).await;
                                Ok(())
                            }
                        },
                    )
                    .await
            },
            not_reached,
        )
        .await;
        assert!(
            matches!(
                result,
                Err(SentByError::Elapsed {
                    stage: PreSendStage::EndpointIdentity,
                    sent_tx_hash: None,
                })
            ),
            "{result:?}"
        );
        assert_eq!(tokio::time::Instant::now(), send_by);

        let start = tokio::time::Instant::now();
        let result = budgeted_submission(
            Some(start + Duration::from_secs(60)),
            Duration::from_secs(60),
            |budget| async move {
                budget
                    .read(
                        PreSendStage::SignatureBinding,
                        SIGNER_SET_READ,
                        |deadline| {
                            assert_eq!(deadline, start + PRE_SEND_BUDGET);
                            async {
                                tokio::time::sleep(Duration::from_secs(40)).await;
                                Ok(())
                            }
                        },
                    )
                    .await
            },
            not_reached,
        )
        .await;
        assert_budget_refusal(result, SIGNER_SET_READ);
    }

    // ── TRY_AGAIN_LATER ──────────────────────────────────────────────────────

    /// A `sendTransaction` answer with `status`, naming the transaction of
    /// [`poll_intent`].
    fn send_answer(status: &str) -> stellar_rpc_client::SendTransactionResponse {
        stellar_rpc_client::SendTransactionResponse {
            hash: poll_intent().tx_hash,
            status: status.to_owned(),
            error_result_xdr: None,
            latest_ledger: 1000,
            latest_ledger_close_time: 1_699_999_999,
        }
    }

    /// A decoded signed envelope to send.
    fn send_envelope() -> TransactionEnvelope {
        use stellar_xdr::Limits;
        TransactionEnvelope::from_xdr_base64(
            stellar_agent_test_support::signed_envelope::SignedTestEnvelope::for_source([0x51; 32])
                .envelope_xdr(),
            Limits::none(),
        )
        .unwrap()
    }

    /// Runs the send phase of [`poll_intent`] against `answers`, one per
    /// send in order, the last repeated, with every confirmation poll
    /// answering `SUCCESS`. Returns the result, the bytes of every send and
    /// the recorded outcomes.
    async fn send_through(
        answers: &[&str],
        send_by: Option<tokio::time::Instant>,
        send_deadline: tokio::time::Instant,
    ) -> (
        Result<SubmissionResult, SentByError>,
        Vec<String>,
        Vec<SubmissionOutcome>,
    ) {
        use stellar_xdr::{Limits, WriteXdr as _};
        let envelope = send_envelope();
        let intent = poll_intent();
        let recorder = Outcomes::default();
        let sent = std::sync::Mutex::new(Vec::new());
        let result = send_and_confirm_through(
            |envelope: &TransactionEnvelope| {
                let mut sent = sent.lock().unwrap();
                sent.push(envelope.to_xdr_base64(Limits::none()).unwrap());
                let status = answers[(sent.len() - 1).min(answers.len() - 1)];
                std::future::ready(Ok(send_answer(status)))
            },
            || std::future::ready(Ok(answer("SUCCESS"))),
            &RpcEndpoint::plain(ENDPOINT),
            SendPhase {
                envelope: &envelope,
                intent: &intent,
                send_by,
                send_deadline,
                timeout: Duration::from_secs(10),
                recorder: Some(&recorder),
                signer_kind: None,
                witness: FailureWitness::Primary,
            },
        )
        .await;
        let outcomes = recorder.0.lock().unwrap().clone();
        (result, sent.into_inner().unwrap(), outcomes)
    }

    /// `TRY_AGAIN_LATER` resends the same bytes until the endpoint takes
    /// them, and the accepted send confirms.
    #[tokio::test(start_paused = true)]
    async fn try_again_later_resends_the_same_bytes_until_pending() {
        use stellar_xdr::{Limits, WriteXdr as _};
        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        let (result, sent, outcomes) = send_through(
            &["TRY_AGAIN_LATER", "TRY_AGAIN_LATER", "PENDING"],
            None,
            deadline,
        )
        .await;

        let result = result.expect("the third send is taken and confirms");
        assert_eq!(result.tx_hash, poll_intent().tx_hash);
        let bytes = send_envelope().to_xdr_base64(Limits::none()).unwrap();
        assert_eq!(
            sent,
            [bytes.clone(), bytes.clone(), bytes],
            "the same bytes, three times"
        );
        assert_eq!(
            outcomes,
            [SubmissionOutcome::Success {
                ledger: 7,
                created_at: None,
            }]
        );
    }

    /// `TRY_AGAIN_LATER` until the send deadline, and until a send-by
    /// instant after a first attempt, ends without a resolved status: the
    /// recorder is told the outcome is unknown, and the call returns the
    /// timeout shape naming the transaction.
    #[tokio::test(start_paused = true)]
    async fn try_again_later_until_the_deadline_records_transport_after_send() {
        let start = tokio::time::Instant::now();
        let deadline = start + Duration::from_secs(3);
        let (result, sent, outcomes) = send_through(&["TRY_AGAIN_LATER"], None, deadline).await;
        match result {
            Err(SentByError::Failed(WalletError::Submission(SubmissionError::TxTimeout {
                tx_hash,
                seconds: 10,
            }))) => assert_eq!(tx_hash, poll_intent().tx_hash),
            other => panic!("expected the timeout shape, got {other:?}"),
        }
        assert!(!sent.is_empty());
        assert!(tokio::time::Instant::now() <= deadline);
        assert!(
            matches!(
                outcomes.as_slice(),
                [SubmissionOutcome::TransportAfterSend { .. }]
            ),
            "{outcomes:?}"
        );

        let start = tokio::time::Instant::now();
        let send_by = start + Duration::from_millis(1);
        let (result, sent, outcomes) = send_through(
            &["TRY_AGAIN_LATER"],
            Some(send_by),
            start + Duration::from_secs(60),
        )
        .await;
        match result {
            Err(SentByError::Elapsed {
                stage: PreSendStage::Send,
                sent_tx_hash: Some(tx_hash),
            }) => assert_eq!(tx_hash, poll_intent().tx_hash),
            other => panic!("expected the send-by refusal after a send, got {other:?}"),
        }
        assert_eq!(sent.len(), 1, "no attempt starts after the send-by instant");
        assert!(
            matches!(
                outcomes.as_slice(),
                [SubmissionOutcome::TransportAfterSend { .. }]
            ),
            "{outcomes:?}"
        );
    }

    // ── The authorized submission ─────────────────────────────────────────────

    #[cfg(feature = "mainnet-write")]
    mod authorized {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Mutex};

        use serde_json::json;
        use serial_test::serial;
        use stellar_agent_core::policy::v1::criteria::state_store::WindowEntry;
        use stellar_agent_core::profile::receipt::ReceiptStatus;
        use stellar_agent_test_support::SubmissionEchoResponder;
        use stellar_agent_test_support::signed_envelope::{
            SignedTestEnvelope, TESTNET_PASSPHRASE, get_network_result,
        };
        use wiremock::matchers::{body_partial_json, method};
        use wiremock::{Mock, MockServer};

        use super::*;
        use crate::mainnet::authorization::MainnetTxSignAuthorization;
        use crate::mainnet::fixtures::{self, LedgerFixture, SEQUENCE, SIGNER_SEED, TTL_MS};
        use crate::policy_state::DomainBinding;
        use crate::submission_record::WalletSubmissionRecorder;

        const NOW: u64 = 1_800_000_000_000;
        const OTHER_SEED: [u8; 32] = [0x3b; 32];
        const TIMEOUT: Duration = Duration::from_secs(10);

        /// The proof field a [`CountingRecorder`] changes after the real
        /// consumption.
        #[derive(Clone, Copy)]
        enum Tamper {
            EnvelopeHash,
            ContentDigest,
            AuthorizationId,
        }

        /// The fixture's wallet recorder, counting the calls of each kind and
        /// optionally changing one field of the proof it returns.
        struct CountingRecorder<'a> {
            inner: WalletSubmissionRecorder<'a>,
            tamper: Option<Tamper>,
            pre_sends: AtomicUsize,
            consumes: AtomicUsize,
            outcomes: Mutex<Vec<&'static str>>,
            /// How long the consumption takes after the real one.
            consume_delay: Duration,
            /// The send-by instant of every intent the consumption saw.
            send_bys: Mutex<Vec<Option<u64>>>,
        }

        impl<'a> CountingRecorder<'a> {
            fn new(inner: WalletSubmissionRecorder<'a>, tamper: Option<Tamper>) -> Self {
                Self {
                    inner,
                    tamper,
                    pre_sends: AtomicUsize::new(0),
                    consumes: AtomicUsize::new(0),
                    outcomes: Mutex::new(Vec::new()),
                    consume_delay: Duration::ZERO,
                    send_bys: Mutex::new(Vec::new()),
                }
            }

            fn send_bys(&self) -> Vec<Option<u64>> {
                self.send_bys.lock().unwrap().clone()
            }

            fn consumes(&self) -> usize {
                self.consumes.load(Ordering::SeqCst)
            }

            fn pre_sends(&self) -> usize {
                self.pre_sends.load(Ordering::SeqCst)
            }

            fn outcomes(&self) -> Vec<&'static str> {
                self.outcomes.lock().unwrap().clone()
            }
        }

        #[async_trait::async_trait]
        impl SubmissionRecorder for CountingRecorder<'_> {
            async fn pre_send(&self, intent: &SubmissionIntent) -> Result<(), WalletError> {
                self.pre_sends.fetch_add(1, Ordering::SeqCst);
                self.inner.pre_send(intent).await
            }

            async fn pre_send_authorized(
                &self,
                intent: &SubmissionIntent,
                grant: MainnetSubmitGrant,
            ) -> Result<AuthorizationConsumed, WalletError> {
                self.consumes.fetch_add(1, Ordering::SeqCst);
                self.send_bys.lock().unwrap().push(intent.send_by_ms);
                let proof = self.inner.pre_send_authorized(intent, grant).await?;
                tokio::time::sleep(self.consume_delay).await;
                let mut envelope_hash = *proof.envelope_hash();
                let mut content_digest = *proof.content_digest();
                let mut id = *proof.authorization_id().as_bytes();
                match self.tamper {
                    None => return Ok(proof),
                    Some(Tamper::EnvelopeHash) => envelope_hash[0] ^= 1,
                    Some(Tamper::ContentDigest) => content_digest[0] ^= 1,
                    Some(Tamper::AuthorizationId) => id[0] ^= 1,
                }
                Ok(AuthorizationConsumed::new(
                    envelope_hash,
                    content_digest,
                    crate::mainnet::AuthorizationId::from_bytes(id),
                ))
            }

            async fn outcome(&self, intent: &SubmissionIntent, outcome: &SubmissionOutcome) {
                self.outcomes.lock().unwrap().push(match outcome {
                    SubmissionOutcome::Success { .. } => "success",
                    SubmissionOutcome::OnChainFailed { .. } => "on_chain_failed",
                    SubmissionOutcome::Rejected { .. } => "rejected",
                    SubmissionOutcome::Timeout { .. } => "timeout",
                    SubmissionOutcome::TransportAfterSend { .. } => "transport_after_send",
                    SubmissionOutcome::NotSent { .. } => "not_sent",
                });
                self.inner.outcome(intent, outcome).await;
            }
        }

        /// The `txBadSeq` result a `FAILED` answer of the primary carries.
        const BAD_SEQ_RESULT_XDR: &str = "AAAAAAAAAGT////7AAAAAA==";

        /// A base64 `TransactionResult` carrying `result`.
        fn result_xdr(result: TransactionResultResult) -> String {
            use stellar_xdr::{Limits, TransactionResultExt, WriteXdr};
            TransactionResult {
                fee_charged: 0,
                result,
                ext: TransactionResultExt::V0,
            }
            .to_xdr_base64(Limits::none())
            .unwrap()
        }

        /// A `getTransaction` answer for `envelope` with `status`, carrying
        /// `result` as its result XDR.
        fn transaction_answer(
            envelope: &SignedTestEnvelope,
            status: &str,
            result: Option<&str>,
        ) -> serde_json::Value {
            json!({
                "status": status,
                "txHash": envelope.tx_hash_hex(),
                "ledger": 4567,
                "createdAt": "1700000000",
                "envelopeXdr": null,
                "resultXdr": result,
                "resultMetaXdr": null
            })
        }

        /// Mounts the endpoint for `envelope`: it reports `passphrase`, the
        /// envelope's signer sets, `sends` accepted sends, and the
        /// transaction's success.
        async fn mount(
            server: &MockServer,
            envelope: &SignedTestEnvelope,
            passphrase: &str,
            sends: u64,
        ) {
            mount_answers(
                server,
                envelope,
                passphrase,
                sends,
                json!({
                    "hash": envelope.tx_hash_hex(),
                    "status": "PENDING",
                    "latestLedger": 1000,
                    "latestLedgerCloseTime": "1699999999"
                }),
                transaction_answer(envelope, "SUCCESS", None),
            )
            .await;
        }

        /// Mounts the endpoint for `envelope`: it reports `passphrase` and the
        /// envelope's signer sets, answers `sends` sends with `send`, and
        /// answers every `getTransaction` with `poll`.
        async fn mount_answers(
            server: &MockServer,
            envelope: &SignedTestEnvelope,
            passphrase: &str,
            sends: u64,
            send: serde_json::Value,
            poll: serde_json::Value,
        ) {
            for (rpc_method, result) in [
                ("getNetwork", get_network_result(passphrase)),
                ("getLedgerEntries", envelope.ledger_entries_result()),
            ] {
                Mock::given(method("POST"))
                    .and(body_partial_json(json!({ "method": rpc_method })))
                    .respond_with(SubmissionEchoResponder::new(result, MAINNET_PASSPHRASE))
                    .mount(server)
                    .await;
            }
            Mock::given(method("POST"))
                .and(body_partial_json(json!({ "method": "sendTransaction" })))
                .respond_with(SubmissionEchoResponder::new(send, MAINNET_PASSPHRASE))
                .expect(sends)
                .named("sendTransaction")
                .mount(server)
                .await;
            Mock::given(method("POST"))
                .and(body_partial_json(json!({ "method": "getTransaction" })))
                .respond_with(SubmissionEchoResponder::new(poll, MAINNET_PASSPHRASE))
                .mount(server)
                .await;
        }

        /// A mock oracle reporting the mainnet passphrase and answering every
        /// `getTransaction` with `answer`, and a client of it.
        async fn oracle_answering(answer: serde_json::Value) -> (MockServer, StellarRpcClient) {
            oracle_reporting(MAINNET_PASSPHRASE, Duration::ZERO, answer, Duration::ZERO).await
        }

        /// A mock oracle reporting `passphrase` after `identity_delay` and
        /// answering every `getTransaction` with `answer` after `delay`, and a
        /// client of it.
        async fn oracle_reporting(
            passphrase: &str,
            identity_delay: Duration,
            answer: serde_json::Value,
            delay: Duration,
        ) -> (MockServer, StellarRpcClient) {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(body_partial_json(json!({ "method": "getNetwork" })))
                .respond_with(DelayedResponder {
                    inner: SubmissionEchoResponder::new(
                        get_network_result(passphrase),
                        MAINNET_PASSPHRASE,
                    ),
                    delay: identity_delay,
                })
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(body_partial_json(json!({ "method": "getTransaction" })))
                .respond_with(DelayedResponder {
                    inner: SubmissionEchoResponder::new(answer, MAINNET_PASSPHRASE),
                    delay,
                })
                .mount(&server)
                .await;
            let client = StellarRpcClient::new(&server.uri()).unwrap();
            (server, client)
        }

        /// Answers as `inner` does, after `delay`.
        struct DelayedResponder {
            inner: SubmissionEchoResponder,
            delay: Duration,
        }

        impl wiremock::Respond for DelayedResponder {
            fn respond(&self, request: &wiremock::Request) -> wiremock::ResponseTemplate {
                wiremock::Respond::respond(&self.inner, request).set_delay(self.delay)
            }
        }

        /// How far past its deadline a submission may return in the deadline
        /// tests: the work around the bounded wait, never a second wait.
        const SLACK: Duration = Duration::from_millis(1500);

        /// The JSON-RPC methods `server` was asked, in order.
        async fn methods_asked(server: &MockServer) -> Vec<String> {
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .map(|request| {
                    serde_json::from_slice::<serde_json::Value>(&request.body).unwrap()["method"]
                        .as_str()
                        .unwrap()
                        .to_owned()
                })
                .collect()
        }

        /// The number of requests `server` received.
        async fn requests(server: &MockServer) -> usize {
            server.received_requests().await.unwrap().len()
        }

        /// A mainnet ledger fixture, a mock endpoint, a client of it, and the
        /// signed envelope a grant is minted over.
        struct Case {
            fx: LedgerFixture,
            server: MockServer,
            client: StellarRpcClient,
            envelope: SignedTestEnvelope,
            holds: Vec<WindowEntry>,
        }

        impl Case {
            async fn new(label: &str) -> Self {
                let fx = LedgerFixture::new(label, NOW);
                let envelope = fixtures::signed_envelope();
                Self::with_fixture(fx, envelope).await
            }

            async fn with_envelope(label: &str, envelope: SignedTestEnvelope) -> Self {
                Self::with_fixture(LedgerFixture::new(label, NOW), envelope).await
            }

            async fn with_fixture(fx: LedgerFixture, envelope: SignedTestEnvelope) -> Self {
                let server = MockServer::start().await;
                let client = StellarRpcClient::new(&server.uri()).unwrap();
                let holds = vec![fixtures::hold(&fx.name, NOW, 100)];
                Self {
                    fx,
                    server,
                    client,
                    envelope,
                    holds,
                }
            }

            /// The binding of the approved unsigned envelope, after `edit`.
            fn binding(&self, edit: impl FnOnce(&mut DomainBinding)) -> DomainBinding {
                let unsigned = fixtures::unsigned_envelope();
                let mut binding =
                    fixtures::tx_binding(unsigned.envelope_xdr(), unsigned.tx_hash_hex());
                edit(&mut binding);
                binding
            }

            /// A grant minted for this client's endpoint.
            fn grant(&self) -> MainnetTxSignAuthorization {
                self.grant_for(self.endpoint(), self.binding(|_| {}))
            }

            fn grant_for(
                &self,
                endpoint: (String, u64),
                binding: DomainBinding,
            ) -> MainnetTxSignAuthorization {
                self.fx
                    .mint(binding, &self.holds, Some(endpoint), "approval-1")
            }

            fn endpoint(&self) -> (String, u64) {
                (self.client.url.authority(), self.client.id())
            }

            fn recorder(&self, tamper: Option<Tamper>) -> CountingRecorder<'_> {
                CountingRecorder::new(
                    self.fx
                        .recorder(self.holds.clone(), Some(Arc::clone(&self.fx.writer))),
                    tamper,
                )
            }

            async fn submit_with(
                &self,
                client: &StellarRpcClient,
                passphrase: &str,
                consumer: MainnetConsumer,
                recorder: &CountingRecorder<'_>,
                authorization: MainnetTxSignAuthorization,
            ) -> Result<SubmissionResult, AuthorizedPathError> {
                authorized_submission(
                    client,
                    None,
                    self.envelope.envelope_xdr(),
                    TIMEOUT,
                    passphrase,
                    None,
                    recorder,
                    consumer,
                    MainnetSubmitGrant::Tx(authorization),
                )
                .await
            }

            async fn submit(
                &self,
                recorder: &CountingRecorder<'_>,
                authorization: MainnetTxSignAuthorization,
            ) -> Result<SubmissionResult, AuthorizedPathError> {
                self.submit_with(
                    &self.client,
                    MAINNET_PASSPHRASE,
                    MainnetConsumer::CliPay,
                    recorder,
                    authorization,
                )
                .await
            }

            /// Submits under a fresh grant through the public entry point,
            /// with `oracle` as the witness of negative answers.
            async fn submit_witnessed(
                &self,
                recorder: &CountingRecorder<'_>,
                oracle: Option<&StellarRpcClient>,
            ) -> Result<SubmissionResult, WalletError> {
                self.submit_witnessed_within(recorder, oracle, TIMEOUT)
                    .await
            }

            /// [`Self::submit_witnessed`] with `timeout` as the submission
            /// deadline.
            async fn submit_witnessed_within(
                &self,
                recorder: &CountingRecorder<'_>,
                oracle: Option<&StellarRpcClient>,
                timeout: Duration,
            ) -> Result<SubmissionResult, WalletError> {
                submit_authorized_transaction_and_wait(
                    &self.client,
                    oracle,
                    self.envelope.envelope_xdr(),
                    timeout,
                    MAINNET_PASSPHRASE,
                    None,
                    recorder,
                    MainnetConsumer::CliPay,
                    MainnetSubmitGrant::Tx(self.grant()),
                )
                .await
            }

            /// The envelope hash the submission is recorded under.
            fn envelope_hash(&self) -> String {
                envelope_hash_hex(self.envelope.envelope_xdr())
            }

            /// Whether the window still holds the submission's reservation.
            fn reservation_is_open(&self) -> bool {
                let id = self.envelope_hash();
                self.fx
                    .window
                    .pending_reservations(&self.fx.profile)
                    .unwrap()
                    .iter()
                    .any(|reservation| reservation.id == id)
            }

            /// The status the submission's receipt records.
            fn receipt_status(&self) -> ReceiptStatus {
                self.fx
                    .receipts
                    .get(&self.envelope_hash())
                    .unwrap()
                    .expect("the submission's receipt exists")
                    .status
            }
        }

        /// Asserts that a submission whose negative answer nothing confirmed
        /// stands: the call returned the timeout shape for the local hash,
        /// the recorder saw one unknown outcome, the reservation and the
        /// pending receipt stand, and no failed row was written.
        fn assert_submission_stands(
            case: &Case,
            recorder: &CountingRecorder<'_>,
            result: Result<SubmissionResult, WalletError>,
        ) {
            match result {
                Err(WalletError::Submission(SubmissionError::TxTimeout { tx_hash, .. })) => {
                    assert_eq!(tx_hash, case.envelope.tx_hash_hex());
                }
                other => panic!("expected the timeout shape, got {other:?}"),
            }
            assert_eq!(recorder.outcomes(), ["transport_after_send"]);
            assert!(case.reservation_is_open(), "the reservation stands");
            assert_eq!(case.receipt_status(), ReceiptStatus::Pending);
            assert_eq!(
                case.fx.audit_kinds(),
                ["value_action_pending"],
                "no row settles the submission"
            );
        }

        fn refused(result: Result<SubmissionResult, AuthorizedPathError>) -> MainnetPrecondition {
            match result {
                Err(AuthorizedPathError::Refused(precondition)) => precondition,
                other => panic!("expected a refusal, got {other:?}"),
            }
        }

        /// Asserts that a refused submission sent nothing and never entered
        /// the consumption, and that the grant's record stays open.
        fn assert_not_consumed(
            case: &Case,
            recorder: &CountingRecorder<'_>,
            id: crate::mainnet::AuthorizationId,
        ) {
            assert_eq!(recorder.consumes(), 0, "the consumption is not entered");
            assert_eq!(recorder.pre_sends(), 0);
            assert!(case.fx.is_open(id), "the record stays open");
        }

        /// The valid grant is consumed once and the envelope sent once.
        #[tokio::test]
        #[serial]
        async fn a_valid_grant_sends_once() {
            let case = Case::new("submit-valid").await;
            mount(&case.server, &case.envelope, MAINNET_PASSPHRASE, 1).await;
            let recorder = case.recorder(None);
            let authorization = case.grant();
            let id = authorization.id();

            let result = submit_authorized_transaction_and_wait(
                &case.client,
                None,
                case.envelope.envelope_xdr(),
                TIMEOUT,
                MAINNET_PASSPHRASE,
                None,
                &recorder,
                MainnetConsumer::CliPay,
                MainnetSubmitGrant::Tx(authorization),
            )
            .await
            .expect("a valid grant submits");

            assert_eq!(result.tx_hash, case.envelope.tx_hash_hex());
            assert_eq!(recorder.consumes(), 1);
            assert_eq!(
                recorder.pre_sends(),
                0,
                "the ungranted record step is not used"
            );
            assert_eq!(recorder.outcomes(), ["success"]);
            assert!(!case.fx.is_open(id), "the record is used");
            assert!(
                case.reservation_is_open(),
                "a reported success keeps the reservation as possible spending"
            );
            assert_eq!(
                case.fx.audit_kinds(),
                ["value_action_pending"],
                "a reported success writes no submitted row"
            );
            case.server.verify().await;
        }

        /// A send whose answer is lost is resent with the same bytes, and the
        /// grant is consumed once for both sends.
        #[cfg(feature = "test-hooks")]
        #[tokio::test]
        #[serial]
        async fn a_resent_envelope_is_consumed_once() {
            struct Lost;
            impl Drop for Lost {
                fn drop(&mut self) {
                    lose_send_answers_on_this_thread(0);
                }
            }

            let case = Case::new("submit-resend").await;
            mount(&case.server, &case.envelope, MAINNET_PASSPHRASE, 2).await;
            let recorder = case.recorder(None);
            let authorization = case.grant();

            let _lost = Lost;
            lose_send_answers_on_this_thread(1);
            case.submit(&recorder, authorization)
                .await
                .expect("the resend confirms");

            assert_eq!(recorder.consumes(), 1, "one consumption for both sends");
            assert_eq!(recorder.outcomes(), ["success"]);
            case.server.verify().await;
        }

        /// A grant for another client of the same endpoint is refused before
        /// any request.
        #[tokio::test]
        #[serial]
        async fn a_grant_for_another_client_is_refused_before_any_request() {
            let case = Case::new("submit-client").await;
            mount(&case.server, &case.envelope, MAINNET_PASSPHRASE, 0).await;
            let recorder = case.recorder(None);
            let other = StellarRpcClient::new(&case.server.uri()).unwrap();
            let authorization =
                case.grant_for((other.url.authority(), other.id()), case.binding(|_| {}));
            let id = authorization.id();

            assert_eq!(
                refused(case.submit(&recorder, authorization).await),
                MainnetPrecondition::EndpointClient
            );
            assert_eq!(requests(&case.server).await, 0);
            assert_not_consumed(&case, &recorder, id);
        }

        /// A grant for another endpoint authority is refused before any
        /// request.
        #[tokio::test]
        #[serial]
        async fn a_grant_for_another_authority_is_refused_before_any_request() {
            let case = Case::new("submit-authority").await;
            mount(&case.server, &case.envelope, MAINNET_PASSPHRASE, 0).await;
            let recorder = case.recorder(None);
            let authorization = case.grant_for(
                ("https://rpc.other.example".to_owned(), case.client.id()),
                case.binding(|_| {}),
            );
            let id = authorization.id();

            assert_eq!(
                refused(case.submit(&recorder, authorization).await),
                MainnetPrecondition::EndpointAuthority
            );
            assert_eq!(requests(&case.server).await, 0);
            assert_not_consumed(&case, &recorder, id);
        }

        #[tokio::test]
        #[serial]
        async fn a_grant_on_testnet_is_refused_before_any_request() {
            let case = Case::new("submit-testnet").await;
            mount(&case.server, &case.envelope, MAINNET_PASSPHRASE, 0).await;
            let recorder = case.recorder(None);
            let authorization = case.grant();
            let id = authorization.id();

            assert_eq!(
                refused(
                    case.submit_with(
                        &case.client,
                        TESTNET_PASSPHRASE,
                        MainnetConsumer::CliPay,
                        &recorder,
                        authorization,
                    )
                    .await
                ),
                MainnetPrecondition::ChainNotMainnet
            );
            assert_eq!(requests(&case.server).await, 0);
            assert_not_consumed(&case, &recorder, id);
        }

        #[tokio::test]
        #[serial]
        async fn another_consumer_is_refused_before_any_request() {
            let case = Case::new("submit-consumer").await;
            mount(&case.server, &case.envelope, MAINNET_PASSPHRASE, 0).await;
            let recorder = case.recorder(None);
            let authorization = case.grant();
            let id = authorization.id();

            assert_eq!(
                refused(
                    case.submit_with(
                        &case.client,
                        MAINNET_PASSPHRASE,
                        MainnetConsumer::McpPay,
                        &recorder,
                        authorization,
                    )
                    .await
                ),
                MainnetPrecondition::ConsumerMismatch
            );
            assert_eq!(requests(&case.server).await, 0);
            assert_not_consumed(&case, &recorder, id);
        }

        #[tokio::test]
        #[serial]
        async fn an_expired_grant_is_refused_before_any_request() {
            let case = Case::new("submit-expired").await;
            mount(&case.server, &case.envelope, MAINNET_PASSPHRASE, 0).await;
            let recorder = case.recorder(None);
            let authorization = case.grant();
            case.fx.clock.set(NOW + TTL_MS);

            assert_eq!(
                refused(case.submit(&recorder, authorization).await),
                MainnetPrecondition::Expired
            );
            assert_eq!(requests(&case.server).await, 0);
            assert_eq!(recorder.consumes(), 0, "the consumption is not entered");
            assert_eq!(recorder.pre_sends(), 0);
        }

        /// An endpoint that reports another network is refused after the
        /// probe and before any send.
        #[tokio::test]
        #[serial]
        async fn an_endpoint_on_another_network_is_refused_before_the_send() {
            let case = Case::new("submit-probe").await;
            mount(&case.server, &case.envelope, TESTNET_PASSPHRASE, 0).await;
            let recorder = case.recorder(None);
            let authorization = case.grant();
            let id = authorization.id();

            let result = case.submit(&recorder, authorization).await;
            match result {
                Err(AuthorizedPathError::Wallet(error)) => {
                    assert_eq!(error.code(), "network.endpoint_network_mismatch");
                }
                other => panic!("expected the endpoint refusal, got {other:?}"),
            }
            assert_not_consumed(&case, &recorder, id);
            case.server.verify().await;
        }

        /// A grant over another transaction hash is refused before the send.
        #[tokio::test]
        #[serial]
        async fn another_transaction_hash_is_refused_before_the_send() {
            let case = Case::new("submit-hash").await;
            mount(&case.server, &case.envelope, MAINNET_PASSPHRASE, 0).await;
            let recorder = case.recorder(None);
            let authorization = case.grant_for(
                case.endpoint(),
                case.binding(|binding| {
                    if let DomainBinding::Transaction { tx_hash, .. } = binding {
                        *tx_hash = [0x22; 32];
                    }
                }),
            );
            let id = authorization.id();

            assert_eq!(
                refused(case.submit(&recorder, authorization).await),
                MainnetPrecondition::TxHash
            );
            assert_not_consumed(&case, &recorder, id);
            case.server.verify().await;
        }

        /// An envelope signed only by another of the source's signers, a
        /// signature the network binding accepts, is refused because the
        /// grant's signer did not sign it.
        #[tokio::test]
        #[serial]
        async fn an_envelope_without_the_grant_signer_is_refused_before_the_send() {
            let envelope = SignedTestEnvelope::builder(SIGNER_SEED)
                .network_passphrase(MAINNET_PASSPHRASE)
                .time_bounds(0, NOW / 1000 + 120)
                .sequence(SEQUENCE)
                .sign(OTHER_SEED, MAINNET_PASSPHRASE)
                .ed25519_signer(&fixtures::account(SIGNER_SEED), OTHER_SEED)
                .build();
            let case = Case::with_envelope("submit-signer", envelope).await;
            mount(&case.server, &case.envelope, MAINNET_PASSPHRASE, 0).await;
            let recorder = case.recorder(None);
            let authorization = case.grant();
            let id = authorization.id();

            assert_eq!(
                refused(case.submit(&recorder, authorization).await),
                MainnetPrecondition::SignerKeyMismatch
            );
            assert_not_consumed(&case, &recorder, id);
            case.server.verify().await;
        }

        /// A proof that differs from the submission in one field is refused
        /// before the send, after the consumption. The outcome is recorded as
        /// rejected and the converted reservation stands: the signed bytes
        /// exist outside the wallet and may still apply.
        async fn assert_tampered_proof_refused(
            label: &str,
            tamper: Tamper,
            expected: MainnetPrecondition,
        ) {
            let case = Case::new(label).await;
            mount(&case.server, &case.envelope, MAINNET_PASSPHRASE, 0).await;
            let recorder = case.recorder(Some(tamper));

            let authorization = case.grant();
            let id = authorization.id();
            assert_eq!(
                refused(case.submit(&recorder, authorization).await),
                expected
            );
            assert_eq!(recorder.consumes(), 1);
            assert_eq!(recorder.outcomes(), ["rejected"]);
            case.fx.assert_used_without_holds(id);
            assert!(
                case.reservation_is_open(),
                "a rejection keeps the converted reservation"
            );
            case.server.verify().await;
        }

        #[tokio::test]
        #[serial]
        async fn a_proof_of_another_envelope_is_refused_before_the_send() {
            assert_tampered_proof_refused(
                "submit-proof-envelope",
                Tamper::EnvelopeHash,
                MainnetPrecondition::BindingMismatch,
            )
            .await;
        }

        #[tokio::test]
        #[serial]
        async fn a_proof_of_other_content_is_refused_before_the_send() {
            assert_tampered_proof_refused(
                "submit-proof-content",
                Tamper::ContentDigest,
                MainnetPrecondition::ContentDigest,
            )
            .await;
        }

        #[tokio::test]
        #[serial]
        async fn a_proof_of_another_authorization_is_refused_before_the_send() {
            assert_tampered_proof_refused(
                "submit-proof-id",
                Tamper::AuthorizationId,
                MainnetPrecondition::UnknownAuthorization,
            )
            .await;
        }

        /// A primary endpoint that reports `FAILED` for a transaction the
        /// oracle reports applied settles nothing: the reservation keeps the
        /// debit and the caller gets the timeout shape.
        #[tokio::test]
        #[serial]
        async fn a_failed_confirmation_the_oracle_reports_applied_keeps_the_reservation() {
            let case = Case::new("submit-failed-oracle-success").await;
            mount_answers(
                &case.server,
                &case.envelope,
                MAINNET_PASSPHRASE,
                1,
                json!({ "hash": case.envelope.tx_hash_hex(), "status": "PENDING",
                    "latestLedger": 1000, "latestLedgerCloseTime": "1699999999" }),
                transaction_answer(&case.envelope, "FAILED", Some(BAD_SEQ_RESULT_XDR)),
            )
            .await;
            let (oracle_server, oracle) =
                oracle_answering(transaction_answer(&case.envelope, "SUCCESS", None)).await;
            let recorder = case.recorder(None);

            let result = case.submit_witnessed(&recorder, Some(&oracle)).await;

            assert_submission_stands(&case, &recorder, result);
            assert_eq!(
                methods_asked(&oracle_server).await,
                ["getNetwork", "getTransaction"],
                "the oracle's identity, then one question"
            );
            case.server.verify().await;
        }

        /// The oracle's own `FAILED` is returned under the code of the
        /// oracle's result, and the submission stands: a reported failure does
        /// not release possible spending and writes no failed row.
        #[tokio::test]
        #[serial]
        async fn a_failed_confirmation_the_oracle_confirms_returns_the_oracle_code_and_stands() {
            let case = Case::new("submit-failed-oracle-failed").await;
            mount_answers(
                &case.server,
                &case.envelope,
                MAINNET_PASSPHRASE,
                1,
                json!({ "hash": case.envelope.tx_hash_hex(), "status": "PENDING",
                    "latestLedger": 1000, "latestLedgerCloseTime": "1699999999" }),
                transaction_answer(&case.envelope, "FAILED", Some(BAD_SEQ_RESULT_XDR)),
            )
            .await;
            let oracle_result = result_xdr(TransactionResultResult::TxInsufficientFee);
            let (_oracle_server, oracle) = oracle_answering(transaction_answer(
                &case.envelope,
                "FAILED",
                Some(&oracle_result),
            ))
            .await;
            let recorder = case.recorder(None);

            let error = case
                .submit_witnessed(&recorder, Some(&oracle))
                .await
                .expect_err("a confirmed failure is returned");

            assert_eq!(error.code(), "ledger.op_failed", "the oracle's code");
            assert_eq!(recorder.outcomes(), ["on_chain_failed"]);
            assert!(case.reservation_is_open(), "the reservation stands");
            assert_eq!(case.receipt_status(), ReceiptStatus::Pending);
            assert_eq!(
                case.fx.audit_kinds(),
                ["value_action_pending"],
                "a reported failure writes no failed row"
            );
            let log = std::fs::read_to_string(&case.fx.profile.audit_log_path).unwrap();
            assert!(!log.contains("submission.sequence_number_stale"), "{log}");
            case.server.verify().await;
        }

        /// A `FAILED` confirmation with an oracle that cannot be reached, and
        /// with no oracle at all, settles nothing.
        #[tokio::test]
        #[serial]
        async fn a_failed_confirmation_without_an_oracle_answer_keeps_the_reservation() {
            let unreachable = StellarRpcClient::new("http://127.0.0.1:9").unwrap();
            for (label, oracle) in [
                ("submit-failed-oracle-unreachable", Some(&unreachable)),
                ("submit-failed-no-oracle", None),
            ] {
                let case = Case::new(label).await;
                mount_answers(
                    &case.server,
                    &case.envelope,
                    MAINNET_PASSPHRASE,
                    1,
                    json!({ "hash": case.envelope.tx_hash_hex(), "status": "PENDING",
                        "latestLedger": 1000, "latestLedgerCloseTime": "1699999999" }),
                    transaction_answer(&case.envelope, "FAILED", Some(BAD_SEQ_RESULT_XDR)),
                )
                .await;
                let recorder = case.recorder(None);

                let result = case.submit_witnessed(&recorder, oracle).await;

                assert_submission_stands(&case, &recorder, result);
                case.server.verify().await;
            }
        }

        /// An oracle that reports the testnet passphrase confirms nothing: its
        /// `FAILED` for the same hash does not settle the submission, and its
        /// transaction is never asked.
        #[tokio::test]
        #[serial]
        async fn a_failed_confirmation_an_oracle_on_another_network_reports_keeps_the_reservation()
        {
            let case = Case::new("submit-failed-oracle-testnet").await;
            mount_answers(
                &case.server,
                &case.envelope,
                MAINNET_PASSPHRASE,
                1,
                json!({ "hash": case.envelope.tx_hash_hex(), "status": "PENDING",
                    "latestLedger": 1000, "latestLedgerCloseTime": "1699999999" }),
                transaction_answer(&case.envelope, "FAILED", Some(BAD_SEQ_RESULT_XDR)),
            )
            .await;
            let (oracle_server, oracle) = oracle_reporting(
                TESTNET_PASSPHRASE,
                Duration::ZERO,
                transaction_answer(&case.envelope, "FAILED", Some(BAD_SEQ_RESULT_XDR)),
                Duration::ZERO,
            )
            .await;
            let recorder = case.recorder(None);

            let result = case.submit_witnessed(&recorder, Some(&oracle)).await;

            assert_submission_stands(&case, &recorder, result);
            assert_eq!(methods_asked(&oracle_server).await, ["getNetwork"]);
            case.server.verify().await;
        }

        /// An oracle whose answer arrives after the submission deadline
        /// confirms nothing: the call returns the timeout shape at the
        /// deadline, before the oracle's late `FAILED`, and the reservation
        /// stands.
        #[tokio::test]
        #[serial]
        async fn a_failed_confirmation_the_oracle_confirms_after_the_deadline_keeps_the_reservation()
         {
            const DEADLINE: Duration = Duration::from_secs(2);
            const LATE: Duration = Duration::from_secs(30);
            let case = Case::new("submit-failed-oracle-late").await;
            mount_answers(
                &case.server,
                &case.envelope,
                MAINNET_PASSPHRASE,
                1,
                json!({ "hash": case.envelope.tx_hash_hex(), "status": "PENDING",
                    "latestLedger": 1000, "latestLedgerCloseTime": "1699999999" }),
                transaction_answer(&case.envelope, "FAILED", Some(BAD_SEQ_RESULT_XDR)),
            )
            .await;
            let (oracle_server, oracle) = oracle_reporting(
                MAINNET_PASSPHRASE,
                Duration::ZERO,
                transaction_answer(&case.envelope, "FAILED", Some(BAD_SEQ_RESULT_XDR)),
                LATE,
            )
            .await;
            let recorder = case.recorder(None);

            let started = std::time::Instant::now();
            let result = case
                .submit_witnessed_within(&recorder, Some(&oracle), DEADLINE)
                .await;
            let elapsed = started.elapsed();

            assert_submission_stands(&case, &recorder, result);
            assert!(
                elapsed < DEADLINE + SLACK,
                "the deadline ends the wait for the oracle: {elapsed:?}"
            );
            assert_eq!(
                methods_asked(&oracle_server).await,
                ["getNetwork", "getTransaction"],
                "the oracle was asked and did not answer in time"
            );
            case.server.verify().await;
        }

        /// An oracle whose identity answer arrives after the submission
        /// deadline confirms nothing: the identity check ends at the
        /// deadline, the call returns the timeout shape, the transaction is
        /// never asked, and the reservation stands.
        #[tokio::test]
        #[serial]
        async fn a_failed_confirmation_whose_oracle_identity_answers_after_the_deadline_keeps_the_reservation()
         {
            const DEADLINE: Duration = Duration::from_secs(2);
            const LATE: Duration = Duration::from_secs(30);
            let case = Case::new("submit-failed-oracle-identity-late").await;
            mount_answers(
                &case.server,
                &case.envelope,
                MAINNET_PASSPHRASE,
                1,
                json!({ "hash": case.envelope.tx_hash_hex(), "status": "PENDING",
                    "latestLedger": 1000, "latestLedgerCloseTime": "1699999999" }),
                transaction_answer(&case.envelope, "FAILED", Some(BAD_SEQ_RESULT_XDR)),
            )
            .await;
            let (oracle_server, oracle) = oracle_reporting(
                MAINNET_PASSPHRASE,
                LATE,
                transaction_answer(&case.envelope, "FAILED", Some(BAD_SEQ_RESULT_XDR)),
                Duration::ZERO,
            )
            .await;
            let recorder = case.recorder(None);

            let started = std::time::Instant::now();
            let result = case
                .submit_witnessed_within(&recorder, Some(&oracle), DEADLINE)
                .await;
            let elapsed = started.elapsed();

            assert_submission_stands(&case, &recorder, result);
            assert!(
                elapsed < DEADLINE + SLACK,
                "the deadline ends the identity check: {elapsed:?}"
            );
            assert_eq!(
                methods_asked(&oracle_server).await,
                ["getNetwork"],
                "an oracle whose identity is unread is not asked about the transaction"
            );
            case.server.verify().await;
        }

        /// A send the primary refuses with a result settles nothing on
        /// mainnet: the reservation and the pending receipt stand, and the
        /// sequence stays held against a second submission.
        #[tokio::test]
        #[serial]
        async fn a_refused_send_keeps_the_reservation_and_the_sequence() {
            let case = Case::new("submit-refused").await;
            let refusal = result_xdr(TransactionResultResult::TxInsufficientFee);
            mount_answers(
                &case.server,
                &case.envelope,
                MAINNET_PASSPHRASE,
                1,
                json!({ "hash": case.envelope.tx_hash_hex(), "status": "ERROR",
                    "latestLedger": 1000, "latestLedgerCloseTime": "1699999999",
                    "errorResultXdr": refusal }),
                transaction_answer(&case.envelope, "SUCCESS", None),
            )
            .await;
            let (oracle_server, oracle) =
                oracle_answering(transaction_answer(&case.envelope, "NOT_FOUND", None)).await;
            let recorder = case.recorder(None);

            let result = case.submit_witnessed(&recorder, Some(&oracle)).await;

            assert_submission_stands(&case, &recorder, result);
            assert_eq!(
                requests(&oracle_server).await,
                0,
                "a refusal has no record an oracle could report"
            );

            let rebuilt = SignedTestEnvelope::builder(SIGNER_SEED)
                .network_passphrase(MAINNET_PASSPHRASE)
                .sequence(SEQUENCE)
                .amount_stroops(7_654_321)
                .build();
            assert_ne!(rebuilt.envelope_xdr(), case.envelope.envelope_xdr());
            match case
                .recorder(None)
                .pre_send(&fixtures::intent(&rebuilt))
                .await
            {
                Err(WalletError::Submission(SubmissionError::TxAlreadySubmitted { hash })) => {
                    assert_eq!(hash, case.envelope.tx_hash_hex());
                }
                other => panic!("the held sequence refuses a second submission: {other:?}"),
            }
            case.server.verify().await;
        }

        /// A signed mainnet envelope of the fixture's source whose deadline
        /// lies `seconds` after the fixture clock, and the binding of its
        /// unsigned form.
        fn envelope_due_in(seconds: u64) -> (SignedTestEnvelope, DomainBinding) {
            let build = |signed: bool| {
                let builder = SignedTestEnvelope::builder(SIGNER_SEED)
                    .network_passphrase(MAINNET_PASSPHRASE)
                    .time_bounds(0, NOW / 1000 + seconds)
                    .sequence(SEQUENCE);
                if signed {
                    builder.build()
                } else {
                    builder.unsigned().build()
                }
            };
            let unsigned = build(false);
            (
                build(true),
                fixtures::tx_binding(unsigned.envelope_xdr(), unsigned.tx_hash_hex()),
            )
        }

        /// An envelope whose deadline the send margin reaches refuses before
        /// any request: at exactly the margin, and inside it. Nothing is
        /// recorded and the authorization stays open.
        #[tokio::test]
        #[serial]
        async fn authorized_submission_refuses_inside_the_margin_before_any_request() {
            use crate::mainnet::resolve::MAINNET_SEND_MARGIN_SECONDS;
            for seconds in [MAINNET_SEND_MARGIN_SECONDS, 1] {
                let (envelope, binding) = envelope_due_in(seconds);
                let case = Case::with_envelope(&format!("submit-margin-{seconds}"), envelope).await;
                mount(&case.server, &case.envelope, MAINNET_PASSPHRASE, 0).await;
                let recorder = case.recorder(None);
                let authorization = case.grant_for(case.endpoint(), binding);
                let id = authorization.id();

                assert_eq!(
                    refused(case.submit(&recorder, authorization).await),
                    MainnetPrecondition::DeadlineWithinMargin,
                    "{seconds}"
                );
                assert_eq!(requests(&case.server).await, 0, "{seconds}");
                assert_not_consumed(&case, &recorder, id);
                assert!(
                    case.fx
                        .receipts
                        .get(&case.envelope_hash())
                        .unwrap()
                        .is_none(),
                    "{seconds}: no receipt"
                );
                assert!(case.fx.audit_kinds().is_empty(), "{seconds}: no row");
                assert!(recorder.outcomes().is_empty(), "{seconds}");
            }
        }

        /// A consumption that outlasts the send-by instant, the deadline less
        /// the margin, sends nothing and reports one unsent outcome: the
        /// converted holds are released, the pending row is closed, the
        /// receipt is removed, and the authorization stays used.
        #[tokio::test]
        #[serial]
        async fn authorized_submission_sends_by_the_margin() {
            use crate::mainnet::resolve::MAINNET_SEND_MARGIN_SECONDS;
            // The send-by instant lies one second ahead of the fixture clock.
            let (envelope, binding) = envelope_due_in(MAINNET_SEND_MARGIN_SECONDS + 1);
            let case = Case::with_envelope("submit-send-by", envelope).await;
            mount(&case.server, &case.envelope, MAINNET_PASSPHRASE, 0).await;
            let mut recorder = case.recorder(None);
            recorder.consume_delay = Duration::from_millis(1500);
            let authorization = case.grant_for(case.endpoint(), binding);
            let id = authorization.id();

            assert_eq!(
                refused(case.submit(&recorder, authorization).await),
                MainnetPrecondition::DeadlineWithinMargin
            );
            assert_eq!(recorder.consumes(), 1);
            assert_eq!(recorder.outcomes(), ["not_sent"]);
            assert_eq!(
                methods_asked(&case.server).await,
                ["getNetwork", "getLedgerEntries"],
                "nothing is sent"
            );
            assert!(!case.reservation_is_open(), "the holds are released");
            case.fx.assert_used_without_holds(id);
            assert!(
                case.fx
                    .receipts
                    .get(&case.envelope_hash())
                    .unwrap()
                    .is_none(),
                "the receipt is removed"
            );
            assert_eq!(
                case.fx.audit_kinds(),
                ["value_action_pending", "value_action_failed"]
            );
            case.server.verify().await;
        }

        /// The intent the consumption records carries the attempt's send-by
        /// instant: the envelope's deadline less the send margin, in Unix
        /// milliseconds.
        #[tokio::test]
        #[serial]
        async fn the_intent_carries_the_attempt_send_by() {
            use crate::mainnet::resolve::MAINNET_SEND_MARGIN_SECONDS;
            let case = Case::new("submit-intent-send-by").await;
            mount(&case.server, &case.envelope, MAINNET_PASSPHRASE, 1).await;
            let recorder = case.recorder(None);

            case.submit(&recorder, case.grant())
                .await
                .expect("a valid grant submits");

            assert_eq!(
                recorder.send_bys(),
                [Some(
                    (NOW / 1000 + 120) * 1000 - MAINNET_SEND_MARGIN_SECONDS * 1000
                )]
            );
            case.server.verify().await;
        }

        /// A refusal leaves the public entry point as the generic mainnet
        /// authorization refusal.
        #[tokio::test]
        #[serial]
        async fn a_refused_grant_reports_the_authorization_refusal() {
            let case = Case::new("submit-code").await;
            mount(&case.server, &case.envelope, MAINNET_PASSPHRASE, 0).await;
            let recorder = case.recorder(None);

            let error = submit_authorized_transaction_and_wait(
                &case.client,
                None,
                case.envelope.envelope_xdr(),
                TIMEOUT,
                MAINNET_PASSPHRASE,
                None,
                &recorder,
                MainnetConsumer::McpPay,
                MainnetSubmitGrant::Tx(case.grant()),
            )
            .await
            .expect_err("another consumer is refused");

            assert_eq!(error.code(), "network.mainnet_authorization_refused");
            assert_eq!(requests(&case.server).await, 0);
        }
    }
}
