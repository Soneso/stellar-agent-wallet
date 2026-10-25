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
//! The submission deadline bounds the poll as well: each poll request is cut
//! at it, each sleep between polls ends at it at the latest, and an answer
//! that completes after it is not accepted.
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
use stellar_agent_core::error::{
    LedgerError, NetworkError, ProtocolError, SubmissionError, WalletError,
};
use stellar_xdr::{
    InnerTransactionResultResult, OperationResult, OperationResultTr, PaymentResult, ReadXdr,
    TransactionEnvelope, TransactionResult, TransactionResultResult,
};

use crate::client::{RpcEndpoint, StellarRpcClient, rpc_unreachable, unexpected_status};
use crate::mainnet::authorization::MainnetTxSignAuthorization;
use crate::mainnet::consumed::AuthorizationConsumed;
use crate::mainnet::refusal::AuthorizedPathError;
use crate::mainnet::{AuthorizationDomain, MainnetConsumer, MainnetPrecondition};
use crate::retry::{
    RetryPolicy, is_retryable_poll_error, is_retryable_send_error, retry_with_backoff,
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
/// `timeout` is one budget for the whole submission, not for the send alone:
/// the endpoint identity probe and the signer-set fetch that precede the send
/// are bounded by the same deadline, and each of their retries is cut off by
/// it. A caller sizing this value has to allow for two reads ahead of the
/// send. The confirmation poll ends at the same deadline: a status that
/// arrives after it is not accepted, and the call returns the timeout.
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
///   its identity cannot be established within `timeout`.
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
    .map_err(|e| {
        WalletError::Protocol(ProtocolError::XdrCodecFailed {
            detail: format!("failed to decode TransactionEnvelope from base64 XDR: {e}"),
        })
    })?;

    let send_deadline = tokio::time::Instant::now() + timeout;

    // A legacy V0 envelope has no SEP-23 tagged-transaction form, so neither
    // the signing path nor binding verification can construct a payload for
    // it. Refused here so it costs no round trip.
    reject_v0_envelope(&envelope)?;

    // Ask the endpoint which network it serves and which protocol it runs, on
    // the client instance that will send. The target network is a property of
    // the endpoint; the caller's declaration is only a claim about it, and the
    // two must be shown to agree before anything is sent. Bounded by the
    // caller's own deadline.
    client
        .endpoint_identity(network_passphrase, send_deadline)
        .await?;

    // With the endpoint's network established, verify that the envelope's
    // signatures were produced for that network. This is what stops an
    // envelope signed for one network from being relayed to another. The
    // response's ledger is the endpoint's view of the chain immediately before
    // the send, which is what a later reconciliation compares against the
    // endpoint's retention floor.
    let submission_ledger =
        verify_signature_network_binding(client, &envelope, network_passphrase, send_deadline)
            .await?;

    // The transaction hash is a property of the envelope, not of the endpoint:
    // it is computable from the bytes about to be sent. Computing it here
    // means the wallet polls, records and reports the hash of what it signed,
    // and can tell when the endpoint describes something else.
    let tx_hash_hex = compute_local_tx_hash_hex(&envelope, network_passphrase)?;
    let local_hash_bytes = tx_hash_bytes(&tx_hash_hex)?;

    let (source, sequence) = replay_identity(&envelope)?;
    let intent = SubmissionIntent {
        envelope_hash: envelope_hash_hex(envelope_xdr),
        tx_hash: tx_hash_hex,
        source,
        sequence,
        max_time: crate::idempotent_submit::extract_max_time(&envelope),
        submission_ledger,
    };

    // The record is written before the send, so a submission whose outcome
    // never comes back is still one the wallet remembers.
    if let Some(rec) = recorder {
        rec.pre_send(&intent).await?;
    }

    send_and_confirm(
        client,
        &envelope,
        &intent,
        local_hash_bytes,
        send_deadline,
        timeout,
        recorder,
        signer_kind,
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
/// The mainnet counterpart of [`submit_transaction_and_wait`], with one
/// budget `timeout` for the whole submission in the same way. In order:
///
/// 1. The local gate, before any request: `network_passphrase` and the bound
///    chain must be mainnet's, `consumer` the bound consuming verb, the grant
///    unexpired on the clock of [`crate::mainnet::clock::now_ms`], and the
///    client's authority and identity the bound endpoint. The endpoint
///    binding is the authority on the endpoint, so the URL heuristic of
///    [`refuse_mainnet_write`] does not apply.
/// 2. The envelope is decoded; a legacy `TxV0` envelope is refused, and only
///    a `Tx` envelope is sent under a transaction grant.
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
/// 7. The envelope is sent once, through the retry of transport failures
///    that resends the same bytes, and the confirmation is polled.
///
/// Compiled in every build; without mainnet writes no grant exists, so the
/// function cannot be called.
///
/// # Errors
///
/// - [`WalletError::Network`] wrapping
///   [`NetworkError::MainnetAuthorizationRefused`] if a check of the grant
///   fails, the envelope is a fee bump, the bound signer did not sign, or the
///   recorder's proof does not match. The broken precondition is logged.
/// - [`WalletError::Network`] wrapping
///   [`NetworkError::EndpointNetworkMismatch`] if the endpoint does not serve
///   mainnet, and the other errors of [`submit_transaction_and_wait`] for the
///   identity probe, the signature binding, the send, and the poll.
/// - The recorder's refusal from
///   [`SubmissionRecorder::pre_send_authorized`].
///
/// # Panics
///
/// Never panics.
#[allow(
    clippy::too_many_arguments,
    reason = "the inputs of submit_transaction_and_wait plus the consuming verb and the grant"
)]
pub async fn submit_authorized_transaction_and_wait(
    client: &StellarRpcClient,
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
    mainnet_submit_gate(
        network_passphrase,
        &authority,
        client.id(),
        consumer,
        authorization,
        crate::mainnet::clock::now_ms()?,
    )?;

    let envelope = TransactionEnvelope::from_xdr_base64(
        envelope_xdr,
        stellar_agent_xdr_limits::untrusted_decode_limits(envelope_xdr.len()),
    )
    .map_err(|e| {
        WalletError::Protocol(ProtocolError::XdrCodecFailed {
            detail: format!("failed to decode TransactionEnvelope from base64 XDR: {e}"),
        })
    })?;
    let send_deadline = tokio::time::Instant::now() + timeout;
    reject_v0_envelope(&envelope)?;
    if !matches!(envelope, TransactionEnvelope::Tx(_)) {
        return Err(AuthorizedPathError::Refused(
            MainnetPrecondition::BindingMismatch,
        ));
    }

    // The probe's contribution is the passphrase: the endpoint binding was
    // compared against this client's authority and identity above.
    client.mainnet_endpoint_identity(send_deadline).await?;
    let submission_ledger =
        verify_signature_network_binding(client, &envelope, MAINNET_PASSPHRASE, send_deadline)
            .await?;
    if !grant_signer_signed(&envelope, &authorization.signer_public_key())? {
        return Err(AuthorizedPathError::Refused(
            MainnetPrecondition::SignerKeyMismatch,
        ));
    }

    let tx_hash_hex = compute_local_tx_hash_hex(&envelope, MAINNET_PASSPHRASE)?;
    let local_hash_bytes = tx_hash_bytes(&tx_hash_hex)?;
    authorization.check_tx_hash(&local_hash_bytes)?;

    let (source, sequence) = replay_identity(&envelope)?;
    let intent = SubmissionIntent {
        envelope_hash: envelope_hash_hex(envelope_xdr),
        tx_hash: tx_hash_hex,
        source,
        sequence,
        max_time: crate::idempotent_submit::extract_max_time(&envelope),
        submission_ledger,
    };
    let authorization_id = authorization.id();

    // The consumption is the record: it runs once, before the send and its
    // retries.
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

    Ok(send_and_confirm(
        client,
        &envelope,
        &intent,
        local_hash_bytes,
        send_deadline,
        timeout,
        Some(recorder),
        signer_kind,
    )
    .await?)
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
/// that resends the same bytes, compares the endpoint's hash with the local
/// one, and polls for the confirmation.
#[allow(
    clippy::too_many_arguments,
    reason = "the facts both submit paths established before the send"
)]
async fn send_and_confirm(
    client: &StellarRpcClient,
    envelope: &TransactionEnvelope,
    intent: &SubmissionIntent,
    local_hash_bytes: [u8; 32],
    send_deadline: tokio::time::Instant,
    timeout: Duration,
    recorder: Option<&dyn SubmissionRecorder>,
    signer_kind: Option<SubmissionSignerKind>,
) -> Result<SubmissionResult, WalletError> {
    let retry_policy = RetryPolicy::default();
    let redacted = redact_tx_hash(&intent.tx_hash);

    // Submit via `sendTransaction`, with bounded exponential-backoff retry for
    // transient transport errors.
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

    let server_tx_hash = {
        let inner = &client.inner;
        // `envelope` is borrowed (not moved) across each retry attempt so the
        // closure can be called multiple times (FnMut requirement).
        retry_with_backoff(
            &retry_policy,
            send_deadline,
            is_retryable_send_error,
            || async { lose_send_answer(inner.send_transaction(envelope).await) },
        )
        .await
    };

    let server_tx_hash = match server_tx_hash {
        Ok(h) => h,
        Err(e) => {
            return Err(
                handle_send_failure(recorder, intent, &e, &client.url, timeout.as_secs()).await,
            );
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
        return Err(err);
    }

    let tx_hash = stellar_xdr::Hash(local_hash_bytes);
    tracing::info!(tx_hash = %redacted, "submit_transaction_and_wait: transaction submitted");

    poll_for_confirmation(
        || client.get_transaction_record(&tx_hash),
        &client.url,
        send_deadline,
        timeout.as_secs(),
        intent,
        recorder,
        signer_kind,
    )
    .await
}

/// Discards the endpoint's answer to this many accepted sends and reports a
/// transport timeout in its place, so the resend of the same envelope after a
/// lost answer is reachable from a test.
///
/// No endpoint answer makes the RPC client report a retryable send error: it
/// reports every failed request as a submission failure. The toggle stands in
/// for a transport that lost the answer after the endpoint took the bytes;
/// the retry that follows it is the production one.
///
/// Only compiled when the `test-hooks` Cargo feature is enabled. Never include
/// `test-hooks` in production or release builds.
#[cfg(feature = "test-hooks")]
#[doc(hidden)]
pub static LOSE_SEND_ANSWERS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// The send's answer, or a transport timeout in its place while
/// [`LOSE_SEND_ANSWERS`] is above zero under `test-hooks`.
#[allow(
    clippy::result_large_err,
    reason = "passes the RPC client's own send result through to its retry classification"
)]
fn lose_send_answer(
    answer: Result<stellar_xdr::Hash, stellar_rpc_client::Error>,
) -> Result<stellar_xdr::Hash, stellar_rpc_client::Error> {
    #[cfg(feature = "test-hooks")]
    if answer.is_ok()
        && LOSE_SEND_ANSWERS
            .try_update(
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
                |lost| lost.checked_sub(1),
            )
            .is_ok()
    {
        return Err(stellar_rpc_client::Error::TransactionSubmissionTimeout);
    }
    answer
}

/// Polls `getTransaction` through `poll` until the transaction settles or
/// `send_deadline` passes, and settles the record to match.
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
/// Keep in sync with the poll loop in `idempotent_submit.rs`: any change to
/// the deadline or retryable-error treatment here must be mirrored there.
async fn poll_for_confirmation<P, F>(
    mut poll: P,
    url: &RpcEndpoint,
    send_deadline: tokio::time::Instant,
    timeout_secs: u64,
    intent: &SubmissionIntent,
    recorder: Option<&dyn SubmissionRecorder>,
    signer_kind: Option<SubmissionSignerKind>,
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
                let err = map_failed_record(&record);
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
                return Err(err);
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

/// Sleeps `interval` before the next confirmation poll, or until `deadline`
/// when that comes first.
///
/// A poll interval never carries a submission past its deadline: the loop
/// that sleeps here checks the deadline before its next request.
pub(crate) async fn sleep_before_next_poll(interval: Duration, deadline: tokio::time::Instant) {
    tokio::time::sleep_until(deadline.min(tokio::time::Instant::now() + interval)).await;
}

/// Settles the record for a submission whose confirmation never arrived, and
/// builds the timeout the caller returns.
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

/// Settles the record for a send that did not return a transaction hash, and
/// builds the error the caller returns.
///
/// Two classes, and they settle differently:
///
/// - The endpoint refused the bytes with a real `TransactionResult`. Nothing
///   was queued and no value moved, so the reservation goes back and the
///   caller gets the refusal itself, with its result code.
/// - Anything else left the outcome unknown. The layer cannot tell a refused
///   connection from a lost response, and by this point the same client has
///   already answered the identity probe and the signer fetch, so the failure
///   is mid-flight rather than a dead endpoint. The record stands and the
///   caller gets the timeout shape, which is what the agent's recovery
///   protocol is written against.
async fn handle_send_failure(
    recorder: Option<&dyn SubmissionRecorder>,
    intent: &SubmissionIntent,
    error: &stellar_rpc_client::Error,
    url: &RpcEndpoint,
    timeout_secs: u64,
) -> WalletError {
    let mapped = map_send_error(error, url, timeout_secs);
    let definitive = is_definitive_send_refusal(error);

    let Some(rec) = recorder else {
        return mapped;
    };

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
/// result. The two settle a submission differently, so they have to be told
/// apart.
const SEND_NO_RESPONSE_MARKER: &str = "No status yet:";

/// Returns true when the send step's failure is the endpoint's own verdict on
/// the transaction.
///
/// The test is negative on purpose. A failure the layer cannot positively
/// attribute to a verdict is treated as one whose outcome is unknown, which is
/// the direction that keeps a transaction that may have been queued recorded.
/// Classifying the other way round would release a reservation and record a
/// failure for a transaction that later applies.
///
/// # Dependency coupling
///
/// The marker is the dependency's own wording, not a contract it publishes:
/// `stellar-rpc-client`'s `send_transaction` builds it at
/// `src/lib.rs`, in the arm that wraps a `jsonrpsee` request failure, while
/// the arm that wraps an endpoint verdict carries the decoded
/// `TransactionResult` instead. A version bump that rewords either arm
/// reclassifies every transport failure as a verdict, which would release a
/// reservation and record a failure for a transaction that may have been
/// queued.
///
/// Both sides are pinned against the real client by
/// `a_transport_failure_after_the_record_returns_the_timeout_shape` and
/// `a_refused_send_releases_the_reservation_and_frees_the_sequence`
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
            envelope_hash: "ab".repeat(32),
            tx_hash: "cd".repeat(32),
            source: "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL".to_owned(),
            sequence: 1,
            max_time: 0,
            submission_ledger: 1,
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

    // ── The authorized submission ─────────────────────────────────────────────

    #[cfg(feature = "mainnet-write")]
    mod authorized {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Mutex};

        use serde_json::json;
        use serial_test::serial;
        use stellar_agent_core::policy::v1::criteria::state_store::WindowEntry;
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
        }

        impl<'a> CountingRecorder<'a> {
            fn new(inner: WalletSubmissionRecorder<'a>, tamper: Option<Tamper>) -> Self {
                Self {
                    inner,
                    tamper,
                    pre_sends: AtomicUsize::new(0),
                    consumes: AtomicUsize::new(0),
                    outcomes: Mutex::new(Vec::new()),
                }
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
                let proof = self.inner.pre_send_authorized(intent, grant).await?;
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
                });
                self.inner.outcome(intent, outcome).await;
            }
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
                .respond_with(SubmissionEchoResponder::new(
                    json!({
                        "hash": envelope.tx_hash_hex(),
                        "status": "PENDING",
                        "latestLedger": 1000,
                        "latestLedgerCloseTime": "1699999999"
                    }),
                    MAINNET_PASSPHRASE,
                ))
                .expect(sends)
                .named("sendTransaction")
                .mount(server)
                .await;
            Mock::given(method("POST"))
                .and(body_partial_json(json!({ "method": "getTransaction" })))
                .respond_with(SubmissionEchoResponder::new(
                    json!({
                        "status": "SUCCESS",
                        "txHash": envelope.tx_hash_hex(),
                        "ledger": 4567,
                        "createdAt": "1700000000",
                        "envelopeXdr": null,
                        "resultXdr": null,
                        "resultMetaXdr": null
                    }),
                    MAINNET_PASSPHRASE,
                ))
                .mount(server)
                .await;
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
                Self::with_envelope(label, fixtures::signed_envelope()).await
            }

            async fn with_envelope(label: &str, envelope: SignedTestEnvelope) -> Self {
                let fx = LedgerFixture::new(label, NOW);
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
            assert_eq!(
                case.fx.audit_kinds(),
                ["value_action_pending", "value_action_submitted"]
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
                    LOSE_SEND_ANSWERS.store(0, Ordering::SeqCst);
                }
            }

            let case = Case::new("submit-resend").await;
            mount(&case.server, &case.envelope, MAINNET_PASSPHRASE, 2).await;
            let recorder = case.recorder(None);
            let authorization = case.grant();

            let _lost = Lost;
            LOSE_SEND_ANSWERS.store(1, Ordering::SeqCst);
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
        /// before the send, after the consumption, and the record is settled
        /// as rejected.
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
                case.fx
                    .window
                    .pending_reservations(&case.fx.profile)
                    .unwrap()
                    .is_empty(),
                "rejection settles the converted reservations"
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
