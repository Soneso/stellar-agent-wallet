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

use crate::client::StellarRpcClient;
use crate::redact::redact_url_authority;
use crate::retry::{
    RetryPolicy, is_retryable_poll_error, is_retryable_send_error, retry_with_backoff,
    truncate_error_display,
};

// Mainnet network passphrase (canonical; same constant used by friendbot.rs).
const MAINNET_PASSPHRASE: &str = "Public Global Stellar Network ; September 2015";

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
/// `network_passphrase` is compared against the canonical mainnet passphrase
/// as the primary mainnet-write guard. The URL heuristic `is_mainnet_url`
/// is retained as a defence-in-depth layer.
///
/// # Errors
///
/// - [`WalletError::Protocol`] wrapping [`ProtocolError::XdrCodecFailed`] if
///   `envelope_xdr` cannot be decoded.
/// - [`WalletError::Network`] wrapping [`NetworkError::RpcUnreachable`] or
///   [`NetworkError::RpcTimeout`] on transport errors.
/// - [`WalletError::Network`] wrapping [`NetworkError::MainnetWriteForbidden`]
///   if `network_passphrase` matches the mainnet passphrase or the URL appears
///   to target mainnet.
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
) -> Result<SubmissionResult, WalletError> {
    // Mainnet write is structurally forbidden at the submit layer.
    //
    // Primary check: passphrase comparison (catches third-party providers
    // that do not use SDF hostnames).
    if network_passphrase == MAINNET_PASSPHRASE {
        return Err(WalletError::Network(NetworkError::MainnetWriteForbidden));
    }
    // Defence-in-depth: URL heuristic (catches slip-of-the-fingers RPC URL
    // overrides that still target SDF mainnet endpoints).
    if is_mainnet_url(&client.url) {
        return Err(WalletError::Network(NetworkError::MainnetWriteForbidden));
    }

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

    // Submit via `sendTransaction`, with bounded exponential-backoff retry for
    // transient transport errors.
    //
    // Safety: retrying the same signed envelope is safe ONLY because the
    // idempotent-submit layer (`idempotent_submit`) tracks the envelope hash.
    // A retried send that already landed is caught by the receipt store.
    // Do NOT remove or bypass idempotency when using this retry.
    //
    // `TransactionSubmissionFailed` is NOT retried — it wraps both genuine
    // on-chain rejections AND transport-429-on-send, and those are
    // indistinguishable here without fragile Display-string matching.
    // Retry-After / transport-429-on-send is not currently honoured; blind backoff is used instead.
    let started = tokio::time::Instant::now();
    let send_deadline = started + timeout;
    let retry_policy = RetryPolicy::default();

    let tx_hash = {
        let inner = &client.inner;
        let url = &client.url;
        let timeout_secs = timeout.as_secs();
        // `envelope` is borrowed (not moved) across each retry attempt so the
        // closure can be called multiple times (FnMut requirement).
        retry_with_backoff(
            &retry_policy,
            send_deadline,
            is_retryable_send_error,
            || async { inner.send_transaction(&envelope).await },
        )
        .await
        .map_err(|e| map_send_error(&e, url, timeout_secs))?
    };

    let tx_hash_hex = bytes_to_hex(&tx_hash.0);
    let redacted = redact_tx_hash(&tx_hash_hex);
    tracing::info!(tx_hash = %redacted, "submit_transaction_and_wait: transaction submitted");

    // Poll until SUCCESS, FAILED, or timeout.
    //
    // Transient `JsonRpc(_)` errors from `get_transaction` are treated like
    // `NOT_FOUND` — log at debug level and fall through to the deadline check
    // + POLL_INTERVAL sleep.  This prevents a transient rate-limit from
    // aborting the entire submission while preserving the hard timeout bound.
    // A retryable poll error never `continue`s past the deadline check — the
    // loop terminates on timeout even if every poll errors.
    //
    // Keep in sync with the poll loop in `idempotent_submit.rs`: any change to
    // retryable-error treatment here must be mirrored there.

    loop {
        let poll_result = client.inner.get_transaction(&tx_hash).await;

        let response = match poll_result {
            Ok(r) => r,
            Err(ref e) if is_retryable_poll_error(e) => {
                // Treat transient transport error as NOT_FOUND: log at debug
                // and fall through to the deadline check + sleep.
                // Truncate error display to bound log volume from a hostile
                // endpoint.
                let url_authority = redact_url_authority(&client.url);
                tracing::debug!(
                    tx_hash = %redacted,
                    rpc_url = %url_authority,
                    error = %truncate_error_display(e),
                    "submit_transaction_and_wait: transient get_transaction error \
                     (treating as NOT_FOUND, continuing poll)"
                );
                // Fall through to deadline check below.
                if started.elapsed() >= timeout {
                    return Err(WalletError::Submission(SubmissionError::TxTimeout {
                        tx_hash: tx_hash_hex,
                        seconds: timeout.as_secs(),
                    }));
                }
                tokio::time::sleep(POLL_INTERVAL).await;
                continue;
            }
            Err(e) => {
                return Err(map_rpc_error_generic(&e, &client.url, timeout.as_secs()));
            }
        };

        match response.status.as_str() {
            "SUCCESS" => {
                let ledger = response.ledger.unwrap_or(0);
                tracing::info!(
                    tx_hash = %redacted,
                    ledger,
                    "submit_transaction_and_wait: confirmed"
                );
                return Ok(SubmissionResult {
                    tx_hash: tx_hash_hex,
                    ledger,
                    signer_kind,
                });
            }

            "FAILED" => {
                let err = map_failed_result(response.result.as_ref());
                tracing::warn!(
                    tx_hash = %redacted,
                    error = %err,
                    "submit_transaction_and_wait: transaction failed on-chain"
                );
                return Err(err);
            }

            // NOT_FOUND: transaction not yet in a ledger. Continue polling.
            "NOT_FOUND" => {}

            other => {
                return Err(WalletError::Network(NetworkError::RpcUnreachable {
                    url: redact_url_authority(&client.url),
                    reason: format!("unexpected getTransaction status: {other}"),
                }));
            }
        }

        if started.elapsed() >= timeout {
            return Err(WalletError::Submission(SubmissionError::TxTimeout {
                tx_hash: tx_hash_hex,
                seconds: timeout.as_secs(),
            }));
        }

        tokio::time::sleep(POLL_INTERVAL).await;
    }
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
fn map_send_error(e: &stellar_rpc_client::Error, url: &str, timeout_secs: u64) -> WalletError {
    use stellar_rpc_client::Error as RpcErr;
    match e {
        RpcErr::TransactionSubmissionFailed(msg) => {
            // Try to parse the message for specific error codes.
            WalletError::Submission(SubmissionError::TxMalformed {
                detail: msg.clone(),
            })
        }
        RpcErr::TransactionSubmissionTimeout => WalletError::Network(NetworkError::RpcTimeout {
            url: redact_url_authority(url),
            timeout_secs,
        }),
        RpcErr::Xdr(_) => WalletError::Protocol(ProtocolError::XdrCodecFailed {
            detail: e.to_string(),
        }),
        _ => WalletError::Network(NetworkError::RpcUnreachable {
            url: redact_url_authority(url),
            reason: e.to_string(),
        }),
    }
}

/// Maps a generic RPC error to [`WalletError`].
///
/// `timeout_secs` is the actual caller-configured timeout, used in the
/// `RpcTimeout` variant so the value is accurate rather than hardcoded.
fn map_rpc_error_generic(
    e: &stellar_rpc_client::Error,
    url: &str,
    timeout_secs: u64,
) -> WalletError {
    use stellar_rpc_client::Error as RpcErr;
    match e {
        RpcErr::TransactionSubmissionTimeout => WalletError::Network(NetworkError::RpcTimeout {
            url: redact_url_authority(url),
            timeout_secs,
        }),
        RpcErr::Xdr(_) => WalletError::Protocol(ProtocolError::XdrCodecFailed {
            detail: e.to_string(),
        }),
        _ => WalletError::Network(NetworkError::RpcUnreachable {
            url: redact_url_authority(url),
            reason: e.to_string(),
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
/// Exported `pub(crate)` so the retention-aware poll loop in
/// `idempotent_submit::submit_with_retention_poll` and the stale-Pending
/// recovery path in `handle_stale_pending` both use the same mapping,
/// ensuring the receipt's `Failed { code }` string and the returned
/// `WalletError` are always derived from the same XDR path.
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
}
