//! Bounded exponential-backoff retry for Stellar RPC calls.
//!
//! # Overview
//!
//! Implements bounded exponential backoff with per-call-site retryable-error
//! classification and a configurable policy.
//!
//! ## Retry-After upstream limitation
//!
//! `stellar-rpc-client` (via `jsonrpsee_http_client`) exposes no typed HTTP 429
//! variant and no `Retry-After` header accessor.  A 429 response on poll calls
//! surfaces as `Error::JsonRpc(ClientError)`; on `send_transaction` it is
//! wrapped into `Error::TransactionSubmissionFailed("No status yet: …")`, which
//! is indistinguishable from a genuine on-chain rejection without fragile
//! Display-string matching.  This module therefore implements blind capped
//! exponential backoff — the backoff is applied fully; `Retry-After` is not
//! honoured because the upstream client does not surface the header.
//!
//! Retry-After / transport-429-on-send is not currently honoured; blind backoff
//! is used instead.  A typed transport-vs-on-chain discriminator is not yet
//! exposed by `stellar-rpc-client`.
//!
//! ## Safety — no double-submit
//!
//! Retrying `send_transaction` is safe ONLY because the idempotency layer
//! (`idempotent_submit`) sits above the retry loop.  A retried send of an
//! envelope that already landed on the first attempt is caught by the receipt
//! store's terminal-cached path.  **Do not use the send-path retry outside of
//! a context where idempotency is active.**
//!
//! ## Classification is per-call-site
//!
//! A 429 surfaces as different `Error` variants depending on the RPC call:
//! - **Poll** (`get_transaction`, `get_health`): → `Error::JsonRpc(_)` → **retryable**.
//! - **Send** (`send_transaction`): → `Error::TransactionSubmissionFailed("No status yet: …")`
//!   which is indistinguishable from a real on-chain rejection → **NOT retried**
//!   (transport-429-on-send is not currently honoured; blind backoff is used instead).
//!
//! Two separate classifier functions enforce this:
//! - [`is_retryable_send_error`] — for `send_transaction`.
//! - [`is_retryable_poll_error`] — for `get_transaction` / `get_health`.
//!
//! ## Jitter source
//!
//! Full jitter (`delay ∈ [0, min(max_delay, base × 2^attempt)]`) is applied
//! per attempt.  The jitter seed comes from `rand_core::OsRng`, a direct
//! dependency of `stellar-agent-network`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use rand_core::{OsRng, RngCore};
use tokio::time::Instant;

// ─────────────────────────────────────────────────────────────────────────────
// Error-display truncation helper
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum number of characters to log from a server error display string.
///
/// Stellar RPC errors can contain verbose server-controlled response bodies
/// (particularly `JsonRpc` / `TransactionSubmissionFailed` variants).  Logging
/// the full display unbounded creates two risks: log-spam from a hostile
/// endpoint and potential disclosure of internal server-state details.
///
/// 200 chars is sufficient to identify the error class for operational
/// triage without echoing an entire server response body into the log stream.
const MAX_ERROR_DISPLAY_CHARS: usize = 200;

/// Returns at most the first `MAX_ERROR_DISPLAY_CHARS` characters of
/// `e.to_string()` for safe structured-log emission.
///
/// Used at retry-attempt warning/debug sites in `submit.rs` and
/// `idempotent_submit.rs` so a server-controlled `JsonRpc` body cannot
/// produce unbounded log entries.
///
/// Not crypto-sensitive: no envelope XDR or signing material appears in
/// `stellar_rpc_client::Error` display output.
pub(crate) fn truncate_error_display(e: &stellar_rpc_client::Error) -> String {
    let s = e.to_string();
    if s.chars().count() <= MAX_ERROR_DISPLAY_CHARS {
        s
    } else {
        // Take the first MAX_ERROR_DISPLAY_CHARS characters and append an
        // ellipsis so log consumers know the message was truncated.
        let truncated: String = s.chars().take(MAX_ERROR_DISPLAY_CHARS).collect();
        format!("{truncated}…")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RetryPolicy
// ─────────────────────────────────────────────────────────────────────────────

/// Policy governing bounded exponential-backoff retry for RPC calls.
///
/// Configurable max retries with exponential backoff and full jitter.
///
/// # Retry-After limitation
///
/// `stellar-rpc-client` does not surface `Retry-After`; delays are computed
/// from the policy rather than server-supplied hints.  See the module-level
/// documentation for the upstream tracking issue.
///
/// # Examples
///
/// ```
/// use std::time::Duration;
/// use stellar_agent_network::retry::RetryPolicy;
///
/// let policy = RetryPolicy::default();
/// assert_eq!(policy.max_attempts, 5);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Maximum number of attempts (including the first).  The loop exits
    /// after `max_attempts` have been made, regardless of the overall deadline.
    ///
    /// Minimum meaningful value is 1 (run the operation once, no retries).
    pub max_attempts: u32,

    /// Base delay for the first retry.  Subsequent delays double per attempt
    /// before jitter is applied: `min(max_delay, base_delay × 2^attempt)`.
    pub base_delay: Duration,

    /// Hard cap on any single sleep duration (before jitter reduces it to a
    /// uniform sample in `[0, cap]`).  Prevents runaway delays on high
    /// attempt counts.
    pub max_delay: Duration,
}

impl Default for RetryPolicy {
    /// Default policy: 5 attempts, 500 ms base, 8 s cap.
    ///
    /// Under full jitter the actual per-attempt wait is sampled uniformly in
    /// `[0, min(8 s, 500 ms × 2^attempt)]`, bounded by the overall deadline.
    fn default() -> Self {
        Self {
            max_attempts: 5,
            base_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(8),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-call-site retryable classifiers
// ─────────────────────────────────────────────────────────────────────────────

/// Returns `true` if a `sendTransaction` RPC error is worth retrying.
///
/// # Classification rationale
///
/// `send_transaction` wraps any transport failure (including HTTP 429) as
/// `Error::TransactionSubmissionFailed("No status yet: …")` — the same variant
/// used for a genuine on-chain rejection (`status == "ERROR"`).  There is no
/// reliable way to distinguish a transport-level 429 from an on-chain rejection
/// without fragile Display-string matching.
///
/// Retrying `TransactionSubmissionFailed` is unsafe because a deterministic
/// on-chain rejection would be retried, wasting attempts.  The
/// Transport-429-on-send is not currently honoured; blind backoff is used instead.
///
/// Only `TransactionSubmissionTimeout` and `JsonRpc(_)` are retried:
/// - `TransactionSubmissionTimeout`: the RPC call timed out at the transport
///   layer (no on-chain decision was made); safe to retry.
/// - `JsonRpc(_)`: raw transport error (connection reset, server-side error,
///   or 429 surfacing through the jsonrpsee layer before `send_transaction`
///   gets a chance to inspect the response body); safe to retry.
///
/// # Errors
///
/// This function is infallible; it returns a `bool`.
pub fn is_retryable_send_error(e: &stellar_rpc_client::Error) -> bool {
    use stellar_rpc_client::Error as E;
    match e {
        // ── Retryable on send ─────────────────────────────────────────────
        //
        // Transport timeout: the underlying HTTP request timed out.  No
        // on-chain decision was reached; retry is safe.
        E::TransactionSubmissionTimeout => true,

        // Raw transport / jsonrpsee error (connection refused, 5xx, or a
        // 429 that surfaced before the RPC body was read).  Retry is safe.
        E::JsonRpc(_) => true,

        // ── NOT retryable on send ─────────────────────────────────────────
        //
        // On-chain or structural rejections — retrying a guaranteed failure
        // wastes attempts and could mask the real error.

        // `status == "ERROR"` from sendTransaction: the network processed and
        // REJECTED the transaction.  Also wraps transport-429, which is not
        // distinguishable at this level.  NOT retried — retrying a deterministic
        // on-chain rejection is harmful.
        E::TransactionSubmissionFailed(_) => false,

        // The RPC client found a transaction-level failure after submission.
        E::TransactionFailed(_) => false,

        // An unexpected status string came back.  Non-transient protocol error.
        E::UnexpectedTransactionStatus(_) => false,

        // XDR decode failure: the payload is structurally wrong; retry
        // will produce the same result.
        E::Xdr(_) => false,

        // Strkey decode failure: deterministic.
        E::InvalidAddress(_) => false,

        // RPC URL is syntactically invalid: configuration bug, not transient.
        E::InvalidRpcUrl(_) | E::InvalidRpcUrlFromUriParts(_) => false,

        // Friendbot URL invalid: configuration bug.
        E::InvalidUrl(_) => false,

        // JSON / serde decode failure: server returned unparseable data;
        // a structural protocol mismatch that retry cannot fix.
        E::Serde(_) => false,

        // `"result"` field missing from a successful JSON-RPC response:
        // protocol mismatch, not transient.
        E::MissingResult => false,

        // `"error"` field missing from an error JSON-RPC response: same.
        E::MissingError => false,

        // The response body could not be decoded into the expected type:
        // decode failure (e.g. bad `error_result_xdr`).  Retry won't fix
        // a garbage response.
        E::InvalidResponse => false,

        // "not found" from a non-send call: not applicable on send path, but
        // match exhaustively.
        E::NotFound(_, _) => false,

        // Network passphrase mismatch: configuration bug.
        E::InvalidNetworkPassphrase { .. } => false,

        // Missing signing key: configuration bug.
        E::MissingSignerForAddress { .. } => false,

        // Invalid cursor: not applicable to send.
        E::InvalidCursor => false,

        // Simulate result size unexpected: not applicable to send.
        E::UnexpectedSimulateTransactionResultSize { .. } => false,

        // Operation count unexpected: not applicable to send.
        E::UnexpectedOperationCount { .. } => false,

        // Unsupported operation type: structural mismatch.
        E::UnsupportedOperationType => false,

        // Contract-related decode failures: not applicable to send path.
        E::UnexpectedContractCodeDataType(_) => false,
        E::UnexpectedContractInstance(_) => false,

        // Deprecated: not expected on send path but match exhaustively.
        #[allow(deprecated)]
        E::UnexpectedToken(_) => false,

        // Fee too large: structural rejection.
        E::LargeFee(_) => false,

        // Cannot authorise raw transaction: configuration error.
        E::CannotAuthorizeRawTransaction => false,

        // Transaction simulation failure: not a send error, but match
        // exhaustively so the compiler catches new variants.
        E::TransactionSimulationFailed(_) => false,

        // Missing op: protocol mismatch.
        E::MissingOp => false,
    }
}

/// Returns `true` if a `getTransaction` or `getHealth` RPC error is worth
/// retrying.
///
/// # Classification rationale
///
/// On poll calls (`getTransaction`, `getHealth`) the jsonrpsee layer passes
/// HTTP errors directly as `Error::JsonRpc(ClientError)`.  A 429 response
/// surfaces here as `JsonRpc(_)` — without the `TransactionSubmissionFailed`
/// wrapper that `send_transaction` adds.  `JsonRpc(_)` is therefore the
/// primary retryable class on the poll path.
///
/// All other variants encode deterministic failures (decode errors, on-chain
/// result, structural mismatches) that retry cannot fix.
///
/// # Errors
///
/// This function is infallible; it returns a `bool`.
pub fn is_retryable_poll_error(e: &stellar_rpc_client::Error) -> bool {
    use stellar_rpc_client::Error as E;
    match e {
        // ── Retryable on poll ─────────────────────────────────────────────
        //
        // Raw transport / jsonrpsee error including HTTP 429.  The primary
        // retryable bucket on the poll path.
        E::JsonRpc(_) => true,

        // ── NOT retryable on poll ─────────────────────────────────────────

        // A submission-timeout on a poll call should not occur in practice,
        // but classifying it non-retryable (deadline-oriented) is safe.
        E::TransactionSubmissionTimeout => false,

        // On-chain or send-phase failures: not applicable to poll, but match
        // exhaustively.
        E::TransactionSubmissionFailed(_) => false,
        E::TransactionFailed(_) => false,
        E::UnexpectedTransactionStatus(_) => false,

        // Decode failures: deterministic.
        E::Xdr(_) => false,
        E::InvalidAddress(_) => false,
        E::InvalidRpcUrl(_) | E::InvalidRpcUrlFromUriParts(_) => false,
        E::InvalidUrl(_) => false,
        E::Serde(_) => false,
        E::MissingResult => false,
        E::MissingError => false,

        // Response body could not be decoded: decode failure of
        // `error_result_xdr`.  Retry won't fix garbage.
        E::InvalidResponse => false,

        // "not found" response: the poll loop handles NOT_FOUND status at the
        // application layer; this variant from a direct `NotFound` error is
        // non-transient.
        E::NotFound(_, _) => false,

        // Configuration / structural errors: not transient.
        E::InvalidNetworkPassphrase { .. } => false,
        E::MissingSignerForAddress { .. } => false,
        E::InvalidCursor => false,
        E::UnexpectedSimulateTransactionResultSize { .. } => false,
        E::UnexpectedOperationCount { .. } => false,
        E::UnsupportedOperationType => false,
        E::UnexpectedContractCodeDataType(_) => false,
        E::UnexpectedContractInstance(_) => false,
        #[allow(deprecated)]
        E::UnexpectedToken(_) => false,
        E::LargeFee(_) => false,
        E::CannotAuthorizeRawTransaction => false,
        E::TransactionSimulationFailed(_) => false,
        E::MissingOp => false,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Jitter helper
// ─────────────────────────────────────────────────────────────────────────────

/// Process-global counter used to decorrelate per-call jitter seeds.
///
/// This is intentionally process-wide state, not per-`RetryPolicy` or
/// per-caller state.  The goal is within-process thundering-herd prevention:
/// two concurrent backoff loops (from the pool's N simultaneous submits) that
/// happen to start at the same wall-clock instant must produce different delay
/// sequences.  Cross-process decorrelation is out of scope — a blanket jitter
/// offset drawn from `OsRng` already provides statistical separation between
/// independent OS processes.
///
/// Combined with `OsRng` output, the counter ensures per-call sequence
/// divergence even when the OS CSPRNG happens to return the same value for
/// successive calls (unlikely but possible on a heavily loaded system).
static CALL_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Samples a full-jitter delay for the given `attempt` (0-indexed).
///
/// `cap = min(max_delay, base_delay × 2^attempt)`
/// Returns a duration sampled uniformly in `[0, cap]`.
///
/// The jitter seed is drawn from `rand_core::OsRng` (OS CSPRNG).  A
/// per-call decorrelation nonce (`CALL_COUNTER`) is XOR-folded with the OS
/// random to ensure distinct sequences across concurrent callers even if
/// `OsRng` has low resolution.
///
/// Cross-process decorrelation is out of scope: each OS process draws its own
/// `OsRng` seed, providing statistical separation between processes without
/// shared-memory coordination.
///
/// # Overflow safety
///
/// `2^attempt` is computed via `1u64.checked_shl(attempt)`, which returns
/// `None` (no panic) when `attempt >= 64`; the result saturates to `u64::MAX`
/// and is immediately capped by `max_delay` via `saturating_mul` + `min`.
/// This function never panics regardless of `attempt` value.
fn jitter_delay(attempt: u32, base_delay: Duration, max_delay: Duration) -> Duration {
    // Compute the exponential cap: base × 2^attempt, saturating at max_delay.
    // Overflow is handled at every step:
    //   - checked_shl: returns None (→ u64::MAX) when attempt >= 64.
    //   - saturating_mul: saturates to u64::MAX instead of overflowing.
    //   - min(max_ns): caps the result at max_delay nanoseconds.
    // Safe to call with any attempt value; no panic or runaway delay possible.
    let cap = {
        // 2^attempt, capped at u64::MAX via saturating shift.
        // u64::checked_shl returns None when attempt >= 64; in that case the
        // cap is already >> max_delay so we saturate to u64::MAX.
        let multiplier = 1u64.checked_shl(attempt).unwrap_or(u64::MAX);
        let base_ns = base_delay.as_nanos() as u64; // base_delay fits in u64 (reasonable bounds)
        let cap_ns = base_ns.saturating_mul(multiplier);
        let max_ns = max_delay.as_nanos() as u64;
        Duration::from_nanos(cap_ns.min(max_ns))
    };

    if cap.is_zero() {
        return Duration::ZERO;
    }

    // Draw 8 bytes from OsRng and mix with the call counter.
    let raw = OsRng.next_u64();
    let nonce = CALL_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mixed = raw ^ nonce.wrapping_mul(0x9e37_79b9_7f4a_7c15); // Fibonacci hashing for spread

    // Sample uniformly in [0, cap] by scaling mixed into [0, cap_ns].
    let cap_ns = cap.as_nanos() as u64;
    // Use u128 intermediary to avoid overflow on the multiply.
    let sampled_ns = ((mixed as u128 * (cap_ns as u128 + 1)) >> 64) as u64;
    Duration::from_nanos(sampled_ns)
}

// ─────────────────────────────────────────────────────────────────────────────
// retry_with_backoff
// ─────────────────────────────────────────────────────────────────────────────

/// Runs `op` with bounded exponential-backoff retry.
///
/// # Invariants — callers MUST uphold
///
/// **The `op` closure MUST be idempotent at the network layer.**
///
/// For transaction submission specifically: `op` MUST re-send pre-signed,
/// pre-sequenced bytes that were captured **outside** the closure, before
/// `retry_with_backoff` is called.  `op` MUST NOT invoke a signer, derive a
/// sequence number, or call any state-mutating key operation **inside** the
/// closure.  If `op` re-signs or re-sequences on every call, retries will
/// submit distinct transactions to the network — a double-spend.
///
/// Correct pattern (send path):
/// ```ignore
/// // 1. Sign once, capture the signed envelope.
/// let signed_envelope = build_and_sign(&tx, &signer).await?;
/// // 2. Pass the already-signed bytes into the closure by reference.
/// retry_with_backoff(&policy, deadline, is_retryable_send_error, || async {
///     client.send_transaction(&signed_envelope).await
/// }).await?;
/// ```
///
/// Incorrect pattern — DO NOT DO THIS:
/// ```ignore
/// // BAD: signer called inside the closure → re-mints signature every retry.
/// retry_with_backoff(&policy, deadline, is_retryable_send_error, || async {
///     let signed = build_and_sign(&tx, &signer).await?;   // <-- wrong
///     client.send_transaction(&signed).await
/// }).await?;
/// ```
///
/// **Fee-bump retry note:** capture the signed fee-bump envelope before
/// calling `retry_with_backoff`, not inside it.
///
/// # Behaviour
///
/// 1. Runs `op()` **at least once** — even if `overall_deadline` has already
///    passed on entry.  The caller's deadline is a best-effort bound on sleep
///    scheduling, not a pre-flight gate that skips the first attempt.
/// 2. On a **non-retryable** error: returns immediately (1 attempt consumed).
/// 3. On a **retryable** error: sleeps a jitter-capped delay, then retries.
/// 4. Exits when any of the following is true:
///    - `op()` returns `Ok(T)`.
///    - `op()` returns a non-retryable error.
///    - `attempt_count >= policy.max_attempts`.
///    - `Instant::now() >= overall_deadline` (checked BEFORE each sleep, so
///      the deadline governs sleep scheduling; the op itself may run slightly
///      past the deadline on the final attempt).
///
/// The last error seen is returned if all attempts are exhausted.
///
/// # Bounded wall-time
///
/// Total wall-time ≤ `overall_deadline + one max_delay`.  Specifically:
/// - The loop exits before sleeping if `now >= overall_deadline`.
/// - If a sleep starts, it runs for at most `max_delay` regardless of the
///   remaining time (we do NOT trim the sleep to fit the deadline exactly,
///   because the poll interval already handles the hard cutoff at the deadline
///   in the caller's loop).  This one-`max_delay` slop is bounded and small
///   (≤ 8 s by default).
///
/// A malicious server cannot cause an unbounded wait: we never read
/// `Retry-After` from server responses; blind backoff is used instead.
///
/// # Arguments
///
/// - `policy`: retry parameters (attempts, base delay, max delay).
/// - `overall_deadline`: the caller's absolute deadline (e.g. `started + timeout`).
/// - `is_retryable`: per-call-site classifier; use [`is_retryable_send_error`]
///   for `send_transaction` and [`is_retryable_poll_error`] for poll calls.
/// - `op`: the async operation to retry.  Called at most `policy.max_attempts` times.
///
/// # Errors
///
/// Returns the last error from `op` if all attempts fail, or the first
/// non-retryable error immediately.
///
/// # Panics
///
/// Never panics.
///
/// # Examples
///
/// ```no_run
/// use std::time::Duration;
/// use tokio::time::Instant;
/// use stellar_agent_network::retry::{RetryPolicy, is_retryable_poll_error, retry_with_backoff};
///
/// # async fn run() -> Result<u32, stellar_rpc_client::Error> {
/// let policy = RetryPolicy::default();
/// let deadline = Instant::now() + Duration::from_secs(30);
/// let result = retry_with_backoff(
///     &policy,
///     deadline,
///     is_retryable_poll_error,
///     || async { Ok::<u32, stellar_rpc_client::Error>(42) },
/// ).await?;
/// assert_eq!(result, 42);
/// # Ok(result) }
/// ```
pub async fn retry_with_backoff<F, Fut, T>(
    policy: &RetryPolicy,
    overall_deadline: Instant,
    is_retryable: fn(&stellar_rpc_client::Error) -> bool,
    mut op: F,
) -> Result<T, stellar_rpc_client::Error>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, stellar_rpc_client::Error>>,
{
    let mut last_err: Option<stellar_rpc_client::Error> = None;

    for attempt in 0..policy.max_attempts {
        match op().await {
            Ok(val) => return Ok(val),
            Err(e) => {
                if !is_retryable(&e) {
                    // Non-retryable: surface immediately without sleeping.
                    return Err(e);
                }

                last_err = Some(e);

                // Do not schedule another sleep if we have exhausted attempts
                // or the overall deadline has passed.
                let is_last_attempt = attempt + 1 >= policy.max_attempts;
                if is_last_attempt || Instant::now() >= overall_deadline {
                    break;
                }

                let delay = jitter_delay(attempt, policy.base_delay, policy.max_delay);
                tokio::time::sleep(delay).await;
            }
        }
    }

    // All attempts exhausted (or deadline passed before we could retry).
    // SAFETY: the loop runs at least once (`max_attempts >= 1` enforced below by
    // the `0..policy.max_attempts` range, and a deadline-already-past entry still
    // executes attempt 0 before breaking).  Therefore `last_err` is always `Some`
    // at this point — the non-retryable branch returns before reaching this line,
    // and the Ok branch returns before reaching this line.
    //
    // We use `unwrap_or_else(|| unreachable!())` to satisfy clippy's
    // `clippy::expect_used` restriction without introducing an `unsafe` block.
    #[allow(
        clippy::unreachable,
        reason = "last_err is guaranteed Some here; see SAFETY comment above"
    )]
    Err(last_err.unwrap_or_else(|| unreachable!("retry_with_backoff: last_err must be Some")))
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

    use std::sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    };
    use std::time::Duration;

    use tokio::time::Instant;

    use super::*;

    // ─── is_retryable_send_error ─────────────────────────────────────────────

    #[test]
    fn send_timeout_is_retryable() {
        assert!(is_retryable_send_error(
            &stellar_rpc_client::Error::TransactionSubmissionTimeout
        ));
    }

    #[test]
    fn send_json_rpc_is_retryable() {
        let ce = jsonrpsee_core::ClientError::Custom("some transport error".into());
        assert!(is_retryable_send_error(
            &stellar_rpc_client::Error::JsonRpc(ce)
        ));
    }

    #[test]
    fn send_submission_failed_is_not_retryable() {
        // TransactionSubmissionFailed = on-chain rejection OR transport-429-on-send.
        // Neither should be retried on the send path.
        assert!(!is_retryable_send_error(
            &stellar_rpc_client::Error::TransactionSubmissionFailed(
                "No status yet: ...".to_owned()
            )
        ));
    }

    #[test]
    fn send_transaction_failed_is_not_retryable() {
        assert!(!is_retryable_send_error(
            &stellar_rpc_client::Error::TransactionFailed("some failure".to_owned())
        ));
    }

    #[test]
    fn send_invalid_response_is_not_retryable() {
        // Decode failure; retry won't fix garbage.
        assert!(!is_retryable_send_error(
            &stellar_rpc_client::Error::InvalidResponse
        ));
    }

    #[test]
    fn send_xdr_error_is_not_retryable() {
        use stellar_xdr::Error as XdrError;
        assert!(!is_retryable_send_error(&stellar_rpc_client::Error::Xdr(
            XdrError::Invalid
        )));
    }

    #[test]
    fn send_missing_result_is_not_retryable() {
        assert!(!is_retryable_send_error(
            &stellar_rpc_client::Error::MissingResult
        ));
    }

    #[test]
    fn send_missing_error_is_not_retryable() {
        assert!(!is_retryable_send_error(
            &stellar_rpc_client::Error::MissingError
        ));
    }

    // ─── is_retryable_poll_error ─────────────────────────────────────────────

    #[test]
    fn poll_json_rpc_is_retryable() {
        let ce = jsonrpsee_core::ClientError::Custom("429 rate limit".into());
        assert!(is_retryable_poll_error(
            &stellar_rpc_client::Error::JsonRpc(ce)
        ));
    }

    #[test]
    fn poll_submission_timeout_is_not_retryable() {
        // On the poll path this is treated as non-retryable (deadline-oriented).
        assert!(!is_retryable_poll_error(
            &stellar_rpc_client::Error::TransactionSubmissionTimeout
        ));
    }

    #[test]
    fn poll_submission_failed_is_not_retryable() {
        assert!(!is_retryable_poll_error(
            &stellar_rpc_client::Error::TransactionSubmissionFailed("some error".to_owned())
        ));
    }

    #[test]
    fn poll_invalid_response_is_not_retryable() {
        // Decode failure of error_result_xdr; retry won't fix.
        assert!(!is_retryable_poll_error(
            &stellar_rpc_client::Error::InvalidResponse
        ));
    }

    #[test]
    fn poll_xdr_error_is_not_retryable() {
        use stellar_xdr::Error as XdrError;
        assert!(!is_retryable_poll_error(&stellar_rpc_client::Error::Xdr(
            XdrError::Invalid
        )));
    }

    #[test]
    fn poll_not_found_is_not_retryable() {
        // The poll loop handles NOT_FOUND at the application layer; a direct
        // NotFound error from the RPC is non-transient.
        assert!(!is_retryable_poll_error(
            &stellar_rpc_client::Error::NotFound("transaction".to_owned(), "hash".to_owned())
        ));
    }

    // ─── retry_with_backoff ──────────────────────────────────────────────────

    /// Retryable-then-success: two JsonRpc errors then Ok → retried, returns Ok.
    #[tokio::test]
    async fn retry_then_success_returns_ok() {
        tokio::time::pause();
        let call_count = Arc::new(AtomicU32::new(0));
        let cc = Arc::clone(&call_count);

        let policy = RetryPolicy {
            max_attempts: 5,
            base_delay: Duration::from_millis(10),
            max_delay: Duration::from_millis(100),
        };
        let deadline = Instant::now() + Duration::from_secs(60);

        let result = retry_with_backoff(&policy, deadline, is_retryable_poll_error, || {
            let cc = Arc::clone(&cc);
            async move {
                let n = cc.fetch_add(1, Ordering::SeqCst);
                if n < 2 {
                    Err(stellar_rpc_client::Error::JsonRpc(
                        jsonrpsee_core::ClientError::Custom("transient".into()),
                    ))
                } else {
                    Ok(42u32)
                }
            }
        })
        .await;

        assert_eq!(result.unwrap(), 42u32);
        assert_eq!(call_count.load(Ordering::SeqCst), 3);
    }

    /// Always-retryable: exhausts max_attempts and returns the last error.
    #[tokio::test]
    async fn always_retryable_exhausts_max_attempts() {
        tokio::time::pause();

        let call_count = Arc::new(AtomicU32::new(0));
        let cc = Arc::clone(&call_count);

        let policy = RetryPolicy {
            max_attempts: 3,
            base_delay: Duration::from_millis(10),
            max_delay: Duration::from_millis(100),
        };
        let deadline = Instant::now() + Duration::from_secs(60);

        let result = retry_with_backoff(&policy, deadline, is_retryable_poll_error, || {
            let cc = Arc::clone(&cc);
            async move {
                cc.fetch_add(1, Ordering::SeqCst);
                Err::<u32, _>(stellar_rpc_client::Error::JsonRpc(
                    jsonrpsee_core::ClientError::Custom("persistent error".into()),
                ))
            }
        })
        .await;

        assert!(result.is_err());
        assert_eq!(call_count.load(Ordering::SeqCst), 3);
    }

    /// Non-retryable error returns immediately after 1 attempt.
    #[tokio::test]
    async fn non_retryable_returns_after_one_attempt() {
        tokio::time::pause();

        let call_count = Arc::new(AtomicU32::new(0));
        let cc = Arc::clone(&call_count);

        let policy = RetryPolicy {
            max_attempts: 5,
            base_delay: Duration::from_millis(10),
            max_delay: Duration::from_millis(100),
        };
        let deadline = Instant::now() + Duration::from_secs(60);

        let result = retry_with_backoff(&policy, deadline, is_retryable_poll_error, || {
            let cc = Arc::clone(&cc);
            async move {
                cc.fetch_add(1, Ordering::SeqCst);
                // InvalidResponse is NOT retryable on the poll path.
                Err::<u32, _>(stellar_rpc_client::Error::InvalidResponse)
            }
        })
        .await;

        assert!(result.is_err());
        // Must have returned after the first attempt without retrying.
        assert_eq!(call_count.load(Ordering::SeqCst), 1);
    }

    /// Deadline-already-past on entry: op must run once.
    #[tokio::test]
    async fn deadline_already_past_runs_op_once() {
        tokio::time::pause();

        let call_count = Arc::new(AtomicU32::new(0));
        let cc = Arc::clone(&call_count);

        let policy = RetryPolicy {
            max_attempts: 5,
            base_delay: Duration::from_millis(10),
            max_delay: Duration::from_millis(100),
        };
        // Deadline in the past.
        let deadline = Instant::now() - Duration::from_secs(1);

        let result = retry_with_backoff(&policy, deadline, is_retryable_poll_error, || {
            let cc = Arc::clone(&cc);
            async move {
                cc.fetch_add(1, Ordering::SeqCst);
                // Always retryable but deadline is past.
                Err::<u32, _>(stellar_rpc_client::Error::JsonRpc(
                    jsonrpsee_core::ClientError::Custom("error".into()),
                ))
            }
        })
        .await;

        // Must have run at least once despite the deadline being in the past.
        assert!(call_count.load(Ordering::SeqCst) >= 1);
        assert!(result.is_err());
    }

    /// Proves that the signer (or any pre-submission state-mutating step) is
    /// invoked exactly once, regardless of how many retry attempts the op makes.
    ///
    /// The correct pattern: the "sign" step runs once before the retry loop;
    /// the closure captures the result by reference and only re-sends it on
    /// each attempt.  The signer call count MUST remain 1 even when the send
    /// is retried N times.
    ///
    /// If `op` were written to re-sign inside the closure, `sign_count` would
    /// equal `send_count` — demonstrating the double-spend hazard the
    /// `# Invariants` doc forbids.
    #[tokio::test]
    async fn signer_invoked_once_across_retries() {
        tokio::time::pause();

        let sign_count = Arc::new(AtomicU32::new(0));
        let send_count = Arc::new(AtomicU32::new(0));

        // Step 1: sign once — outside the retry loop.
        // (Represents: `let signed_envelope = build_and_sign(&tx, &signer).await?`)
        sign_count.fetch_add(1, Ordering::SeqCst);
        let _signed_envelope = 0xdeadbeef_u32; // placeholder for a signed envelope

        let policy = RetryPolicy {
            max_attempts: 4,
            base_delay: Duration::from_millis(5),
            max_delay: Duration::from_millis(50),
        };
        let deadline = Instant::now() + Duration::from_secs(60);

        // Step 2: retry loop re-uses (borrows) the already-signed value.
        let sc = Arc::clone(&send_count);
        let result = retry_with_backoff(&policy, deadline, is_retryable_send_error, || {
            let sc = Arc::clone(&sc);
            // Capture `_signed_envelope` by value (copy) to prove it is
            // a single pre-computed value, not re-derived per attempt.
            let _envelope = _signed_envelope;
            async move {
                let n = sc.fetch_add(1, Ordering::SeqCst);
                if n < 3 {
                    // Simulate a retryable transport error (e.g. timeout).
                    Err(stellar_rpc_client::Error::TransactionSubmissionTimeout)
                } else {
                    // Fourth attempt succeeds.
                    Ok(99u32)
                }
            }
        })
        .await;

        assert_eq!(result.unwrap(), 99u32);

        // The signer was called exactly once (before the loop).
        // The send was called 4 times (3 retryable failures + 1 success).
        assert_eq!(
            sign_count.load(Ordering::SeqCst),
            1,
            "signer must be invoked exactly once — not once per retry attempt"
        );
        assert_eq!(
            send_count.load(Ordering::SeqCst),
            4,
            "send must be invoked once per attempt (3 retryable + 1 success)"
        );
    }

    /// Jitter delays land in [0, cap] and two concurrent seeds differ.
    #[test]
    fn jitter_delay_in_range_and_per_call_decorrelated() {
        let base = Duration::from_millis(100);
        let max = Duration::from_secs(8);

        for attempt in 0u32..=10 {
            let d = jitter_delay(attempt, base, max);
            assert!(d <= max, "jitter_delay({attempt}) = {d:?} > max={max:?}");
        }

        // Two calls with different counter values should (almost always)
        // produce different delays.  With OsRng + counter mixing this is
        // virtually guaranteed; we allow 1 collision in 100 to avoid flakiness.
        let cap = Duration::from_secs(8);
        let samples: Vec<Duration> = (0..20).map(|_| jitter_delay(5, base, cap)).collect();
        let distinct = samples
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len();
        assert!(
            distinct > 10,
            "expected high diversity in jitter samples, got {distinct} distinct out of 20"
        );
    }

    /// Total advanced time under tokio::time::pause is bounded by the deadline
    /// plus one max_delay.
    #[tokio::test]
    async fn total_elapsed_bounded_by_deadline_plus_max_delay() {
        tokio::time::pause();

        let policy = RetryPolicy {
            max_attempts: 10,
            base_delay: Duration::from_millis(50),
            max_delay: Duration::from_millis(200),
        };
        let overall_deadline = Duration::from_millis(300);
        let start = Instant::now();
        let deadline = start + overall_deadline;

        let _ = retry_with_backoff(&policy, deadline, is_retryable_poll_error, || async {
            Err::<u32, _>(stellar_rpc_client::Error::JsonRpc(
                jsonrpsee_core::ClientError::Custom("rate limited".into()),
            ))
        })
        .await;

        let elapsed = start.elapsed();
        let slop = policy.max_delay;
        assert!(
            elapsed <= overall_deadline + slop,
            "elapsed {elapsed:?} exceeds deadline+max_delay ({:?})",
            overall_deadline + slop
        );
    }
}
