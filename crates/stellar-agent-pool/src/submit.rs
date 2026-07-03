//! Concurrent pooled-submission orchestration.
//!
//! [`submit_pooled`] is the single public entry point for submitting a classic
//! Stellar transaction via a channel from the pool.  It:
//!
//! 1. Calls [`allocator::acquire`] to obtain a [`crate::pool::ChannelLease`] (or
//!    returns [`PoolError::PoolExhausted`] IMMEDIATELY — no queuing).
//! 2. Re-derives the channel signing key from the pool master seed (caller reads
//!    the seed ONCE per batch and passes the same seed for all concurrent calls;
//!    never re-reads the keyring per submission).
//! 3. Applies a caller-supplied closure to a fresh [`ClassicOpBuilder`] whose
//!    source account and sequence number come from the lease.
//! 4. Calls `build_and_sign` with the derived signer and submits the result via
//!    `submit_transaction_and_wait`.
//! 5. Calls [`allocator::release`] with the terminal outcome.
//!
//! # Sequence-number contract
//!
//! [`crate::pool::ChannelLease::sequence_number`] returns the channel's CURRENT on-chain
//! account sequence.  [`ClassicOpBuilder::new`] accepts this value AS-IS;
//! `stellar-baselib`'s `TransactionBuilder::build` auto-increments internally
//! to produce a tx `seq_num = current_seq + 1`.
//!
//! Passing `lease.sequence_number() + 1` to [`ClassicOpBuilder::new`] would
//! produce `current_seq + 2` in the envelope and cause `tx_bad_seq`.
//! This is locked by the regression test
//! `builder.rs::builder_envelope_seq_num_is_caller_seq_plus_one`.
//!
//! # Lock discipline
//!
//! The pool lock is taken only inside [`allocator::acquire`] and
//! [`allocator::release`].  The `.await` for signing and submission is entirely
//! lock-free.  No `std::sync::MutexGuard` crosses an `.await` point.
//!
//! # Secret lifecycle
//!
//! The pool master seed is a `Zeroizing<[u8; 64]>` argument that the caller
//! reads ONCE from the keyring (via [`crate::derive::load_pool_master_seed_from_keyring`])
//! and passes by reference into every concurrent `submit_pooled` call.  Inside,
//! the channel signing key is derived into a temporary `SoftwareSigningKey`
//! that is dropped after `build_and_sign` returns — before the submit `.await`.

use std::time::Duration;

use stellar_agent_core::observability::redact_strkey_first5_last5;
use stellar_agent_network::{
    ClassicOpBuilder, StellarRpcClient, submit::SubmissionResult, submit_transaction_and_wait,
};
use zeroize::Zeroizing;

use crate::allocator;
use crate::derive::derive_channel_signer;
use crate::error::PoolError;
use crate::pool::{ChannelPool, TerminalOutcome};

/// A typed result from [`submit_pooled`] carrying either the on-chain
/// confirmation or the error that caused the submission to fail.
///
/// Both fields in the success arm are public; there are no secret bytes.
#[derive(Debug)]
#[non_exhaustive]
pub struct PoolSubmitResult {
    /// The channel BIP-44 derivation index used for this submission.
    pub channel_index: u32,
    /// The terminal outcome reported to the pool allocator.
    pub outcome: TerminalOutcome,
    /// On success, the on-chain confirmation from `submit_transaction_and_wait`.
    pub submission: Option<SubmissionResult>,
}

/// Submits a classic transaction through a pooled channel account.
///
/// The caller supplies:
///
/// - `pool`: the [`ChannelPool`] (typically `Arc<ChannelPool>` shared across tasks).
/// - `client`: an RPC client pointing at the target network.
/// - `seed`: the 64-byte pool master BIP-39 seed, read ONCE per concurrent batch
///   via [`crate::derive::load_pool_master_seed_from_keyring`] and shared by
///   reference across all concurrent calls (avoids a keyring round-trip per
///   submission).
/// - `network_passphrase`: the Stellar network passphrase string.
/// - `fee_per_op`: the per-operation fee in stroops.
/// - `timeout`: how long to poll for on-chain confirmation.
/// - `build_ops`: a synchronous, infallible closure that receives a mutable
///   reference to a freshly-constructed [`ClassicOpBuilder`] and adds operations
///   to it.  The builder is pre-configured with the channel's public key and
///   current sequence number as the source.
///
/// # Concurrency guarantee
///
/// `submit_pooled` returns [`PoolError::PoolExhausted`] IMMEDIATELY when all
/// channels are in-flight.  It never queues or blocks waiting for a free channel.
/// Each concurrent call owns a distinct [`crate::pool::ChannelLease`] for the
/// entire acquire → sign → submit → release window.
///
/// # Sequence-number contract
///
/// The sequence number passed to [`ClassicOpBuilder::new`] is
/// `lease.sequence_number()` AS-IS.  Do NOT add 1.  The builder's internal
/// `Account::increment_sequence_number` (stellar-baselib `transaction_builder`)
/// bumps it to `current_seq + 1` in the envelope.
///
/// # Lock discipline
///
/// The pool lock is taken and released inside [`allocator::acquire`] (before the
/// first `.await`) and inside [`allocator::release`] (after the last `.await`).
/// No lock guard crosses an `.await` boundary.
///
/// # Errors
///
/// - [`PoolError::PoolExhausted`] — all channels in-flight; call returned immediately.
/// - [`PoolError::NotInitialised`] — the pool has no channels.
/// - [`PoolError::DeriveFailed`] — channel key derivation failed.
/// - [`PoolError::Wallet`] — signing or submission failed; the channel is
///   released with [`TerminalOutcome::Failed`] or [`TerminalOutcome::TxBadSeq`].
/// - [`PoolError::SequenceFetchFailed`] — `tx_bad_seq` re-fetch failed on release.
///
/// # Panics
///
/// Never panics.
///
/// # Examples
///
/// ```no_run
/// use std::{sync::Arc, time::Duration};
///
/// use stellar_agent_core::StellarAmount;
/// use stellar_agent_network::builder::{Asset, ClassicOpBuilder};
/// use stellar_agent_network::StellarRpcClient;
/// use stellar_agent_pool::{ChannelPool, ChannelRecord};
/// use stellar_agent_pool::submit::submit_pooled;
/// use zeroize::Zeroizing;
///
/// # async fn run() -> Result<(), stellar_agent_pool::PoolError> {
/// let channels = vec![ChannelRecord::new(1, "GABC...XYZ")];
/// let pool = Arc::new(ChannelPool::from_records(channels, vec![100]).unwrap());
/// let client = StellarRpcClient::new("https://soroban-testnet.stellar.org").unwrap();
/// let seed = Zeroizing::new([0u8; 64]); // in production: from keyring
///
/// let result = submit_pooled(
///     &pool,
///     &client,
///     &seed,
///     "Test SDF Network ; September 2015",
///     100,
///     Duration::from_secs(60),
///     |builder| {
///         let _ = builder.payment(
///             "GDST...DST",
///             StellarAmount::from_stroops(1_000_000),
///             &Asset::Native,
///         );
///     },
/// ).await?;
/// println!("channel_index={}, outcome={:?}", result.channel_index, result.outcome);
/// # Ok(())
/// # }
/// ```
pub async fn submit_pooled<F>(
    pool: &ChannelPool,
    client: &StellarRpcClient,
    seed: &Zeroizing<[u8; 64]>,
    network_passphrase: &str,
    fee_per_op: u32,
    timeout: Duration,
    build_ops: F,
) -> Result<PoolSubmitResult, PoolError>
where
    // The closure is synchronous: no .await inside it.  The closure takes a
    // mutable reference to the builder and adds operations to it.  Errors from
    // ops are ignored here — if no ops are added, build_and_sign returns an
    // Internal error which maps to PoolError::Wallet.
    F: FnOnce(&mut ClassicOpBuilder),
{
    // ── Step 1: acquire a free channel ──────────────────────────────────────
    // Lock taken and dropped inside acquire(); returns ChannelLease by value.
    // No lock is held after this call returns.
    let lease = allocator::acquire(pool, None, "")?;
    let channel_index = lease.index();
    let public_key = lease.public_key().to_owned();

    tracing::debug!(
        channel = %redact_strkey_first5_last5(&public_key),
        index = channel_index,
        seq = lease.sequence_number(),
        "submit_pooled: channel acquired"
    );

    // ── Step 2: re-derive the channel signing key ────────────────────────────
    // derive_channel_signer takes ownership of a CLONE of the seed (so the
    // caller's seed remains alive for subsequent concurrent calls).
    // The Zeroizing<[u8; 64]> clone ensures the copy is zeroed when it enters
    // derive_channel_signer and is dropped.
    let seed_copy: Zeroizing<[u8; 64]> = Zeroizing::new(**seed);
    let signer = match derive_channel_signer(seed_copy, channel_index) {
        Ok(s) => s,
        Err(e) => {
            // Derivation failed: sync release (no network, no TxBadSeq possible).
            // Use pool.release directly — allocator::release async re-fetch is
            // not needed here because the transaction was never submitted.
            pool.release(lease, TerminalOutcome::Failed, None);
            tracing::warn!(
                channel = %redact_strkey_first5_last5(&public_key),
                index = channel_index,
                error = %e,
                "submit_pooled: channel key derivation failed; released with Failed"
            );
            return Err(e);
        }
    };

    // ── Step 3: build the transaction ───────────────────────────────────────
    // Sequence number contract: pass lease.sequence_number() AS-IS.
    // ClassicOpBuilder::new stores the current seq; stellar-baselib's
    // TransactionBuilder::build auto-increments to current_seq + 1.
    // (Regression test: builder.rs::builder_envelope_seq_num_is_caller_seq_plus_one)
    let mut builder = ClassicOpBuilder::new(
        public_key.as_str(),
        lease.sequence_number(), // do NOT add 1 here — builder does it internally
        network_passphrase,
        fee_per_op,
    );
    build_ops(&mut builder);

    // ── Step 4: sign and submit ──────────────────────────────────────────────
    // build_and_sign is async; the lock is NOT held here (released in step 1).
    let signed_xdr = match builder.build_and_sign(&signer).await {
        Ok(xdr) => xdr,
        Err(e) => {
            // Build/sign failed: sync release (no network, no TxBadSeq possible).
            // Transaction never reached the network; sequence slot not consumed.
            pool.release(lease, TerminalOutcome::Failed, None);
            tracing::warn!(
                channel = %redact_strkey_first5_last5(&public_key),
                index = channel_index,
                "submit_pooled: build_and_sign failed; released with Failed"
            );
            return Err(PoolError::Wallet(e));
        }
    };

    // Signer is dropped here — secret zeroed before submit .await.
    drop(signer);

    let submission_result =
        submit_transaction_and_wait(client, &signed_xdr, timeout, network_passphrase, None).await;

    // ── Step 5: map outcome and release ─────────────────────────────────────
    match submission_result {
        Ok(sr) => {
            let tx_hash_redacted = stellar_agent_network::submit::redact_tx_hash(&sr.tx_hash);
            tracing::info!(
                channel = %redact_strkey_first5_last5(&public_key),
                index = channel_index,
                tx_hash = %tx_hash_redacted,
                ledger = sr.ledger,
                "submit_pooled: confirmed"
            );
            // release is async (may trigger re-fetch on tx_bad_seq).
            allocator::release(
                pool,
                client,
                lease,
                TerminalOutcome::Success,
                None,
                None,
                "",
            )
            .await?;
            Ok(PoolSubmitResult {
                channel_index,
                outcome: TerminalOutcome::Success,
                submission: Some(sr),
            })
        }

        Err(e) if is_tx_bad_seq(&e) => {
            tracing::warn!(
                channel = %redact_strkey_first5_last5(&public_key),
                index = channel_index,
                "submit_pooled: tx_bad_seq; will re-fetch sequence on release"
            );
            // TxBadSeq: pass no fresh_sequence; allocator::release will re-fetch.
            allocator::release(
                pool,
                client,
                lease,
                TerminalOutcome::TxBadSeq,
                None,
                None,
                "",
            )
            .await?;
            Err(PoolError::Wallet(e))
        }

        Err(e) => {
            tracing::warn!(
                channel = %redact_strkey_first5_last5(&public_key),
                index = channel_index,
                "submit_pooled: submission failed; released with Failed"
            );
            // Failed: sequence not consumed, return channel as-is.
            allocator::release(pool, client, lease, TerminalOutcome::Failed, None, None, "")
                .await?;
            Err(PoolError::Wallet(e))
        }
    }
}

/// Returns `true` if the [`stellar_agent_core::WalletError`] represents a
/// `tx_bad_seq` ledger rejection.
///
/// # Detection strategy
///
/// **Primary (typed):** `stellar_agent_network::submit::map_failed_result` maps
/// stellar-xdr `TransactionResultResult::TxBadSeq`
/// to `WalletError::Submission(SubmissionError::SequenceNumberStale)` with code
/// `"submission.sequence_number_stale"`.  This is the stable, wording-independent
/// match that fires when the network surfaces `tx_bad_seq` through the
/// `getTransaction FAILED` path.
///
/// **Fallback (substring):** Some RPC versions or error paths surface `tx_bad_seq`
/// via `WalletError::Submission(SubmissionError::TxMalformed { detail })` (the
/// `sendTransaction ERROR` path).  The fallback checks the lowercased Display
/// string for `"tx_bad_seq"` / `"txbadseq"` as a defence-in-depth second layer.
///
/// # Concurrency-guarantee crux
///
/// If a real `tx_bad_seq` falls through to the `Failed` arm, the channel's
/// cached sequence is NOT corrected and the next submission will repeat the
/// error.  This function must be conservative (prefer false positive over false
/// negative).
fn is_tx_bad_seq(e: &stellar_agent_core::WalletError) -> bool {
    use stellar_agent_core::WalletError;
    use stellar_agent_core::error::SubmissionError;

    // Primary typed match: SequenceNumberStale is the stable code emitted by
    // map_failed_result for TransactionResultResult::TxBadSeq.
    if matches!(
        e,
        WalletError::Submission(SubmissionError::SequenceNumberStale)
    ) {
        return true;
    }

    // Fallback substring: catches sendTransaction ERROR path where the RPC
    // returns a TxBadSeq detail string inside TxMalformed.
    let code = e.code();
    let msg = e.to_string().to_lowercase();
    (code.starts_with("submission.") || code.starts_with("ledger."))
        && (msg.contains("tx_bad_seq") || msg.contains("txbadseq"))
}

#[cfg(test)]
mod tests {
    use stellar_agent_core::WalletError;
    use stellar_agent_core::error::SubmissionError;

    use super::is_tx_bad_seq;

    /// `SubmissionError::SequenceNumberStale` returns `true` — the typed primary arm.
    #[test]
    fn is_tx_bad_seq_sequence_number_stale_returns_true() {
        let e = WalletError::Submission(SubmissionError::SequenceNumberStale);
        assert!(
            is_tx_bad_seq(&e),
            "SequenceNumberStale must be recognised as tx_bad_seq by the typed arm"
        );
    }

    /// `SubmissionError::TxMalformed` with `"tx_bad_seq"` in the detail returns
    /// `true` — the fallback substring arm.
    ///
    /// This arm handles the `sendTransaction ERROR` path where the RPC embeds the
    /// ledger error string inside `TxMalformed.detail` rather than returning a
    /// `FAILED` result XDR with `TxBadSeq` discriminant.
    #[test]
    fn is_tx_bad_seq_fallback_substring_malformed_detail_returns_true() {
        let e = WalletError::Submission(SubmissionError::TxMalformed {
            detail: "sendTransaction ERROR: tx_bad_seq from RPC".to_owned(),
        });
        assert!(
            is_tx_bad_seq(&e),
            "TxMalformed with 'tx_bad_seq' in detail must be recognised by the fallback arm"
        );
    }

    /// An unrelated error returns `false` — no false positives.
    #[test]
    fn is_tx_bad_seq_unrelated_error_returns_false() {
        use stellar_agent_core::error::NetworkError;
        let e = WalletError::Network(NetworkError::RpcUnreachable {
            url: "redacted".to_owned(),
            reason: "timeout".to_owned(),
        });
        assert!(
            !is_tx_bad_seq(&e),
            "RpcUnreachable must not be treated as tx_bad_seq"
        );
    }
}
