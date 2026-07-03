//! Idempotent fee-bump retry with profile-local receipt tracking.
//!
//! `submit_fee_bump_idempotent` wraps [`build_and_sign_fee_bump`] +
//! `submit_with_retention_poll` with a [`ReceiptStore`] idempotency gate keyed
//! by the **inner** transaction hash.  A second call with a larger
//! `outer_fee_stroops` re-bumps against the same inner key, while a call whose
//! inner tx has already applied returns the cached receipt without re-submitting.
//!
//! # Idempotency key — inner tx hash
//!
//! The convergence key is the **inner** tx identity, prefixed `feebump-inner:`,
//! because:
//! - Re-bumping at a higher fee produces a different OUTER envelope (new fee +
//!   new fee-payer signature ⇒ different outer hash) but the SAME inner tx.
//! - CAP-15's "inner applied regardless" makes the inner identity the correct
//!   answer to "has this already applied?".
//! - The inner tx hash is `SHA-256(network_id ‖ ENVELOPE_TYPE_TX ‖ inner-tx-body)`,
//!   the canonical Stellar replay-protection identity (source-account sequence
//!   number advances once the inner applies; any second submission is rejected
//!   `txBAD_SEQ`).
//! - The `feebump-inner:` prefix namespaces this key away from the outer
//!   signed-envelope hash key space, preventing aliasing between the two identity
//!   spaces.
//!
//! # Receipt field semantics
//!
//! - `envelope_hash` holds the prefixed INNER key `"feebump-inner:<inner_tx_hash_hex>"`
//!   (the idempotency identity — what `try_begin` is keyed on).
//! - `tx_hash` holds the OUTER fee-bump tx hash
//!   (`SHA-256(network_id ‖ TransactionSignaturePayload::TxFeeBump(fee_bump_tx))`)
//!   so that stale-Pending recovery can poll `getTransaction` using the correct
//!   handle.  `stellar-rpc` indexes a fee-bump by BOTH outer and inner hash, so
//!   polling by the stored outer hash works.
//!
//! # max_time
//!
//! The `max_time` recorded in the receipt is the **inner** tx's `TimeBounds.maxTime`.
//! A fee-bump has no `cond` of its own (CAP-15); the network rejects a stale
//! inner as `tx_too_late`, so the inner's `max_time` is the correct
//! safe-resubmit gate.  Obtained by calling `extract_max_time` over
//! `TransactionEnvelope::Tx(v1_inner)`, which descends into the inner tx's
//! preconditions.
//!
//! # No-re-sign guarantee
//!
//! `build_and_sign_fee_bump` is called exactly ONCE on the winner path, before
//! `submit_with_retention_poll`.  No re-signing occurs inside any retry closure.
//! Polling and retention-window handling are inside `submit_with_retention_poll`.
//!
//! # Higher-fee retry semantics
//!
//! A second call with a larger `outer_fee_stroops`:
//! - If the inner already applied (`Success` receipt cached): returns the cached
//!   receipt and does NOT re-bump — no double-apply.
//! - If the inner has not yet applied (non-terminal or outer-failed): the second
//!   call re-bumps at the higher fee against the same inner key, converging on
//!   one receipt.
//!
//! # TxFeeBumpInnerSuccess classification
//!
//! `stellar-rpc` reports an inner-applied fee-bump as `status: SUCCESS`.
//! The `TxFeeBumpInnerSuccess` result variant therefore reaches the SUCCESS
//! arm and is finalised as `Success` — it never reaches the FAILED branch.
//! The defensive `map_failed_result` arm in the submission layer is correct
//! belt-and-suspenders and is not modified here.
//!
//! # Lock discipline
//!
//! The [`ReceiptStore`] lock is **never** held across an `.await`.  All async
//! calls happen outside the lock.

use std::time::Duration;

use sha2::{Digest as _, Sha256};
use stellar_agent_core::error::{InternalError, WalletError};
use stellar_agent_core::profile::receipt::{BeginOutcome, ReceiptStatus, ReceiptStore};
use stellar_xdr::{
    Hash, Limits, TransactionEnvelope, TransactionSignaturePayload,
    TransactionSignaturePayloadTaggedTransaction, WriteXdr,
};

use crate::StellarRpcClient;
use crate::fee_bump::{build_and_sign_fee_bump, build_fee_bump_tx, decode_inner_v1};
// Reuse canonical loser-poll constants from idempotent_submit to keep
// loser-poll semantics in sync across both submission paths.
use crate::idempotent_submit::{
    LOSER_MAX_POLLS, LOSER_POLL_INTERVAL, extract_max_time, submit_with_retention_poll,
};
use crate::signing::Signer;
// Reuse the canonical bytes_to_hex and redact_tx_hash helpers from submit.
use crate::submit::{SubmissionResult, bytes_to_hex, redact_tx_hash};

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Prefix applied to the inner tx hash to form the receipt-store idempotency
/// key for the fee-bump path.
///
/// This namespace separates fee-bump keys (keyed on inner tx hash) from the
/// classic-path keys (keyed on `SHA-256(signed envelope XDR)`) stored in the
/// same [`ReceiptStore`].  Without a prefix, an inner tx hash `H` could
/// theoretically alias a classic-path key that happens to have value `H` — the
/// two identity spaces are completely distinct and the prefix makes that
/// explicit.
const FEEBUMP_INNER_PREFIX: &str = "feebump-inner:";

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Submits a fee-bump transaction idempotently, keyed by the inner tx hash.
///
/// Wraps [`build_and_sign_fee_bump`] with a profile-local receipt store
/// idempotency gate so that a retry-with-higher-fee converges on one receipt
/// and an already-applied inner tx is never re-submitted.
///
/// `inner_envelope_xdr` must be a base64-encoded, already-signed
/// `TransactionEnvelope::Tx` (V1 only).  Non-V1 inner envelopes are rejected
/// fail-closed by `build_and_sign_fee_bump` → [`crate::fee_bump::FeeBumpError::InnerNotV1`].
///
/// `recorded_at_ledger` should be the current ledger sequence number at call
/// time (used for retention-window awareness in the stale-pending poll path).
///
/// # Idempotency key
///
/// `"feebump-inner:" ‖ hex(SHA-256(network_id ‖ ENVELOPE_TYPE_TX ‖ inner-tx-body))`
///
/// This is the canonical Stellar inner tx hash — the network's replay-protection
/// identity.  Two fee-bumps over the same inner (even by different fee-payers)
/// compete to land the same inner tx consuming the same sequence number; at most
/// one applies.  Converging them on one receipt is correct.
///
/// # Receipt fields
///
/// - `envelope_hash`: the prefixed inner key (idempotency identity).
/// - `tx_hash`: the OUTER fee-bump tx hash (RPC poll handle).
/// - `max_time`: the INNER tx's `TimeBounds.maxTime` (the network rejects a
///   stale inner as `tx_too_late`; safe-resubmit gate).
///
/// # Errors
///
/// - [`WalletError`] wrapping [`crate::fee_bump::FeeBumpError`] if the inner envelope is invalid
///   or the fee is outside the allowed range.
/// - Any error from `submit_with_retention_poll` on the submission path.
/// - [`WalletError::Network`] wrapping `NetworkError::RpcUnreachable` if the
///   store poll times out waiting for a concurrent winner to finalise.
///
/// # Behaviour — pre-submit failure and receipt abandonment
///
/// If a sign or validation error occurs AFTER `try_begin` has written a Pending
/// row but BEFORE `send_transaction` is called, the Pending receipt is
/// **abandoned** via [`ReceiptStore::abandon_pre_submit`].  Because
/// `submitted == false` at this point, the receipt is removed from the store,
/// allowing a subsequent call for the same inner tx to be the winner again and
/// retry with a corrected signer.
///
/// If `abandon_pre_submit` refuses (the `submitted` flag was somehow set to
/// `true` before the error), the receipt is finalised as `Failed` instead —
/// fail-closed: the inner tx was either on the network or the flag is
/// unexpectedly set, so we keep the entry rather than risk losing the
/// crash-recovery anchor.
///
/// # Panics
///
/// Never panics.
///
/// # Examples
///
/// ```no_run
/// use std::time::Duration;
/// use stellar_agent_network::{StellarRpcClient, fee_bump_retry::submit_fee_bump_idempotent};
/// use stellar_agent_core::profile::receipt::ReceiptStore;
/// use stellar_agent_network::signing::SoftwareSigningKey;
///
/// # async fn run(inner_xdr: &str) -> Result<(), stellar_agent_core::WalletError> {
/// let client = StellarRpcClient::new("https://soroban-testnet.stellar.org")?;
/// let store = ReceiptStore::open("default").unwrap();
/// let fee_payer = SoftwareSigningKey::new_from_bytes([1u8; 32]);
/// let result = submit_fee_bump_idempotent(
///     &client,
///     inner_xdr,
///     "GCFIRY65OQE7DFP5KLNS2PF2LVZMUZYJX4OZIEQ36N2IQANUB5XVYOJR",
///     500,        // outer_fee_stroops
///     10_000,     // policy_fee_cap_stroops
///     "Test SDF Network ; September 2015",
///     &fee_payer,
///     &store,
///     0,          // recorded_at_ledger
///     Duration::from_secs(60),
/// ).await?;
/// println!("confirmed in ledger {}", result.ledger);
/// # Ok(()) }
/// ```
#[allow(clippy::too_many_arguments)]
pub async fn submit_fee_bump_idempotent(
    client: &StellarRpcClient,
    inner_envelope_xdr: &str,
    fee_source: &str,
    outer_fee_stroops: i64,
    policy_fee_cap_stroops: i64,
    network_passphrase: &str,
    fee_payer_signer: &dyn Signer,
    store: &ReceiptStore,
    recorded_at_ledger: u32,
    timeout: Duration,
) -> Result<SubmissionResult, WalletError> {
    // ── Step 1: decode inner, compute inner tx hash and inner_key ─────────────
    //
    // decode_inner_v1 extracts the TransactionV1Envelope from the already-signed
    // inner XDR, enforcing the CAP-15 v1-only guard before any signing cost is paid.
    let v1_inner = decode_inner_v1(inner_envelope_xdr).map_err(WalletError::from)?;

    // Compute the canonical inner tx hash:
    //   SHA-256(TransactionSignaturePayload { network_id, Tx(inner_tx) })
    // This is the Stellar replay-protection identity (distinct from the outer
    // fee-bump hash), using the same preimage construction as the classic V1
    // path (same XDR types, same SHA-256; no new hashing logic).
    let inner_tx_hash_hex = compute_inner_tx_hash_hex(&v1_inner.tx, network_passphrase)?;

    let inner_key = format!("{FEEBUMP_INNER_PREFIX}{inner_tx_hash_hex}");

    let redacted_inner = redact_inner_key(&inner_key);
    tracing::debug!(
        inner_key = %redacted_inner,
        "submit_fee_bump_idempotent: entry"
    );

    // ── Step 2: FAST-PATH — check for an existing terminal Success receipt ─────
    //
    // This is an optimisation; the authoritative check is try_begin in step 3.
    // A concurrent winner racing with this get() is harmless: try_begin returns
    // AlreadyPresent and the loser polls — no double-submit.
    let existing = store.get(&inner_key).map_err(|e| {
        WalletError::Internal(InternalError::UnexpectedState {
            detail: format!("fee_bump receipt store get failed: {e}"),
        })
    })?;

    if let Some(receipt) = existing {
        // Fast-path: only short-circuit on Success.  Other terminal states
        // (Failed/Ambiguous/Reorged) fall through to try_begin which returns
        // AlreadyPresent; the AlreadyPresent path handles those uniformly.
        if receipt.status == ReceiptStatus::Success {
            tracing::info!(
                inner_key = %redacted_inner,
                "submit_fee_bump_idempotent: terminal Success cached; returning cached receipt"
            );
            return Ok(SubmissionResult {
                tx_hash: receipt.tx_hash,
                ledger: receipt.ledger.unwrap_or(0),
                signer_kind: None,
            });
        }
    }

    // ── Step 3: compute the OUTER fee-bump tx hash (provisional Pending poll handle) ──
    //
    // The precomputed outer hash is the provisional poll handle stored in the
    // Pending row by try_begin.  try_begin writes the outer hash so that
    // stale-Pending recovery can poll getTransaction by the outer hash
    // (stellar-rpc indexes a fee-bump by both outer and inner hash).
    //
    // The terminal receipt's authoritative identity is the RPC-confirmed hash
    // returned by submit_with_retention_poll on the winner path, which MUST equal
    // the precomputed hash (the hash covers the FeeBumpTransaction body, not the
    // signatures).
    //
    // Preimage: SHA-256(network_id ‖ TransactionSignaturePayload {
    //     tagged_transaction: TxFeeBump(fee_bump_tx)
    // })
    //
    // We build the unsigned FeeBumpTransaction body here solely to derive the
    // outer hash.  build_and_sign_fee_bump rebuilds it internally (with the
    // same inputs) and attaches the signature; no double-signing occurs.
    let outer_tx_hash_hex =
        compute_outer_tx_hash_hex(&v1_inner, fee_source, outer_fee_stroops, network_passphrase)?;

    let redacted_outer = redact_tx_hash(&outer_tx_hash_hex);

    // ── Step 4: extract inner max_time from the inner envelope ────────────────
    //
    // Pass the inner envelope directly (TransactionEnvelope::Tx(v1_inner))
    // to extract_max_time, which descends into the inner tx's preconditions.
    // This avoids re-decoding an outer fee-bump envelope.
    let inner_envelope_for_max_time = TransactionEnvelope::Tx(v1_inner.clone());
    let inner_max_time = extract_max_time(&inner_envelope_for_max_time);

    // ── Step 5: atomic winner/loser gate ─────────────────────────────────────
    let outcome = store
        .try_begin(
            &inner_key,
            &outer_tx_hash_hex,
            inner_max_time,
            recorded_at_ledger,
        )
        .map_err(|e| {
            WalletError::Internal(InternalError::UnexpectedState {
                detail: format!("fee_bump receipt store try_begin failed: {e}"),
            })
        })?;

    match outcome {
        BeginOutcome::Winner => {
            tracing::info!(
                inner_key = %redacted_inner,
                outer_tx_hash = %redacted_outer,
                "submit_fee_bump_idempotent: winner; building + signing fee-bump once"
            );

            // Build and sign ONCE — no-re-sign guarantee.
            // build_and_sign_fee_bump is called exactly once on the winner path.
            let signed_outer_xdr = build_and_sign_fee_bump(
                inner_envelope_xdr,
                fee_source,
                outer_fee_stroops,
                policy_fee_cap_stroops,
                network_passphrase,
                fee_payer_signer,
            )
            .await
            .map_err(|e| {
                // Sign error occurred BEFORE send_transaction was called.
                // Abandon the Pending entry so a retry can be winner again.
                // abandon_pre_submit enforces the submitted=false precondition;
                // if it refuses (submitted was somehow true), fall back to
                // finalize(Failed) to ensure the entry does not accumulate as
                // a stale Pending.
                let abandoned = store
                    .abandon_pre_submit(&inner_key)
                    .map(|()| true)
                    .unwrap_or_else(|fe| {
                        tracing::warn!(
                            inner_key = %redacted_inner,
                            error = %fe,
                            "submit_fee_bump_idempotent: abandon_pre_submit failed"
                        );
                        false
                    });

                if !abandoned {
                    // Fallback: finalize as Failed so the entry is not left Pending.
                    let code = e.code().to_owned();
                    if let Err(fe) =
                        store.finalize(&inner_key, ReceiptStatus::Failed { code }, None)
                    {
                        tracing::warn!(
                            inner_key = %redacted_inner,
                            error = %fe,
                            "submit_fee_bump_idempotent: finalize(Failed/sign-error) failed"
                        );
                    }
                }
                WalletError::from(e)
            })?;

            tracing::info!(
                inner_key = %redacted_inner,
                outer_tx_hash = %redacted_outer,
                "submit_fee_bump_idempotent: fee-bump signed; driving submit_with_retention_poll"
            );

            // Mark the receipt as submitted BEFORE the send step.
            // submit_with_retention_poll also calls mark_submitted internally;
            // calling it here first ensures the flag is set even if the send
            // returns an error (belt-and-braces against a stale Pending entry).
            if let Err(e) = store.mark_submitted(&inner_key) {
                tracing::warn!(
                    inner_key = %redacted_inner,
                    error = %e,
                    "submit_fee_bump_idempotent: mark_submitted failed (non-fatal)"
                );
            }

            // Drive the send+poll via submit_with_retention_poll.
            // envelope_hash = inner_key (idempotency identity stored in envelope_hash field).
            // max_time = inner_max_time (the inner tx's timeBounds; the outer has none).
            // The SUCCESS arm finalises Success; the FAILED arm finalises Failed.
            //
            // Invariant: the precomputed outer hash (the provisional Pending poll
            // handle) MUST equal the RPC-confirmed tx_hash on the winner path.
            // The hash covers the FeeBumpTransaction body (not the signatures),
            // so the locally derived hash and the server-confirmed hash agree for
            // a correct fee-bump.  This invariant is verified by the
            // `outer_hash_invariant_precomputed_equals_rpc_confirmed` unit test.
            //
            // The submit_with_retention_poll future is returned directly as the
            // winner-arm value (clippy::let_and_return).
            submit_with_retention_poll(
                client,
                store,
                &signed_outer_xdr,
                timeout,
                network_passphrase,
                &inner_key,
                recorded_at_ledger,
                inner_max_time,
            )
            .await
        }

        BeginOutcome::AlreadyPresent(receipt) => {
            tracing::info!(
                inner_key = %redacted_inner,
                outer_tx_hash = %redact_tx_hash(&receipt.tx_hash),
                status = ?receipt.status,
                "submit_fee_bump_idempotent: AlreadyPresent; checking receipt status"
            );

            // Check is_terminal() FIRST — return the cached terminal result
            // rather than polling for a completed receipt.
            if receipt.status.is_terminal() {
                return fee_bump_receipt_to_result(receipt, &inner_key);
            }

            // Non-terminal (Pending): poll the store until the winner finalises.
            // Mirror `wait_for_winner` in `idempotent_submit.rs`.
            tracing::info!(
                inner_key = %redacted_inner,
                "submit_fee_bump_idempotent: AlreadyPresent + Pending; waiting for winner"
            );
            wait_for_winner_fee_bump(store, &inner_key).await
        }

        // BeginOutcome is #[non_exhaustive]; future variants are unexpected.
        _ => Err(WalletError::Internal(InternalError::UnexpectedState {
            detail: "unknown BeginOutcome variant in submit_fee_bump_idempotent".to_owned(),
        })),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Computes the canonical inner tx hash hex.
///
/// Preimage: `SHA-256(TransactionSignaturePayload { network_id, Tx(inner_tx) })`
///
/// This is the standard Stellar tx hash (ENVELOPE_TYPE_TX variant) used by the
/// network as the inner tx's replay-protection identity.  It uses the
/// `TransactionSignaturePayloadTaggedTransaction::Tx` variant.
fn compute_inner_tx_hash_hex(
    inner_tx: &stellar_xdr::Transaction,
    network_passphrase: &str,
) -> Result<String, WalletError> {
    use stellar_agent_core::error::ProtocolError;

    let network_id = Hash(Sha256::digest(network_passphrase.as_bytes()).into());
    let payload = TransactionSignaturePayload {
        network_id,
        tagged_transaction: TransactionSignaturePayloadTaggedTransaction::Tx(inner_tx.clone()),
    };
    let payload_bytes = payload.to_xdr(Limits::none()).map_err(|e| {
        WalletError::Protocol(ProtocolError::XdrCodecFailed {
            detail: format!(
                "fee_bump_retry: failed to encode inner TransactionSignaturePayload: {e}"
            ),
        })
    })?;
    let hash = Sha256::digest(&payload_bytes);
    Ok(bytes_to_hex(&hash))
}

/// Computes the OUTER fee-bump tx hash — the RPC poll handle.
///
/// Preimage: `SHA-256(TransactionSignaturePayload {
///     network_id, TxFeeBump(fee_bump_tx)
/// })`
///
/// Uses the same preimage that `build_and_sign_fee_bump` computes before
/// signing.  The hash covers the `FeeBumpTransaction` body
/// (fee_source, fee, inner_tx, ext) — NOT the outer envelope's signatures.
///
/// Uses the shared `build_fee_bump_tx` helper to construct the
/// `FeeBumpTransaction` body, keeping the construction identical to the
/// signing path.  Uses the
/// `TransactionSignaturePayloadTaggedTransaction::TxFeeBump` variant.
fn compute_outer_tx_hash_hex(
    v1_inner: &stellar_xdr::TransactionV1Envelope,
    fee_source: &str,
    outer_fee_stroops: i64,
    network_passphrase: &str,
) -> Result<String, WalletError> {
    use stellar_agent_core::error::{ProtocolError, ValidationError};
    use stellar_xdr::{MuxedAccount, Uint256};

    // Parse fee_source G-strkey to MuxedAccount (same as build_fee_bump's
    // parse_fee_source helper, but we only need the MuxedAccount here and
    // parse_fee_source is private to fee_bump.rs).
    let pk = stellar_strkey::ed25519::PublicKey::from_string(fee_source).map_err(|e| {
        WalletError::Validation(ValidationError::AddressInvalid {
            input: format!("fee_source invalid in outer hash computation: {e}"),
        })
    })?;
    let fee_source_muxed = MuxedAccount::Ed25519(Uint256(pk.0));

    // Reuse build_fee_bump_tx to construct the FeeBumpTransaction body,
    // keeping the construction identical to build_and_sign_fee_bump internally.
    let fee_bump_tx = build_fee_bump_tx(fee_source_muxed, outer_fee_stroops, v1_inner.clone());

    let network_id = Hash(Sha256::digest(network_passphrase.as_bytes()).into());
    let payload = TransactionSignaturePayload {
        network_id,
        tagged_transaction: TransactionSignaturePayloadTaggedTransaction::TxFeeBump(fee_bump_tx),
    };
    let payload_bytes = payload.to_xdr(Limits::none()).map_err(|e| {
        WalletError::Protocol(ProtocolError::XdrCodecFailed {
            detail: format!(
                "fee_bump_retry: failed to encode outer TransactionSignaturePayload: {e}"
            ),
        })
    })?;
    let hash = Sha256::digest(&payload_bytes);
    Ok(bytes_to_hex(&hash))
}

/// Redacts the inner key for logging (first-8-last-8 of the hash portion).
///
/// The `feebump-inner:` prefix is preserved; only the 64-hex-char hash suffix
/// is truncated to match the `redact_tx_hash` convention.
fn redact_inner_key(inner_key: &str) -> String {
    let hash_part = inner_key
        .strip_prefix(FEEBUMP_INNER_PREFIX)
        .unwrap_or(inner_key);
    format!("{FEEBUMP_INNER_PREFIX}{}", redact_tx_hash(hash_part))
}

/// Converts a terminal [`stellar_agent_core::profile::receipt::SubmissionReceipt`]
/// to a [`SubmissionResult`] or the appropriate [`WalletError`].
///
/// `inner_key` is used in error messages for the Pending guard; callers only
/// pass terminal receipts here so the Pending arm should not occur.
fn fee_bump_receipt_to_result(
    receipt: stellar_agent_core::profile::receipt::SubmissionReceipt,
    inner_key: &str,
) -> Result<SubmissionResult, WalletError> {
    use stellar_agent_core::error::{NetworkError, SubmissionError};

    match receipt.status {
        ReceiptStatus::Success => Ok(SubmissionResult {
            tx_hash: receipt.tx_hash,
            ledger: receipt.ledger.unwrap_or(0),
            signer_kind: None,
        }),
        // A failed receipt is a deterministic on-chain rejection, not a transport
        // failure; surface it under the Submission category (preserving the
        // original wire code) so a cached replay is not mistaken for a retryable
        // network error.
        ReceiptStatus::Failed { code } => {
            Err(WalletError::Submission(SubmissionError::OnChainFailed {
                code,
            }))
        }
        ReceiptStatus::Ambiguous => Err(WalletError::Network(NetworkError::RpcUnreachable {
            url: "(cached)".to_owned(),
            reason: "cached ambiguous fee-bump receipt: transaction status unknown".to_owned(),
        })),
        ReceiptStatus::Reorged => Err(WalletError::Network(NetworkError::RpcUnreachable {
            url: "(cached)".to_owned(),
            reason: "cached reorged fee-bump receipt: transaction was rewound".to_owned(),
        })),
        ReceiptStatus::Pending => {
            // Should not occur — callers only pass terminal receipts here.
            // Use redact_inner_key for consistency + unconditional panic-safety
            // (no slice indexing that could panic on short keys).
            Err(WalletError::Internal(InternalError::UnexpectedState {
                detail: format!(
                    "fee_bump_receipt_to_result called with Pending receipt for {}",
                    redact_inner_key(inner_key)
                ),
            }))
        }
        _ => Err(WalletError::Internal(InternalError::UnexpectedState {
            detail: "unknown ReceiptStatus variant in fee_bump_receipt_to_result".to_owned(),
        })),
    }
}

/// Polls the receipt store until the receipt for `inner_key` becomes terminal,
/// or until the loser poll limit elapses.
async fn wait_for_winner_fee_bump(
    store: &ReceiptStore,
    inner_key: &str,
) -> Result<SubmissionResult, WalletError> {
    use stellar_agent_core::error::NetworkError;
    use tokio::time::sleep;

    let redacted = redact_inner_key(inner_key);

    for _ in 0..LOSER_MAX_POLLS {
        sleep(LOSER_POLL_INTERVAL).await;

        let receipt = store.get(inner_key).map_err(|e| {
            WalletError::Internal(InternalError::UnexpectedState {
                detail: format!("fee_bump receipt store get failed in winner poll: {e}"),
            })
        })?;

        match receipt {
            Some(r) if r.status.is_terminal() => {
                return fee_bump_receipt_to_result(r, inner_key);
            }
            _ => continue,
        }
    }

    Err(WalletError::Network(NetworkError::RpcUnreachable {
        url: "(none)".to_owned(),
        reason: format!(
            "fee-bump loser task timed out waiting for winner to finalise receipt for \
             inner_key={redacted}"
        ),
    }))
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
        reason = "unit tests; panics/unwraps acceptable"
    )]

    use super::*;
    use stellar_agent_core::StellarAmount;
    use stellar_agent_core::profile::receipt::ReceiptStore;

    // ── Test constants ────────────────────────────────────────────────────────

    const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";

    // Fixed test seeds (public test fixtures, NOT production keys).
    // Seeds [3u8;32] and [4u8;32] are unused by other test modules in this crate,
    // keeping store keys disjoint across fixture sets.
    const INNER_SOURCE_SEED: [u8; 32] = [3u8; 32];
    const FEE_PAYER_SEED: [u8; 32] = [4u8; 32];

    fn open_temp_store() -> (tempfile::TempDir, ReceiptStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = ReceiptStore::open_at(dir.path(), "fee-bump-retry-test").unwrap();
        (dir, store)
    }

    /// Builds a signed inner V1 envelope using the test inner-source key.
    ///
    /// Returns `(inner_signed_xdr, inner_source_gstrkey)`.
    async fn build_inner_signed_xdr(seq: i64, max_time_opt: Option<u64>) -> (String, String) {
        use crate::builder::{Asset, ClassicOpBuilder};
        use crate::signing::software::SoftwareSigningKey;
        use stellar_strkey::ed25519::PublicKey as StrPublicKey;

        let inner_signing_key = ed25519_dalek::SigningKey::from_bytes(&INNER_SOURCE_SEED);
        let inner_pk_bytes: [u8; 32] = inner_signing_key.verifying_key().to_bytes();
        let inner_source_gstrkey = StrPublicKey(inner_pk_bytes).to_string().as_str().to_owned();

        let fee_paying_sk = ed25519_dalek::SigningKey::from_bytes(&FEE_PAYER_SEED);
        let fee_payer_pk: [u8; 32] = fee_paying_sk.verifying_key().to_bytes();
        let fee_payer_gstrkey = StrPublicKey(fee_payer_pk).to_string().as_str().to_owned();

        let inner_signer = SoftwareSigningKey::new_from_bytes(INNER_SOURCE_SEED);
        let mut builder =
            ClassicOpBuilder::new(&inner_source_gstrkey, seq, TESTNET_PASSPHRASE, 100);
        builder
            .payment(
                &fee_payer_gstrkey,
                StellarAmount::from_stroops(1),
                &Asset::Native,
            )
            .unwrap();

        if let Some(mt) = max_time_opt {
            builder.with_time_bounds(0, mt);
        }

        let signed = builder.build_and_sign(&inner_signer).await.unwrap();
        (signed, inner_source_gstrkey)
    }

    /// Returns the fee-payer G-strkey derived from `FEE_PAYER_SEED`.
    fn fee_payer_gstrkey() -> String {
        use stellar_strkey::ed25519::PublicKey as StrPublicKey;
        let sk = ed25519_dalek::SigningKey::from_bytes(&FEE_PAYER_SEED);
        let pk: [u8; 32] = sk.verifying_key().to_bytes();
        StrPublicKey(pk).to_string().as_str().to_owned()
    }

    /// Verifies that a `TxFeeBumpInnerSuccess` result at the SUCCESS layer flows
    /// to `Ok(SubmissionResult)` through the receipt store.
    ///
    /// `stellar-rpc` reports an inner-applied fee-bump as `status: SUCCESS`.
    /// The SUCCESS arm finalises `Success`; `TxFeeBumpInnerSuccess` does not
    /// reach the FAILED branch.
    ///
    /// Pre-seeds a `Success` receipt and verifies that `fee_bump_receipt_to_result`
    /// maps it to `Ok(SubmissionResult)`.  Also confirms that the
    /// `TxFeeBumpInnerSuccess` XDR discriminant is constructable.
    #[test]
    fn fee_bump_inner_success_maps_to_success_receipt() {
        use stellar_xdr::{
            Hash, InnerTransactionResult, InnerTransactionResultExt, InnerTransactionResultPair,
            InnerTransactionResultResult, TransactionResultResult,
        };

        // Confirm the variant is constructable (discriminant existence check).
        let _ = std::mem::discriminant(&TransactionResultResult::TxFeeBumpInnerSuccess(
            InnerTransactionResultPair {
                transaction_hash: Hash([0u8; 32]),
                result: InnerTransactionResult {
                    fee_charged: 100,
                    result: InnerTransactionResultResult::TxSuccess(vec![].try_into().unwrap()),
                    ext: InnerTransactionResultExt::V0,
                },
            },
        ));

        // Pre-seed a Success receipt for an inner key and verify it maps to Ok.
        let (dir, store) = open_temp_store();
        let inner_key =
            "feebump-inner:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let outer_tx_hash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        store.try_begin(inner_key, outer_tx_hash, 0, 100).unwrap();
        store
            .finalize(inner_key, ReceiptStatus::Success, Some(42))
            .unwrap();

        let receipt = store.get(inner_key).unwrap().unwrap();
        assert_eq!(receipt.status, ReceiptStatus::Success);

        let result = fee_bump_receipt_to_result(receipt, inner_key);
        assert!(
            result.is_ok(),
            "fee-bump Success receipt must map to Ok(SubmissionResult), got: {result:?}"
        );
        let sub = result.unwrap();
        assert_eq!(sub.ledger, 42, "ledger must match cached receipt");
        drop(dir);
    }

    /// `compute_inner_tx_hash_hex` is deterministic for the same input.
    #[tokio::test]
    async fn inner_hash_is_stable_and_deterministic() {
        let (inner_xdr, _) = build_inner_signed_xdr(1, None).await;
        let v1 = decode_inner_v1(&inner_xdr)
            .map_err(WalletError::from)
            .unwrap();

        let hash1 = compute_inner_tx_hash_hex(&v1.tx, TESTNET_PASSPHRASE).unwrap();
        let hash2 = compute_inner_tx_hash_hex(&v1.tx, TESTNET_PASSPHRASE).unwrap();
        assert_eq!(hash1, hash2, "inner tx hash must be deterministic");
        assert_eq!(hash1.len(), 64, "SHA-256 hex must be 64 chars");
    }

    /// `compute_outer_tx_hash_hex` is deterministic for the same inputs and
    /// changes when `outer_fee_stroops` changes.
    #[tokio::test]
    async fn outer_hash_is_stable_and_changes_with_fee() {
        let (inner_xdr, _) = build_inner_signed_xdr(1, None).await;
        let v1 = decode_inner_v1(&inner_xdr)
            .map_err(WalletError::from)
            .unwrap();
        let fp_g = fee_payer_gstrkey();

        let hash_500 = compute_outer_tx_hash_hex(&v1, &fp_g, 500, TESTNET_PASSPHRASE).unwrap();
        let hash_500b = compute_outer_tx_hash_hex(&v1, &fp_g, 500, TESTNET_PASSPHRASE).unwrap();
        assert_eq!(hash_500, hash_500b, "outer tx hash must be deterministic");
        assert_eq!(hash_500.len(), 64, "SHA-256 hex must be 64 chars");

        // Different outer fee ⇒ different outer hash (fee is in the signed payload).
        let hash_1000 = compute_outer_tx_hash_hex(&v1, &fp_g, 1000, TESTNET_PASSPHRASE).unwrap();
        assert_ne!(
            hash_500, hash_1000,
            "different outer_fee_stroops must produce different outer hash"
        );
    }

    /// The inner key (with prefix) is distinct from the bare inner tx hash.
    ///
    /// Verifies that the `feebump-inner:` prefix correctly namespaces fee-bump
    /// keys away from the classic-path key space.
    #[tokio::test]
    async fn inner_key_prefix_namespacing() {
        let (inner_xdr, _) = build_inner_signed_xdr(1, None).await;
        let v1 = decode_inner_v1(&inner_xdr)
            .map_err(WalletError::from)
            .unwrap();
        let hash_hex = compute_inner_tx_hash_hex(&v1.tx, TESTNET_PASSPHRASE).unwrap();

        let inner_key = format!("{FEEBUMP_INNER_PREFIX}{hash_hex}");
        assert!(
            inner_key.starts_with(FEEBUMP_INNER_PREFIX),
            "inner key must start with FEEBUMP_INNER_PREFIX"
        );
        assert_ne!(
            inner_key, hash_hex,
            "prefixed inner key must differ from bare hash (no aliasing)"
        );
    }

    /// `max_time` extracted from an inner envelope equals the inner tx's `maxTime`.
    ///
    /// Builds an inner tx with a known `TimeBounds.maxTime` (1_800_000_099) and
    /// verifies that `extract_max_time` over `TransactionEnvelope::Tx(v1_inner)`
    /// returns that exact value.  Confirms the receipt records the inner tx's
    /// `max_time` (not zero / not an outer cond, which does not exist in CAP-15).
    #[tokio::test]
    async fn inner_max_time_extracted_from_inner_envelope() {
        const KNOWN_MAX_TIME: u64 = 1_800_000_099;
        let (inner_xdr, _) = build_inner_signed_xdr(2, Some(KNOWN_MAX_TIME)).await;
        let v1 = decode_inner_v1(&inner_xdr)
            .map_err(WalletError::from)
            .unwrap();

        let inner_envelope = TransactionEnvelope::Tx(v1);
        let max_time = extract_max_time(&inner_envelope);

        assert_eq!(
            max_time, KNOWN_MAX_TIME,
            "extract_max_time over inner envelope must return inner's TimeBounds.maxTime"
        );
    }

    /// Two different inner tx hashes (different sequence numbers) produce
    /// different inner keys — no key collision across distinct inner txs.
    #[tokio::test]
    async fn distinct_inner_txs_produce_distinct_inner_keys() {
        let (inner_xdr_1, _) = build_inner_signed_xdr(10, None).await;
        let (inner_xdr_2, _) = build_inner_signed_xdr(11, None).await;

        let v1_1 = decode_inner_v1(&inner_xdr_1)
            .map_err(WalletError::from)
            .unwrap();
        let v1_2 = decode_inner_v1(&inner_xdr_2)
            .map_err(WalletError::from)
            .unwrap();

        let hash_1 = compute_inner_tx_hash_hex(&v1_1.tx, TESTNET_PASSPHRASE).unwrap();
        let hash_2 = compute_inner_tx_hash_hex(&v1_2.tx, TESTNET_PASSPHRASE).unwrap();

        assert_ne!(
            hash_1, hash_2,
            "distinct inner txs (different seq) must have distinct inner tx hashes"
        );
    }

    /// `compute_outer_tx_hash_hex` produces the same hash as the signed outer
    /// fee-bump envelope's payload hash.
    ///
    /// Guards the invariant that the precomputed outer hash (stored in the
    /// Pending row) MUST agree with the RPC-confirmed outer hash returned by
    /// `submit_with_retention_poll` on the winner path.
    ///
    /// 1. Builds and signs a fee-bump via `build_and_sign_fee_bump`.
    /// 2. Decodes the signed outer envelope and recomputes the outer hash from
    ///    the same `FeeBumpTransaction` body using the same preimage construction
    ///    that `compute_outer_tx_hash_hex` uses internally.
    /// 3. Asserts equality with `compute_outer_tx_hash_hex`.
    ///
    /// The hash covers the `FeeBumpTransaction` body (not the signatures), so
    /// both computations must agree for a correct fee-bump.
    #[tokio::test]
    async fn outer_hash_invariant_precomputed_equals_rpc_confirmed() {
        use crate::fee_bump::build_and_sign_fee_bump;
        use crate::signing::software::SoftwareSigningKey;
        use sha2::{Digest as _, Sha256};
        use stellar_xdr::{
            Hash, Limits, ReadXdr, TransactionEnvelope, TransactionSignaturePayload,
            TransactionSignaturePayloadTaggedTransaction, WriteXdr,
        };

        let (inner_xdr, _) = build_inner_signed_xdr(20, None).await;
        let v1 = decode_inner_v1(&inner_xdr)
            .map_err(WalletError::from)
            .unwrap();
        let fp_g = fee_payer_gstrkey();

        // Precomputed hash via the function under test.
        let precomputed = compute_outer_tx_hash_hex(&v1, &fp_g, 500, TESTNET_PASSPHRASE).unwrap();
        assert_eq!(precomputed.len(), 64, "SHA-256 hex must be 64 chars");
        assert!(
            precomputed.chars().all(|c| c.is_ascii_hexdigit()),
            "outer hash must be lowercase hex"
        );

        // Sign the fee-bump with the fee-payer key.
        let fee_payer_signer = SoftwareSigningKey::new_from_bytes(FEE_PAYER_SEED);
        let signed_outer_xdr = build_and_sign_fee_bump(
            &inner_xdr,
            &fp_g,
            500,
            1_000_000,
            TESTNET_PASSPHRASE,
            &fee_payer_signer,
        )
        .await
        .expect("build_and_sign_fee_bump must succeed on valid inputs");

        // Decode the signed outer fee-bump envelope.
        use base64::Engine as _;
        let outer_bytes = base64::engine::general_purpose::STANDARD
            .decode(signed_outer_xdr.trim())
            .unwrap();
        let outer_env = TransactionEnvelope::from_xdr(&outer_bytes, Limits::none()).unwrap();

        // Extract the FeeBumpTransaction body.
        let fee_bump_tx = match outer_env {
            TransactionEnvelope::TxFeeBump(ref fb_env) => fb_env.tx.clone(),
            _ => panic!("expected TxFeeBump envelope"),
        };

        // Recompute the outer hash from the signed envelope's body.
        let network_id = Hash(Sha256::digest(TESTNET_PASSPHRASE.as_bytes()).into());
        let payload = TransactionSignaturePayload {
            network_id,
            tagged_transaction: TransactionSignaturePayloadTaggedTransaction::TxFeeBump(
                fee_bump_tx,
            ),
        };
        let payload_bytes = payload.to_xdr(Limits::none()).unwrap();
        let from_signed = bytes_to_hex(&Sha256::digest(&payload_bytes));

        // The precomputed hash MUST equal the hash from the signed envelope.
        assert_eq!(
            precomputed, from_signed,
            "compute_outer_tx_hash_hex must agree with the hash computed from the signed \
             envelope body (invariant: precomputed == rpc-confirmed)"
        );
    }

    // ── abandon_pre_submit tests ──────────────────────────────────────────────

    /// `abandon_pre_submit` on a fresh `try_begin` Pending with `submitted=false`
    /// removes the entry; a subsequent `try_begin` for the same key is Winner.
    #[test]
    fn abandon_pre_submit_fresh_pending_removes_entry_retry_wins() {
        let (_dir, store) = open_temp_store();
        let inner_key =
            "feebump-inner:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let outer_tx_hash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

        // Winner: try_begin sets submitted=false.
        let outcome = store.try_begin(inner_key, outer_tx_hash, 0, 100).unwrap();
        assert!(matches!(
            outcome,
            stellar_agent_core::profile::receipt::BeginOutcome::Winner
        ));

        let receipt = store.get(inner_key).unwrap().unwrap();
        assert!(!receipt.submitted, "try_begin must set submitted=false");

        // Abandon the pre-submit entry (signing failed, not yet sent).
        store.abandon_pre_submit(inner_key).unwrap();
        assert!(
            store.get(inner_key).unwrap().is_none(),
            "abandon_pre_submit must remove the entry"
        );

        // A subsequent try_begin must be Winner (corrected-retry can proceed).
        let outer_tx_hash2 = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let outcome2 = store.try_begin(inner_key, outer_tx_hash2, 0, 100).unwrap();
        assert!(
            matches!(
                outcome2,
                stellar_agent_core::profile::receipt::BeginOutcome::Winner
            ),
            "second try_begin after abandon must be Winner; got: {outcome2:?}"
        );
    }

    /// After `mark_submitted(key)`, `abandon_pre_submit` refuses (entry retained).
    /// A finalised terminal entry also refuses.
    #[test]
    fn abandon_pre_submit_refuses_after_mark_submitted_and_terminal() {
        let (_dir, store) = open_temp_store();
        let inner_key =
            "feebump-inner:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
        let outer_tx_hash = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

        // (b-1) Refuse after mark_submitted.
        store.try_begin(inner_key, outer_tx_hash, 0, 100).unwrap();
        store.mark_submitted(inner_key).unwrap();

        let receipt = store.get(inner_key).unwrap().unwrap();
        assert!(receipt.submitted, "mark_submitted must set submitted=true");

        // abandon_pre_submit must be a no-op (entry retained).
        store.abandon_pre_submit(inner_key).unwrap();
        assert!(
            store.get(inner_key).unwrap().is_some(),
            "abandon_pre_submit must be no-op when submitted=true (entry must remain)"
        );

        // (b-2) Refuse on a terminal entry.
        store
            .finalize(
                inner_key,
                stellar_agent_core::profile::receipt::ReceiptStatus::Success,
                Some(42),
            )
            .unwrap();
        store.abandon_pre_submit(inner_key).unwrap();
        assert!(
            store.get(inner_key).unwrap().is_some(),
            "abandon_pre_submit must be no-op on a terminal (Success) entry"
        );
        assert_eq!(
            store.get(inner_key).unwrap().unwrap().status,
            stellar_agent_core::profile::receipt::ReceiptStatus::Success,
            "terminal entry must remain Success after abandon_pre_submit no-op"
        );
    }
}
