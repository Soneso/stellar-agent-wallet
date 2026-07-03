//! Local fee-bump wrapper for Stellar classic transactions.
//!
//! Wraps an already-signed inner `TransactionV1Envelope` in an outer
//! `FeeBumpTransaction` whose `fee_source` is a distinct fee-payer account.
//!
//! # CAP-15 inner-v1 constraint (MUST)
//!
//! `FeeBumpTransactionInnerTx` has a single variant `Tx(TransactionV1Envelope)`.
//! Only `TransactionEnvelope::Tx(v1)` input is accepted; `TxV0` and `TxFeeBump`
//! inputs are rejected with [`FeeBumpError::InnerNotV1`] before any signing.
//!
//! # Fee-payer signing (CAP-15 / SEP-23)
//!
//! The fee-payer signs ONLY the outer `FeeBumpTransaction` payload via a NEW
//! signing site — NOT the inner `TransactionEnvelope`.  The preimage is:
//!
//! ```text
//! SHA-256(network_id || TransactionSignaturePayload {
//!     tagged_transaction: TxFeeBump(fee_bump_tx)
//! })
//! ```
//!
//! This is the `EnvelopeType::TxFeeBump` variant of the standard SEP-23
//! `TransactionSignaturePayload`.
//! The inner `TransactionV1Envelope` (its `tx` + its `signatures`) is
//! preserved byte-for-byte.
//!
//! # CAP-15 fee minimum (rate-based)
//!
//! The outer fee must satisfy a RATE-based minimum, NOT a flat `≥ inner_fee`:
//!
//! ```text
//! cap15_minimum = (inner_op_count + 1) * max(MIN_BASE_FEE_STROOPS, ceil(inner_fee / inner_op_count))
//! ```
//!
//! Source: stellar-core `FeeBumpTransactionFrame::commonValid` +
//! CAP-0015 §"Validity of FeeBumpTransactions".

use sha2::{Digest, Sha256};
use stellar_agent_core::error::{ProtocolError, SubmissionError, ValidationError, WalletError};
use stellar_xdr::{
    DecoratedSignature, FeeBumpTransaction, FeeBumpTransactionEnvelope, FeeBumpTransactionExt,
    FeeBumpTransactionInnerTx, Hash, Limits, MuxedAccount, ReadXdr, Signature, SignatureHint,
    TransactionEnvelope, TransactionSignaturePayload, TransactionSignaturePayloadTaggedTransaction,
    TransactionV1Envelope, Uint256, WriteXdr,
};

use crate::signing::Signer;

// ─────────────────────────────────────────────────────────────────────────────
// CAP-15 constants
// ─────────────────────────────────────────────────────────────────────────────

/// Stellar minimum base fee per operation in stroops.
///
/// Source: Stellar protocol / stellar-core `TxSetUtils.cpp`
/// `MIN_BASE_FEE = 100` stroops per operation.
const MIN_BASE_FEE_STROOPS: u64 = 100;

// ─────────────────────────────────────────────────────────────────────────────
// Public error type
// ─────────────────────────────────────────────────────────────────────────────

/// Errors specific to fee-bump construction.
///
/// All variants are fail-closed: they are returned BEFORE any signing or
/// submission attempt.  No secret material is ever included in the fields.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FeeBumpError {
    /// The inner envelope is not a v1 transaction.
    ///
    /// CAP-15 requires that the inner transaction be of type
    /// `TransactionEnvelope::Tx` (v1).  `TxV0` and `TxFeeBump` are rejected
    /// before any signing.
    ///
    /// `found` is one of `"TxV0"` or `"TxFeeBump"` (the two non-v1
    /// `TransactionEnvelope` variants; the enum is exhaustively matched).
    #[error("fee-bump inner transaction must be TransactionEnvelope::Tx (v1); found: {found}")]
    InnerNotV1 {
        /// The envelope type string that was rejected (`"TxV0"` or `"TxFeeBump"`).
        found: String,
    },

    /// The inner envelope XDR could not be decoded.
    ///
    /// `detail` is a non-secret diagnostic string.
    #[error("inner envelope XDR decode failed: {detail}")]
    InnerDecodeFailed {
        /// Non-secret diagnostic from the XDR decode failure.
        detail: String,
    },

    /// `outer_fee_stroops` is below the CAP-15 rate-based minimum.
    ///
    /// The minimum outer fee is `(inner_op_count + 1) * max(MIN_BASE_FEE_STROOPS,
    /// ceil(inner_fee / inner_op_count))`.
    #[error(
        "outer_fee_stroops ({supplied}) is below the CAP-15 minimum ({minimum}); \
         inner_op_count={inner_op_count}, inner_fee={inner_fee}"
    )]
    FeeBelowCap15Minimum {
        /// The fee supplied by the caller.
        supplied: i64,
        /// The computed CAP-15 minimum.
        minimum: i64,
        /// The number of operations in the inner transaction.
        inner_op_count: u32,
        /// The inner transaction fee in stroops.
        inner_fee: u32,
    },

    /// `outer_fee_stroops` exceeds the caller-supplied policy cap.
    #[error("outer_fee_stroops ({supplied}) exceeds the policy cap ({cap})")]
    FeeExceedsPolicyCap {
        /// The fee supplied by the caller.
        supplied: i64,
        /// The policy cap supplied by the caller.
        cap: i64,
    },

    /// The fee-source G-strkey could not be parsed as an ed25519 public key.
    ///
    /// `detail` is a non-secret diagnostic string.
    #[error("fee_source address is invalid: {detail}")]
    InvalidFeeSource {
        /// Non-secret diagnostic.
        detail: String,
    },

    /// The fee_source does not match the fee_payer_signer's public key.
    ///
    /// A fee-bump envelope signed by a key that does not match the declared
    /// `fee_source` will be rejected on-chain with `txBAD_AUTH`.
    #[error(
        "fee_source does not match the fee_payer_signer's public key; \
         they must be the same account"
    )]
    FeeSourceSignerMismatch,

    /// XDR encoding of the constructed fee-bump envelope failed.
    ///
    /// `detail` is a non-secret diagnostic string.
    #[error("fee-bump envelope XDR encode failed: {detail}")]
    EnvelopeEncodeFailed {
        /// Non-secret diagnostic.
        detail: String,
    },

    /// A signing operation on the fee-payer key failed.
    ///
    /// The underlying [`WalletError`] is propagated transparently.
    #[error("fee-payer signing failed: {0}")]
    SigningFailed(WalletError),
}

impl FeeBumpError {
    /// Returns the stable wire-format error code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::InnerNotV1 { .. } => "feebump.inner_not_v1",
            Self::InnerDecodeFailed { .. } => "feebump.inner_decode_failed",
            Self::FeeBelowCap15Minimum { .. } => "feebump.fee_below_cap15_minimum",
            Self::FeeExceedsPolicyCap { .. } => "feebump.fee_exceeds_policy_cap",
            Self::InvalidFeeSource { .. } => "feebump.invalid_fee_source",
            Self::FeeSourceSignerMismatch => "feebump.fee_source_signer_mismatch",
            Self::EnvelopeEncodeFailed { .. } => "feebump.envelope_encode_failed",
            Self::SigningFailed(_) => "feebump.signing_failed",
        }
    }
}

// Map FeeBumpError into the unified WalletError taxonomy.
impl From<FeeBumpError> for WalletError {
    fn from(e: FeeBumpError) -> Self {
        match e {
            // Protocol-level (XDR decode/encode) errors.
            FeeBumpError::InnerDecodeFailed { detail } => {
                WalletError::Protocol(ProtocolError::XdrCodecFailed { detail })
            }
            FeeBumpError::EnvelopeEncodeFailed { detail } => {
                WalletError::Protocol(ProtocolError::XdrCodecFailed { detail })
            }
            // Validation errors (caller-supplied bad input).
            FeeBumpError::InnerNotV1 { found } => {
                WalletError::Validation(ValidationError::AddressInvalid {
                    input: format!("inner envelope type {found} (expected Tx/v1)"),
                })
            }
            FeeBumpError::InvalidFeeSource { detail } => {
                WalletError::Validation(ValidationError::AddressInvalid { input: detail })
            }
            // Submission errors.
            FeeBumpError::FeeBelowCap15Minimum {
                supplied, minimum, ..
            } => WalletError::Submission(SubmissionError::TxMalformed {
                detail: format!(
                    "fee_bump: outer_fee_stroops {supplied} below CAP-15 minimum {minimum}"
                ),
            }),
            FeeBumpError::FeeExceedsPolicyCap { supplied, cap } => {
                WalletError::Submission(SubmissionError::TxMalformed {
                    detail: format!(
                        "fee_bump: outer_fee_stroops {supplied} exceeds policy cap {cap}"
                    ),
                })
            }
            FeeBumpError::FeeSourceSignerMismatch => {
                WalletError::Submission(SubmissionError::TxMalformed {
                    detail: "fee_source does not match fee_payer_signer public key".to_owned(),
                })
            }
            // Signing failures contain a WalletError; unwrap and propagate directly.
            FeeBumpError::SigningFailed(source) => source,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Wraps an already-signed inner `TransactionV1Envelope` in an unsigned
/// `FeeBumpTransactionEnvelope`.
///
/// The returned base64 string is a `TransactionEnvelope::TxFeeBump` with an
/// empty `signatures` vec.  Call [`build_and_sign_fee_bump`] to attach the
/// fee-payer signature.
///
/// # Arguments
///
/// - `inner_envelope_xdr` — base64-encoded `TransactionEnvelope`; MUST be
///   `TransactionEnvelope::Tx(v1)`.
/// - `fee_source` — G-strkey of the fee-payer account.  This becomes the
///   `fee_source` field of the `FeeBumpTransaction`.  MUST equal the
///   `fee_payer_signer`'s public key when calling [`build_and_sign_fee_bump`].
/// - `outer_fee_stroops` — the total outer fee in stroops (not per-op) charged
///   to the `fee_source` account.  This is the fee recorded on-chain for the
///   fee-bump envelope; it is NOT a ceiling — it is the exact amount charged.
/// - `policy_fee_cap_stroops` — the caller-supplied upper-bound policy cap.
///   Derived from `FeeStatsView` p99 × a multiplier or a profile-level cap;
///   callers MUST NOT pass `i64::MAX` as this would neuter the fail-closed
///   policy guard.  Rejected with [`FeeBumpError::FeeExceedsPolicyCap`] if
///   `outer_fee_stroops` exceeds this value.
///
/// # Correctness contracts
///
/// 1. **CAP-15 v1-guard**: if `inner_envelope_xdr` decodes to `TxV0` or
///    `TxFeeBump`, returns [`FeeBumpError::InnerNotV1`] BEFORE any construction.
/// 2. **CAP-15 fee minimum**: rejects `outer_fee_stroops` below
///    `cap15_minimum = (inner_op_count + 1) * max(100, ceil(inner_fee /
///    inner_op_count))`.
///    Source: CAP-0015 §"Validity of FeeBumpTransactions".
/// 3. **Policy cap**: rejects `outer_fee_stroops > policy_fee_cap_stroops`.
/// 4. **Inner integrity**: the inner `TransactionV1Envelope` (tx + its
///    signatures) is preserved byte-for-byte in the outer `inner_tx` field.
///
/// # Errors
///
/// - [`FeeBumpError::InnerDecodeFailed`] — XDR decode failed.
/// - [`FeeBumpError::InnerNotV1`] — inner is `TxV0` or `TxFeeBump`.
/// - [`FeeBumpError::InvalidFeeSource`] — `fee_source` is not a valid
///   G-strkey or is a muxed M-strkey (only plain Ed25519 G-strkeys are
///   accepted as fee_source).
/// - [`FeeBumpError::FeeBelowCap15Minimum`] — fee below CAP-15 minimum.
/// - [`FeeBumpError::FeeExceedsPolicyCap`] — fee above policy cap.
/// - [`FeeBumpError::EnvelopeEncodeFailed`] — XDR encode failed.
///
/// # Panics
///
/// Never panics.
///
/// # Examples
///
/// # Note
///
/// This function is `pub(crate)` — it is an internal building block for tests
/// and other crate-internal callers.  External callers that need a fully-signed
/// fee-bump envelope should call [`build_and_sign_fee_bump`].
// pub(crate) visibility allows test modules to call build_fee_bump directly
// without duplicating the construction logic.
#[allow(dead_code)]
pub(crate) fn build_fee_bump(
    inner_envelope_xdr: &str,
    fee_source: &str,
    outer_fee_stroops: i64,
    policy_fee_cap_stroops: i64,
) -> Result<String, FeeBumpError> {
    let v1_inner = decode_inner_v1(inner_envelope_xdr)?;
    validate_fee(outer_fee_stroops, policy_fee_cap_stroops, &v1_inner)?;
    let fee_source_muxed = parse_fee_source(fee_source)?;

    let fee_bump_tx = build_fee_bump_tx(fee_source_muxed, outer_fee_stroops, v1_inner);
    let fee_bump_env = TransactionEnvelope::TxFeeBump(FeeBumpTransactionEnvelope {
        tx: fee_bump_tx,
        signatures: vec![]
            .try_into()
            .map_err(|_| FeeBumpError::EnvelopeEncodeFailed {
                detail: "unexpected: zero signatures exceeded VecM cap".to_owned(),
            })?,
    });

    fee_bump_env
        .to_xdr_base64(Limits::none())
        .map_err(|e| FeeBumpError::EnvelopeEncodeFailed {
            detail: format!("TransactionEnvelope::TxFeeBump XDR base64 encode failed: {e}"),
        })
}

/// Wraps an already-signed inner `TransactionV1Envelope` in a
/// `FeeBumpTransactionEnvelope` and attaches the fee-payer's ed25519
/// signature over the outer `TxFeeBump` payload.
///
/// This is the complete fee-bump construction + signing path.  The fee-payer
/// signs ONLY the outer `FeeBumpTransaction` payload — the inner
/// `TransactionV1Envelope` (its `tx` + its `signatures`) is preserved
/// byte-for-byte.
///
/// # Signing contract (CAP-15 / SEP-23)
///
/// The fee-payer signature is over:
///
/// ```text
/// SHA-256(network_id || TransactionSignaturePayload {
///     tagged_transaction: TxFeeBump(fee_bump_tx)
/// })
/// ```
///
/// where `network_id = SHA-256(network_passphrase)`.
///
/// This is the `EnvelopeType::TxFeeBump` variant of `TransactionSignaturePayload`,
/// computed via a dedicated signing site for the outer fee-bump payload
/// (distinct from the `EnvelopeType::Tx` variant used for inner transactions).
///
/// # Arguments
///
/// - `inner_envelope_xdr` — base64-encoded `TransactionEnvelope::Tx(v1)`.
/// - `fee_source` — G-strkey of the fee-payer.  MUST match
///   `fee_payer_signer.public_key()`.  Only plain Ed25519 G-strkeys are
///   accepted; muxed M-strkeys are rejected with
///   [`FeeBumpError::InvalidFeeSource`].
/// - `outer_fee_stroops` — total outer fee in stroops charged to `fee_source`.
/// - `policy_fee_cap_stroops` — caller-supplied upper-bound policy cap.
///   Typically derived from `FeeStatsView` p99 × a multiplier or a
///   profile-level cap.  Callers MUST NOT pass `i64::MAX` as this neuters the
///   fail-closed policy guard.
/// - `network_passphrase` — used to construct the SEP-23 signature payload.
/// - `fee_payer_signer` — signer whose public key MUST match `fee_source`.
///
/// # Errors
///
/// All errors from `build_fee_bump`, plus:
///
/// - [`FeeBumpError::FeeSourceSignerMismatch`] — `fee_source` does not match
///   `fee_payer_signer.public_key()`.
/// - [`FeeBumpError::SigningFailed`] — `Signer::public_key()` or
///   `Signer::sign_tx_payload()` returned an error.
/// - [`FeeBumpError::EnvelopeEncodeFailed`] — XDR encode of the
///   `TransactionSignaturePayload` or final envelope failed.
///
/// # Panics
///
/// Never panics.
///
/// # Examples
///
/// ```no_run
/// use stellar_agent_network::fee_bump::build_and_sign_fee_bump;
/// use stellar_agent_network::signing::SoftwareSigningKey;
///
/// # async fn example(inner_xdr: &str) -> Result<(), stellar_agent_network::fee_bump::FeeBumpError> {
/// let fee_payer = SoftwareSigningKey::new_from_bytes([1u8; 32]);
/// // G-strkey for seed [1u8;32] (verified via SoftwareSigningKey::public_key())
/// let signed_xdr = build_and_sign_fee_bump(
///     inner_xdr,
///     "GCFIRY65OQE7DFP5KLNS2PF2LVZMUZYJX4OZIEQ36N2IQANUB5XVYOJR",
///     /* outer_fee_stroops */ 1000,
///     /* policy_fee_cap_stroops */ 10_000,
///     "Test SDF Network ; September 2015",
///     &fee_payer,
/// ).await?;
/// # Ok(()) }
/// ```
pub async fn build_and_sign_fee_bump(
    inner_envelope_xdr: &str,
    fee_source: &str,
    outer_fee_stroops: i64,
    policy_fee_cap_stroops: i64,
    network_passphrase: &str,
    fee_payer_signer: &dyn Signer,
) -> Result<String, FeeBumpError> {
    let v1_inner = decode_inner_v1(inner_envelope_xdr)?;
    validate_fee(outer_fee_stroops, policy_fee_cap_stroops, &v1_inner)?;
    let fee_source_muxed = parse_fee_source(fee_source)?;

    // Validate that fee_source matches fee_payer_signer's public key.
    //
    // A fee-bump signed by a key != fee_source fails on-chain (txBAD_AUTH).
    // We validate eagerly to catch the mismatch before signing.
    let signer_pk = fee_payer_signer
        .public_key()
        .await
        .map_err(FeeBumpError::SigningFailed)?;

    // Both fee_source and signer_pk must represent the same 32-byte ed25519 key.
    // fee_source_muxed is MuxedAccount::Ed25519(Uint256(bytes)) — extract the bytes.
    let fee_source_bytes = match &fee_source_muxed {
        MuxedAccount::Ed25519(Uint256(bytes)) => *bytes,
        _ => {
            // Muxed accounts are not currently accepted (parse_fee_source rejects them).
            return Err(FeeBumpError::InvalidFeeSource {
                detail: "only Ed25519 (G-strkey) fee_source accounts are supported".to_owned(),
            });
        }
    };
    if fee_source_bytes != signer_pk.0 {
        return Err(FeeBumpError::FeeSourceSignerMismatch);
    }

    let fee_bump_tx = build_fee_bump_tx(fee_source_muxed, outer_fee_stroops, v1_inner);

    // Build the SEP-23 TxFeeBump signature payload.
    //
    // Preimage: SHA-256(network_id || TransactionSignaturePayload {
    //     tagged_transaction: TxFeeBump(fee_bump_tx)
    // })
    //
    // This is the EnvelopeType::TxFeeBump variant of TransactionSignaturePayload,
    // using a dedicated signing site for the outer fee-bump payload
    // (distinct from the EnvelopeType::Tx variant used for inner transactions).
    let network_id_hash = Hash(Sha256::digest(network_passphrase.as_bytes()).into());
    let sig_payload = TransactionSignaturePayload {
        network_id: network_id_hash,
        tagged_transaction: TransactionSignaturePayloadTaggedTransaction::TxFeeBump(
            // Clone is required: fee_bump_tx is also moved into the outer
            // FeeBumpTransactionEnvelope below; the payload construction
            // must happen before the move.
            fee_bump_tx.clone(),
        ),
    };
    let payload_bytes =
        sig_payload
            .to_xdr(Limits::none())
            .map_err(|e| FeeBumpError::EnvelopeEncodeFailed {
                detail: format!("TransactionSignaturePayload TxFeeBump XDR encode failed: {e}"),
            })?;

    // SHA-256 the payload and sign exactly once.
    let tx_hash: [u8; 32] = Sha256::digest(&payload_bytes).into();
    let sig_bytes = fee_payer_signer
        .sign_tx_payload(&tx_hash)
        .await
        .map_err(FeeBumpError::SigningFailed)?;

    // Derive the 4-byte hint from the last 4 bytes of the 32-byte public key
    // (same mechanism as `envelope_signing::attach_signature`).
    let hint_bytes: [u8; 4] =
        signer_pk.0[28..32]
            .try_into()
            .map_err(|_| FeeBumpError::EnvelopeEncodeFailed {
                detail: "public key is not 32 bytes".to_owned(),
            })?;

    let decorated = DecoratedSignature {
        hint: SignatureHint(hint_bytes),
        signature: Signature(sig_bytes.to_vec().try_into().map_err(|_| {
            FeeBumpError::EnvelopeEncodeFailed {
                detail: "signature is not 64 bytes".to_owned(),
            }
        })?),
    };

    // Attach the signature to the OUTER FeeBumpTransactionEnvelope.
    // The inner v1 envelope (tx + its signatures) is preserved byte-for-byte.
    let fee_bump_env = TransactionEnvelope::TxFeeBump(FeeBumpTransactionEnvelope {
        tx: fee_bump_tx,
        signatures: vec![decorated]
            .try_into()
            .map_err(|_| FeeBumpError::EnvelopeEncodeFailed {
                detail: "too many signatures for VecM<DecoratedSignature, 20>".to_owned(),
            })?,
    });

    fee_bump_env
        .to_xdr_base64(Limits::none())
        .map_err(|e| FeeBumpError::EnvelopeEncodeFailed {
            detail: format!("signed FeeBumpTransactionEnvelope XDR base64 encode failed: {e}"),
        })
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Decodes `inner_envelope_xdr` and extracts the inner `TransactionV1Envelope`,
/// rejecting `TxV0` and `TxFeeBump` with a typed error.
///
/// # CAP-15 v1-guard
///
/// `FeeBumpTransactionInnerTx` has a single variant `Tx(TransactionV1Envelope)`.
/// Only `TransactionEnvelope::Tx` is accepted here; `TxV0` and `TxFeeBump`
/// return [`FeeBumpError::InnerNotV1`].
///
/// Malformed/undecodable input returns [`FeeBumpError::InnerDecodeFailed`] —
/// never a panic.
pub(crate) fn decode_inner_v1(
    inner_envelope_xdr: &str,
) -> Result<TransactionV1Envelope, FeeBumpError> {
    // The inner envelope is caller-supplied and untrusted; bounded limits
    // prevent a deeply nested auth-invocation tree from exhausting the stack.
    let envelope = TransactionEnvelope::from_xdr_base64(
        inner_envelope_xdr,
        stellar_agent_xdr_limits::untrusted_decode_limits(inner_envelope_xdr.len()),
    )
    .map_err(|e| FeeBumpError::InnerDecodeFailed {
        detail: format!("failed to decode TransactionEnvelope from base64 XDR: {e}"),
    })?;

    match envelope {
        TransactionEnvelope::Tx(v1) => Ok(v1),
        TransactionEnvelope::TxV0(_) => Err(FeeBumpError::InnerNotV1 {
            found: "TxV0".to_owned(),
        }),
        TransactionEnvelope::TxFeeBump(_) => Err(FeeBumpError::InnerNotV1 {
            found: "TxFeeBump".to_owned(),
        }),
    }
}

/// Validates `outer_fee_stroops` against both the CAP-15 rate-based lower bound
/// and the caller-supplied policy cap upper bound.
///
/// # CAP-15 fee minimum (rate-based)
///
/// The outer fee rate (`fee / (inner_ops + 1)`) must be ≥ both the minimum
/// base fee (100 stroops) AND the inner tx's fee rate.  Therefore:
///
/// ```text
/// cap15_minimum = (inner_op_count + 1) * max(MIN_BASE_FEE_STROOPS, ceil(inner_fee / inner_op_count))
/// ```
///
/// Source: stellar-core `FeeBumpTransactionFrame::commonValid` and
/// CAP-0015 §"Validity of FeeBumpTransactions"
/// (`stellar-protocol/core/cap-0015.md`, "Validity of FeeBumpTransactions").
///
/// `inner_fee` is the inner transaction's `u32 fee` field.
/// `inner_op_count` is `inner.tx.operations.len()`.
///
/// # Fail-closed
///
/// If `inner_op_count == 0` (degenerate inner tx), we use a count of 1 to
/// avoid division by zero; stellar-core would also reject such a transaction
/// (txMISSING_OPERATION), but we produce a meaningful typed error rather than
/// a panic.
fn validate_fee(
    outer_fee_stroops: i64,
    policy_fee_cap_stroops: i64,
    inner: &TransactionV1Envelope,
) -> Result<(), FeeBumpError> {
    let inner_fee = inner.tx.fee; // u32
    let inner_op_count = inner.tx.operations.len() as u32;

    // Treat zero-op inner as 1-op to avoid division by zero; stellar-core would
    // reject a zero-op inner with txMISSING_OPERATION regardless.
    let effective_op_count = inner_op_count.max(1);

    // ceil(inner_fee / effective_op_count) — use div_ceil per Rust 1.73+ stable.
    let inner_fee_rate: u64 = u64::from(inner_fee).div_ceil(u64::from(effective_op_count));

    // Rate per op must be at least MIN_BASE_FEE_STROOPS.
    let required_rate: u64 = inner_fee_rate.max(MIN_BASE_FEE_STROOPS);

    // The +1 accounts for the fee-bump's notional extra op.
    let bumped_ops = u64::from(effective_op_count) + 1;
    let cap15_minimum: u64 = required_rate.saturating_mul(bumped_ops);

    // Convert to i64 for comparison (i64::MAX is >> any realistic fee).
    let cap15_minimum_i64 = i64::try_from(cap15_minimum).unwrap_or(i64::MAX);

    if outer_fee_stroops < cap15_minimum_i64 {
        return Err(FeeBumpError::FeeBelowCap15Minimum {
            supplied: outer_fee_stroops,
            minimum: cap15_minimum_i64,
            inner_op_count,
            inner_fee,
        });
    }

    if outer_fee_stroops > policy_fee_cap_stroops {
        return Err(FeeBumpError::FeeExceedsPolicyCap {
            supplied: outer_fee_stroops,
            cap: policy_fee_cap_stroops,
        });
    }

    Ok(())
}

/// Parses a G-strkey into a `MuxedAccount::Ed25519`.
///
/// # Errors
///
/// Returns [`FeeBumpError::InvalidFeeSource`] if the string is not a valid
/// ed25519 G-strkey.  Muxed-account M-strkeys are not currently accepted.
fn parse_fee_source(fee_source: &str) -> Result<MuxedAccount, FeeBumpError> {
    let pk = stellar_strkey::ed25519::PublicKey::from_string(fee_source).map_err(|e| {
        FeeBumpError::InvalidFeeSource {
            detail: format!("invalid fee_source G-strkey '{fee_source}': {e}"),
        }
    })?;
    Ok(MuxedAccount::Ed25519(Uint256(pk.0)))
}

/// Constructs a `FeeBumpTransaction` from the validated components.
///
/// The inner `TransactionV1Envelope` is wrapped in
/// `FeeBumpTransactionInnerTx::Tx(v1)` — the sole variant of
/// `FeeBumpTransactionInnerTx` per CAP-15.
///
/// The `fee` field is `i64` as defined in the XDR schema for `FeeBumpTransaction`.
///
/// `pub(crate)` so that `fee_bump_retry::compute_outer_tx_hash_hex` can reuse
/// the identical construction rather than duplicating the four XDR field
/// assignments.  No external callers need to construct an unsigned
/// `FeeBumpTransaction` directly.
pub(crate) fn build_fee_bump_tx(
    fee_source: MuxedAccount,
    outer_fee_stroops: i64,
    v1_inner: TransactionV1Envelope,
) -> FeeBumpTransaction {
    FeeBumpTransaction {
        fee_source,
        fee: outer_fee_stroops,
        // FeeBumpTransactionInnerTx::Tx is the SOLE variant (CAP-15 v1-only).
        inner_tx: FeeBumpTransactionInnerTx::Tx(v1_inner),
        ext: FeeBumpTransactionExt::V0,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "unit tests; panics/unwraps acceptable"
    )]

    use stellar_xdr::{
        FeeBumpTransactionInnerTx, Limits, Memo, MuxedAccount, Preconditions, ReadXdr,
        SequenceNumber, TransactionEnvelope, Uint256, WriteXdr,
    };

    use super::*;
    use crate::signing::software::SoftwareSigningKey;

    // ── Test constants ────────────────────────────────────────────────────────

    const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";

    // Seed [1u8;32] → G-strkey GCFIRY65OQE7DFP5KLNS2PF2LVZMUZYJX4OZIEQ36N2IQANUB5XVYOJR
    // (verified via SoftwareSigningKey::new_from_bytes([1u8;32]).public_key())
    const FEE_PAYER_SEED: [u8; 32] = [1u8; 32];
    const FEE_PAYER_GSTRKEY: &str = "GCFIRY65OQE7DFP5KLNS2PF2LVZMUZYJX4OZIEQ36N2IQANUB5XVYOJR";

    // A second key for inner tx source (seed [2u8;32]).
    // G-strkey derived from seed [2u8;32] via ed25519-dalek.
    const INNER_SOURCE_SEED: [u8; 32] = [2u8; 32];

    // ── Helper: build a minimal TransactionV1Envelope ────────────────────────

    /// Builds a valid inner `TransactionEnvelope::Tx(v1)` with `op_count`
    /// payment operations (the XDR is structurally valid; the signatures are
    /// placeholder zeros since we don't submit to the network in unit tests).
    ///
    /// The inner tx fee is `per_op_fee * op_count` (u32).
    fn make_inner_v1_xdr(op_count: u32, per_op_fee: u32) -> String {
        use stellar_xdr::{
            Asset, Memo, MuxedAccount, Operation, OperationBody, PaymentOp, SequenceNumber,
            Transaction, TransactionEnvelope, TransactionExt, TransactionV1Envelope, Uint256,
        };

        let inner_pk = ed25519_dalek::SigningKey::from_bytes(&INNER_SOURCE_SEED)
            .verifying_key()
            .to_bytes();
        let dst_pk = ed25519_dalek::SigningKey::from_bytes(&FEE_PAYER_SEED)
            .verifying_key()
            .to_bytes();

        let ops: Vec<Operation> = (0..op_count)
            .map(|_| Operation {
                source_account: None,
                body: OperationBody::Payment(PaymentOp {
                    destination: MuxedAccount::Ed25519(Uint256(dst_pk)),
                    asset: Asset::Native,
                    amount: 1_000_000,
                }),
            })
            .collect();

        let tx = Transaction {
            source_account: MuxedAccount::Ed25519(Uint256(inner_pk)),
            fee: per_op_fee * op_count,
            seq_num: SequenceNumber(1),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: ops.try_into().expect("op count within VecM cap"),
            ext: TransactionExt::V0,
        };

        let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: vec![].try_into().expect("empty sigs"),
        });
        envelope
            .to_xdr_base64(Limits::none())
            .expect("encode inner v1 envelope")
    }

    /// Builds a `TransactionEnvelope::TxV0` XDR string (degenerate v0 envelope).
    fn make_inner_v0_xdr() -> String {
        use stellar_xdr::{
            TransactionEnvelope, TransactionV0, TransactionV0Envelope, TransactionV0Ext, Uint256,
        };
        let envelope = TransactionEnvelope::TxV0(TransactionV0Envelope {
            tx: TransactionV0 {
                source_account_ed25519: Uint256([0u8; 32]),
                fee: 100,
                seq_num: SequenceNumber(1),
                time_bounds: None,
                memo: Memo::None,
                operations: vec![].try_into().expect("empty ops"),
                ext: TransactionV0Ext::V0,
            },
            signatures: vec![].try_into().expect("empty sigs"),
        });
        envelope.to_xdr_base64(Limits::none()).expect("encode v0")
    }

    /// Builds a `TransactionEnvelope::TxFeeBump` XDR string (nested fee-bump).
    fn make_inner_fee_bump_xdr() -> String {
        use stellar_xdr::{
            FeeBumpTransaction, FeeBumpTransactionEnvelope, FeeBumpTransactionExt,
            FeeBumpTransactionInnerTx, Memo, MuxedAccount, Preconditions, SequenceNumber,
            Transaction, TransactionEnvelope, TransactionExt, TransactionV1Envelope, Uint256,
        };
        let inner = TransactionV1Envelope {
            tx: Transaction {
                source_account: MuxedAccount::Ed25519(Uint256([0u8; 32])),
                fee: 100,
                seq_num: SequenceNumber(1),
                cond: Preconditions::None,
                memo: Memo::None,
                operations: vec![].try_into().expect("empty ops"),
                ext: TransactionExt::V0,
            },
            signatures: vec![].try_into().expect("empty sigs"),
        };
        let fb_env = TransactionEnvelope::TxFeeBump(FeeBumpTransactionEnvelope {
            tx: FeeBumpTransaction {
                fee_source: MuxedAccount::Ed25519(Uint256([0u8; 32])),
                fee: 200,
                inner_tx: FeeBumpTransactionInnerTx::Tx(inner),
                ext: FeeBumpTransactionExt::V0,
            },
            signatures: vec![].try_into().expect("empty sigs"),
        });
        fb_env
            .to_xdr_base64(Limits::none())
            .expect("encode fee_bump")
    }

    // ── Tests: v1 guard ───────────────────────────────────────────────────────

    /// build_fee_bump on a TxV0 envelope returns InnerNotV1 before construction.
    #[test]
    fn v1_guard_rejects_txv0() {
        let inner_xdr = make_inner_v0_xdr();
        let result = build_fee_bump(
            &inner_xdr,
            FEE_PAYER_GSTRKEY,
            /* outer_fee_stroops */ 1000,
            /* policy_fee_cap_stroops */ 100_000,
        );
        match result {
            Err(FeeBumpError::InnerNotV1 { found }) => {
                assert_eq!(found, "TxV0");
            }
            other => panic!("expected InnerNotV1(TxV0), got {other:?}"),
        }
    }

    /// build_fee_bump on a TxFeeBump envelope returns InnerNotV1 before construction.
    #[test]
    fn v1_guard_rejects_txfeebump() {
        let inner_xdr = make_inner_fee_bump_xdr();
        let result = build_fee_bump(
            &inner_xdr,
            FEE_PAYER_GSTRKEY,
            /* outer_fee_stroops */ 1000,
            /* policy_fee_cap_stroops */ 100_000,
        );
        match result {
            Err(FeeBumpError::InnerNotV1 { found }) => {
                assert_eq!(found, "TxFeeBump");
            }
            other => panic!("expected InnerNotV1(TxFeeBump), got {other:?}"),
        }
    }

    /// build_fee_bump on malformed base64 returns InnerDecodeFailed (not a panic).
    #[test]
    fn v1_guard_malformed_base64() {
        let result = build_fee_bump(
            "not-valid-base64!!!",
            FEE_PAYER_GSTRKEY,
            /* outer_fee_stroops */ 1000,
            /* policy_fee_cap_stroops */ 100_000,
        );
        assert!(
            matches!(result, Err(FeeBumpError::InnerDecodeFailed { .. })),
            "expected InnerDecodeFailed, got {result:?}"
        );
    }

    /// build_fee_bump on a valid Tx(v1) envelope succeeds.
    #[test]
    fn v1_guard_accepts_txv1() {
        let inner_xdr = make_inner_v1_xdr(1, 100);
        let result = build_fee_bump(
            &inner_xdr,
            FEE_PAYER_GSTRKEY,
            /* outer_fee_stroops */ 300,
            /* policy_fee_cap_stroops */ 100_000,
        );
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    // ── Tests: structure ──────────────────────────────────────────────────────

    /// Decode the built FeeBumpTransactionEnvelope and assert structural invariants.
    ///
    /// Asserts:
    /// - `fee_source` == the supplied G-strkey (as Ed25519 bytes).
    /// - `fee` == `outer_fee_stroops`.
    /// - `inner_tx` == the original inner envelope bytes (byte-for-byte).
    #[test]
    fn structure_fee_source_fee_inner_preserved() {
        let inner_xdr = make_inner_v1_xdr(2, 100); // 2 ops × 100 = fee 200
        let outer_fee = 600i64; // satisfies CAP-15 minimum for 2 ops
        let result = build_fee_bump(
            &inner_xdr,
            FEE_PAYER_GSTRKEY,
            outer_fee,
            /* policy_fee_cap_stroops */ 100_000,
        );
        let fee_bump_xdr = result.expect("build_fee_bump should succeed");

        let envelope =
            TransactionEnvelope::from_xdr_base64(&fee_bump_xdr, Limits::none()).expect("decode");
        let fb_env = match envelope {
            TransactionEnvelope::TxFeeBump(fb) => fb,
            other => panic!("expected TxFeeBump, got {other:?}"),
        };

        // fee == outer_fee_stroops
        assert_eq!(fb_env.tx.fee, outer_fee);

        // fee_source == FEE_PAYER_GSTRKEY as Ed25519 bytes
        let expected_pk =
            stellar_strkey::ed25519::PublicKey::from_string(FEE_PAYER_GSTRKEY).expect("pk");
        assert_eq!(
            fb_env.tx.fee_source,
            MuxedAccount::Ed25519(Uint256(expected_pk.0))
        );

        // inner_tx bytes == original inner envelope bytes
        let inner_tx_xdr = match &fb_env.tx.inner_tx {
            FeeBumpTransactionInnerTx::Tx(v1) => TransactionEnvelope::Tx(v1.clone())
                .to_xdr_base64(Limits::none())
                .expect("re-encode inner"),
        };
        assert_eq!(
            inner_tx_xdr, inner_xdr,
            "inner tx must be preserved byte-for-byte"
        );

        // Outer signatures vec is empty (unsigned envelope)
        assert_eq!(fb_env.signatures.len(), 0);
    }

    // ── Tests: fee cap ────────────────────────────────────────────────────────

    /// build_fee_bump with fee below CAP-15 minimum returns FeeBelowCap15Minimum.
    ///
    /// CAP-15 minimum for 1 op, inner_fee=100: (1+1)*max(100, ceil(100/1)) = 2*100 = 200.
    #[test]
    fn fee_cap_below_cap15_minimum_rejected() {
        let inner_xdr = make_inner_v1_xdr(1, 100); // 1 op, fee=100
        // Minimum = (1+1) * max(100, ceil(100/1)) = 200; supply 199 to trigger.
        let result = build_fee_bump(
            &inner_xdr,
            FEE_PAYER_GSTRKEY,
            /* outer_fee_stroops */ 199,
            /* policy_fee_cap_stroops */ 100_000,
        );
        assert!(
            matches!(
                result,
                Err(FeeBumpError::FeeBelowCap15Minimum {
                    supplied: 199,
                    minimum: 200,
                    ..
                })
            ),
            "expected FeeBelowCap15Minimum(supplied=199, minimum=200), got {result:?}"
        );
    }

    /// build_fee_bump with fee above policy cap returns FeeExceedsPolicyCap.
    #[test]
    fn fee_cap_above_policy_cap_rejected() {
        let inner_xdr = make_inner_v1_xdr(1, 100);
        let result = build_fee_bump(
            &inner_xdr,
            FEE_PAYER_GSTRKEY,
            /* outer_fee_stroops */ 5000,
            /* policy_fee_cap_stroops */ 1000,
        );
        assert!(
            matches!(
                result,
                Err(FeeBumpError::FeeExceedsPolicyCap {
                    supplied: 5000,
                    cap: 1000,
                })
            ),
            "expected FeeExceedsPolicyCap, got {result:?}"
        );
    }

    /// build_fee_bump with fee exactly at CAP-15 minimum and below policy cap succeeds.
    #[test]
    fn fee_cap_valid_mid_range_accepted() {
        let inner_xdr = make_inner_v1_xdr(2, 100); // 2 ops, fee=200
        // CAP-15 min = (2+1) * max(100, ceil(200/2)) = 3 * 100 = 300
        let result = build_fee_bump(
            &inner_xdr,
            FEE_PAYER_GSTRKEY,
            /* outer_fee_stroops */ 300,
            /* policy_fee_cap_stroops */ 100_000,
        );
        assert!(
            result.is_ok(),
            "expected Ok at exactly cap15 minimum, got {result:?}"
        );
    }

    /// CAP-15 minimum with high inner fee rate (congestion): rate-based formula
    /// produces a minimum higher than inner_fee.
    ///
    /// inner_fee = 1000, op_count = 2 → rate = 500 > 100.
    /// cap15_minimum = (2+1) * 500 = 1500.
    #[test]
    fn fee_cap_high_inner_fee_rate_correctly_enforced() {
        let inner_xdr = make_inner_v1_xdr(2, 500); // 2 ops, fee=1000
        // cap15_minimum = 3 * max(100, ceil(1000/2)) = 3 * 500 = 1500
        // Supply 1499 to trigger rejection.
        let result = build_fee_bump(
            &inner_xdr,
            FEE_PAYER_GSTRKEY,
            /* outer_fee_stroops */ 1499,
            /* policy_fee_cap_stroops */ 100_000,
        );
        assert!(
            matches!(
                result,
                Err(FeeBumpError::FeeBelowCap15Minimum {
                    supplied: 1499,
                    minimum: 1500,
                    ..
                })
            ),
            "expected FeeBelowCap15Minimum(1499, 1500), got {result:?}"
        );

        // Supply 1500: should succeed.
        let result2 = build_fee_bump(
            &inner_xdr,
            FEE_PAYER_GSTRKEY,
            /* outer_fee_stroops */ 1500,
            /* policy_fee_cap_stroops */ 100_000,
        );
        assert!(result2.is_ok(), "expected Ok at 1500, got {result2:?}");
    }

    // ── Tests: sign ───────────────────────────────────────────────────────────

    /// build_and_sign_fee_bump attaches exactly one fee-payer signature to the
    /// OUTER signatures vec; the inner v1 signatures are unchanged.
    #[tokio::test]
    async fn sign_attaches_one_outer_signature_inner_unchanged() {
        let inner_xdr = make_inner_v1_xdr(1, 100); // 1 op, fee=100
        let fee_payer = SoftwareSigningKey::new_from_bytes(FEE_PAYER_SEED);

        let signed_xdr = build_and_sign_fee_bump(
            &inner_xdr,
            FEE_PAYER_GSTRKEY,
            /* outer_fee_stroops */ 300,
            /* policy_fee_cap_stroops */ 100_000,
            TESTNET_PASSPHRASE,
            &fee_payer,
        )
        .await
        .expect("build_and_sign_fee_bump should succeed");

        // Decode the signed fee-bump envelope.
        let envelope =
            TransactionEnvelope::from_xdr_base64(&signed_xdr, Limits::none()).expect("decode");
        let fb_env = match envelope {
            TransactionEnvelope::TxFeeBump(fb) => fb,
            other => panic!("expected TxFeeBump, got {other:?}"),
        };

        // Exactly ONE signature in the OUTER vec.
        assert_eq!(
            fb_env.signatures.len(),
            1,
            "expected exactly 1 fee-payer signature on the outer envelope"
        );

        // The inner v1 signatures vec is unchanged (empty in this case,
        // since make_inner_v1_xdr produces an unsigned inner).
        let inner_sigs = match &fb_env.tx.inner_tx {
            FeeBumpTransactionInnerTx::Tx(v1) => v1.signatures.len(),
        };
        assert_eq!(
            inner_sigs, 0,
            "inner envelope signatures must be preserved byte-for-byte (empty here)"
        );

        // Verify the outer signature hint matches the fee-payer public key's last 4 bytes.
        let pk = stellar_strkey::ed25519::PublicKey::from_string(FEE_PAYER_GSTRKEY).expect("pk");
        let expected_hint = &pk.0[28..32];
        assert_eq!(
            fb_env.signatures[0].hint.0, expected_hint,
            "outer signature hint must match fee-payer public key last 4 bytes"
        );
    }

    /// build_and_sign_fee_bump with fee_source != signer public key returns
    /// FeeSourceSignerMismatch before signing.
    #[tokio::test]
    async fn sign_fee_source_mismatch_rejected() {
        let inner_xdr = make_inner_v1_xdr(1, 100);
        // Use a different signer (seed [2u8;32]) but claim the fee_payer's G-strkey.
        let wrong_signer = SoftwareSigningKey::new_from_bytes(INNER_SOURCE_SEED);

        let result = build_and_sign_fee_bump(
            &inner_xdr,
            FEE_PAYER_GSTRKEY, // claims fee_payer G-strkey
            /* outer_fee_stroops */ 300,
            /* policy_fee_cap_stroops */ 100_000,
            TESTNET_PASSPHRASE,
            &wrong_signer, // but signs with inner source key
        )
        .await;

        assert!(
            matches!(result, Err(FeeBumpError::FeeSourceSignerMismatch)),
            "expected FeeSourceSignerMismatch, got {result:?}"
        );
    }

    /// build_fee_bump with a muxed M-strkey as fee_source returns InvalidFeeSource.
    ///
    /// Only plain Ed25519 G-strkeys are accepted as fee_source.  Muxed accounts
    /// are rejected before construction because the binding check in
    /// build_and_sign_fee_bump compares against the signer's plain ed25519 key,
    /// and allowing muxed fee_source would silently pass the parse step then fail
    /// at the binding check with a misleading error.  Explicit rejection at
    /// parse_fee_source is the clearer path.
    #[test]
    fn fee_source_muxed_strkey_rejected() {
        let inner_xdr = make_inner_v1_xdr(1, 100);
        // A syntactically valid muxed M-strkey (64-byte muxed account format).
        // stellar_strkey::ed25519::MuxedAccount encodes a G-key + u64 mux ID.
        // Any M-strkey is sufficient to test that parse_fee_source rejects it.
        let muxed_strkey = "MA7QYNF7SOWQ3GLR2BGMZEHXR6DROW7HY3A3ZB3BNYB3QAVYUHX3AAAAAAAAAAAPCIBORA";
        let result = build_fee_bump(
            &inner_xdr,
            muxed_strkey,
            /* outer_fee_stroops */ 300,
            /* policy_fee_cap_stroops */ 100_000,
        );
        assert!(
            matches!(result, Err(FeeBumpError::InvalidFeeSource { .. })),
            "muxed M-strkey as fee_source must be rejected with InvalidFeeSource, got {result:?}"
        );
    }

    /// build_and_sign_fee_bump preserves inner signatures byte-for-byte when the
    /// inner v1 envelope already carries DecoratedSignatures before fee-bumping.
    ///
    /// The fee-bump only wraps the inner envelope — it MUST NOT strip, reorder,
    /// or mutate the inner signatures.  This test encodes an inner envelope with
    /// a synthetic (invalid but structurally correct) DecoratedSignature, fee-bumps
    /// it, decodes the result, and asserts the inner signatures are byte-for-byte
    /// equal to the originals.
    #[tokio::test]
    async fn sign_inner_existing_signatures_preserved_byte_for_byte() {
        use stellar_xdr::{
            DecoratedSignature, Memo, MuxedAccount, Operation, OperationBody, PaymentOp,
            Preconditions, SequenceNumber, Signature, SignatureHint, Transaction, TransactionExt,
            TransactionV1Envelope, Uint256,
        };

        // Build an inner tx with a pre-existing synthetic DecoratedSignature.
        // The signature bytes are not cryptographically valid, but structural
        // preservation does not require validity — we are testing the wrapper,
        // not the verifier.
        let inner_pk = ed25519_dalek::SigningKey::from_bytes(&INNER_SOURCE_SEED)
            .verifying_key()
            .to_bytes();
        let dst_pk = ed25519_dalek::SigningKey::from_bytes(&FEE_PAYER_SEED)
            .verifying_key()
            .to_bytes();

        let op = Operation {
            source_account: None,
            body: OperationBody::Payment(PaymentOp {
                destination: MuxedAccount::Ed25519(Uint256(dst_pk)),
                asset: stellar_xdr::Asset::Native,
                amount: 1_000_000,
            }),
        };
        let inner_tx = Transaction {
            source_account: MuxedAccount::Ed25519(Uint256(inner_pk)),
            fee: 100,
            seq_num: SequenceNumber(1),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: vec![op].try_into().expect("1 op"),
            ext: TransactionExt::V0,
        };

        // Synthetic inner signature: hint = last 4 bytes of inner_pk, sig = [0x42;64].
        let inner_hint = SignatureHint(inner_pk[28..32].try_into().expect("4 bytes"));
        let inner_sig_bytes = vec![0x42u8; 64];
        let inner_sig = DecoratedSignature {
            hint: inner_hint.clone(),
            signature: Signature(inner_sig_bytes.clone().try_into().expect("64 bytes")),
        };

        let inner_envelope = TransactionV1Envelope {
            tx: inner_tx,
            signatures: vec![inner_sig].try_into().expect("1 inner sig"),
        };

        let inner_xdr = TransactionEnvelope::Tx(inner_envelope.clone())
            .to_xdr_base64(Limits::none())
            .expect("encode inner with signature");

        // Fee-bump with the fee-payer key.
        let fee_payer = SoftwareSigningKey::new_from_bytes(FEE_PAYER_SEED);
        let signed_xdr = build_and_sign_fee_bump(
            &inner_xdr,
            FEE_PAYER_GSTRKEY,
            /* outer_fee_stroops */ 300,
            /* policy_fee_cap_stroops */ 100_000,
            TESTNET_PASSPHRASE,
            &fee_payer,
        )
        .await
        .expect("build_and_sign_fee_bump must succeed");

        // Decode the built fee-bump and assert inner signatures are preserved.
        let envelope =
            TransactionEnvelope::from_xdr_base64(&signed_xdr, Limits::none()).expect("decode");
        let fb_env = match envelope {
            TransactionEnvelope::TxFeeBump(fb) => fb,
            other => panic!("expected TxFeeBump, got {other:?}"),
        };

        let FeeBumpTransactionInnerTx::Tx(wrapped_inner) = &fb_env.tx.inner_tx;

        // Exactly 1 inner signature (the original synthetic one).
        assert_eq!(
            wrapped_inner.signatures.len(),
            1,
            "inner signature count must be preserved (1), got {}",
            wrapped_inner.signatures.len()
        );

        // The inner signature hint and bytes must match exactly.
        let wrapped_sig = &wrapped_inner.signatures[0];
        assert_eq!(
            wrapped_sig.hint.0, inner_hint.0,
            "inner signature hint must be byte-for-byte preserved"
        );
        assert_eq!(
            wrapped_sig.signature.as_slice(),
            inner_sig_bytes.as_slice(),
            "inner signature bytes must be byte-for-byte preserved"
        );

        // The outer envelope carries exactly 1 fee-payer signature.
        assert_eq!(
            fb_env.signatures.len(),
            1,
            "outer envelope must have exactly 1 fee-payer signature"
        );
    }
}
