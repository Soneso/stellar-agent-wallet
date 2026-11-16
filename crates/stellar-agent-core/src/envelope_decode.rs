//! Authoritative argument re-derivation from HMAC-bound `envelope_xdr`.
//!
//! At `_commit` time the policy engine MUST evaluate the fields that were
//! actually encoded in the nonce-bound XDR envelope, not the caller-supplied
//! args.  An attacker who mutates args between simulate and commit would
//! otherwise be able to subvert the policy decision even though the HMAC and
//! divergence checks ultimately catch the tampered envelope.
//!
//! This module provides [`decode_authoritative_args`], which decodes the XDR,
//! extracts the single operation, and renders a `serde_json::Value` in the same
//! shape that `WalletServer::dispatch_gate` forwards to the
//! `PolicyEngine::evaluate` call.
//!
//! # Value-denominated fields are decimal strings
//!
//! `amount_stroops`, `starting_balance_stroops`, and `limit_stroops` are
//! encoded as decimal strings, not JSON numbers: a JSON number backed by
//! `f64` cannot represent an `i64` stroop amount exactly once it exceeds
//! `2^53`, so a caller re-deriving these fields from a raw
//! `serde_json::Value` MUST tolerate both the string form and a legacy
//! number (see `stellar_agent_mcp::tools::amount_wire::value_as_stroops_i64`
//! for the tolerant reader). `total_fee_stroops` is the one exception: it is
//! always a JSON number. That field never crosses the MCP wire on its own —
//! it is an internal-only value consumed exclusively by the same-process
//! commit handler that called this function — so it carries no `2^53`
//! precision risk and stays numeric for readability.
//!
//! # XDR semantics — source account resolution
//!
//! In Stellar XDR a `TransactionV1Envelope` carries a transaction-level
//! `source_account` (`MuxedAccount`) on the `Transaction` struct.  Each
//! individual `Operation` MAY override that with its own optional
//! `source_account` field.  This module follows the Stellar Protocol rule:
//!
//! > If an operation's `source_account` is present, use it; otherwise fall
//! > back to the transaction-level `source_account`.
//!
//! Both `MuxedAccount::Ed25519` and `MuxedAccount::MuxedEd25519` are resolved
//! to a G-strkey by extracting the underlying ed25519 public key bytes and
//! encoding them via [`stellar_strkey::ed25519::PublicKey`].
//!
//! # Redaction discipline
//!
//! Decode failures MUST NOT echo raw XDR bytes or partial binary content.
//! All error variants carry only a short typed description or a non-sensitive
//! count / kind label — no raw byte payloads.

use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
// Error type
// ─────────────────────────────────────────────────────────────────────────────

/// Errors returned by [`decode_authoritative_args`] and [`classic_summary`].
///
/// Each variant carries the minimum description needed to diagnose the failure
/// without leaking raw XDR byte content.
///
/// | Variant | When returned | Caller invariant |
/// |---------|---------------|------------------|
/// | `Base64Decode` | `envelope_xdr` string is not valid base64 | Wallet-built envelopes are base64 strings; this indicates tampered or corrupted input. |
/// | `XdrDecode` | Base64 succeeded but the XDR layer rejected the bytes | Indicates tampered input or a stale wallet build against an incompatible XDR major version. |
/// | `NotTransactionV1` | Envelope is a fee-bump or legacy transaction variant | Policy evaluation does not run on fee-bump or legacy envelopes; caller must surface a typed error. |
/// | `UnexpectedOperationCount` | Operation count is not exactly one | Wallet builds single-operation transactions; any other count indicates tampering or unsupported input. |
/// | `OperationKindMismatch` | Operation kind disagrees with the dispatched tool | Caller passed the wrong tool name, or the envelope changed between simulate and commit. |
/// | `UnsupportedTool` | Tool name is not in the recognised decoder set | Caller bug or future tool not yet wired into this decoder. |
/// | `IssuerEncodeFailed` | XDR-decoded issuer key fails strkey encoding | Should be unreachable for valid XDR; defensive guard for malformed-but-XDR-valid keys. |
/// | `AssetCodeInvalid` | An asset code holds a byte outside ASCII letters and digits, or is empty | [`classic_summary`] refuses a code an approval surface cannot show faithfully. |
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum EnvelopeDecodeError {
    /// Base64 decode of the `envelope_xdr` string failed.
    ///
    /// The error message does not include the raw bytes — only the failure
    /// kind from the base64 decoder (e.g. "invalid character at position N").
    #[error("envelope_xdr base64 decode failed: {detail}")]
    Base64Decode {
        /// Short description from the base64 decoder; no raw byte content.
        detail: String,
    },

    /// XDR decode of the `TransactionEnvelope` failed after base64 decode.
    ///
    /// The detail string is the XDR library error kind (e.g. "unexpected end
    /// of input") without any raw byte dump.
    #[error("envelope_xdr XDR decode failed: {detail}")]
    XdrDecode {
        /// Short description from the XDR decoder; no raw byte content.
        detail: String,
    },

    /// The envelope is not a `TransactionV1` (`Tx`) variant.
    ///
    /// Classic operations always produce `TransactionV1`; fee-bump and legacy
    /// envelopes are not supported at the policy-evaluation layer.
    #[error("envelope is not a TransactionV1; unsupported envelope kind")]
    NotTransactionV1,

    /// The transaction contains a number of operations other than exactly 1.
    ///
    /// The wallet always builds single-operation transactions. A count != 1
    /// indicates a tampered or unexpected envelope.
    #[error("envelope contains {count} operations; exactly 1 required")]
    UnexpectedOperationCount {
        /// The actual number of operations found.
        count: usize,
    },

    /// The single operation's `OperationBody` kind does not match the
    /// expected kind for the given `tool` name.
    ///
    /// For example, `stellar_pay_commit` expects a `Payment`,
    /// `PathPaymentStrictReceive`, or `PathPaymentStrictSend` body, but the
    /// decoded op is a `CreateAccount`.
    #[error("operation kind mismatch: tool {tool} expects {expected}, found {found}")]
    OperationKindMismatch {
        /// The tool name passed to `decode_authoritative_args`.
        tool: &'static str,
        /// The expected operation kind(s) for the tool.
        expected: &'static str,
        /// The actual operation body kind found in the envelope.
        found: String,
    },

    /// The `tool` argument is not a tool name supported by this decoder.
    ///
    /// Recognised tool names: `"stellar_pay_commit"`,
    /// `"stellar_create_account_commit"`, `"stellar_trustline_commit"`, and
    /// `"stellar_claim_commit"`.
    #[error("unsupported tool name; expected a registered classic commit tool")]
    UnsupportedTool,

    /// The asset issuer G-strkey could not be encoded.
    ///
    /// This should be unreachable for valid XDR-decoded keys (the XDR
    /// decoder enforces exact 32-byte layout) but is guarded defensively.
    #[error("asset issuer encode failed for code '{code}': {detail}")]
    IssuerEncodeFailed {
        /// The asset code for which encoding failed.
        code: String,
        /// Short description; no raw byte content.
        detail: String,
    },

    /// An asset code is not 1 to 12 ASCII letters and digits followed only
    /// by NUL padding.
    ///
    /// Returned by [`classic_summary`]; the code bytes are not echoed.
    #[error("asset code is not 1 to 12 ASCII letters and digits")]
    AssetCodeInvalid,
}

// ─────────────────────────────────────────────────────────────────────────────
// stroop-to-human formatter
// ─────────────────────────────────────────────────────────────────────────────

/// Converts an `i64` stroop amount to a human-readable decimal string with
/// exactly 7 decimal places (e.g. `10_000_000` → `"1.0000000"`).
///
/// Delegates to [`crate::amount::StellarAmount::as_xlm_decimal_string`]; kept
/// as a free function in this module since callers reach for it alongside
/// [`decode_authoritative_args`] without needing the full [`StellarAmount`](crate::amount::StellarAmount) type.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::envelope_decode::stroops_to_human;
///
/// assert_eq!(stroops_to_human(10_000_000), "1.0000000");
/// assert_eq!(stroops_to_human(1_500_000), "0.1500000");
/// assert_eq!(stroops_to_human(0), "0.0000000");
/// assert_eq!(stroops_to_human(-10_000_000), "-1.0000000");
/// ```
#[must_use]
pub fn stroops_to_human(stroops: i64) -> String {
    crate::amount::StellarAmount::from_stroops(stroops).as_xlm_decimal_string()
}

// ─────────────────────────────────────────────────────────────────────────────
// MuxedAccount → G-strkey resolver
// ─────────────────────────────────────────────────────────────────────────────

/// Resolves a `stellar_xdr::MuxedAccount` to a canonical G-strkey.
///
/// Both `Ed25519` and `MuxedEd25519` variants contain an ed25519 public-key
/// component; this function extracts that 32-byte array and encodes it as a
/// G-strkey via [`stellar_strkey::ed25519::PublicKey`].
///
/// `MuxedEd25519` carries an additional `id`, which this function discards.
/// It resolves source accounts: every M address of an account signs with
/// the same key and spends from the same account entry. Payment destinations
/// keep the complete M address through `muxed_account_to_display_strkey`.
///
/// This function is **infallible** for inputs from XDR decode: the XDR decoder
/// enforces exact 32-byte layout for ed25519 keys, and `format!("{}", PublicKey(bytes))`
/// never fails for a 32-byte array.
fn muxed_account_to_strkey(muxed: &stellar_xdr::MuxedAccount) -> String {
    let key_bytes: [u8; 32] = match muxed {
        stellar_xdr::MuxedAccount::Ed25519(uint256) => uint256.0,
        stellar_xdr::MuxedAccount::MuxedEd25519(med) => med.ed25519.0,
    };
    // `stellar_strkey::ed25519::PublicKey::to_string` returns `heapless::String`
    // (not `std::string::String`); use the `Display` impl via `format!` to
    // obtain an owned heap allocation.  Never fails for well-formed 32-byte keys.
    format!("{}", stellar_strkey::ed25519::PublicKey(key_bytes))
}

/// Resolves a `stellar_xdr::AccountId` (newtype over `PublicKey`) to a
/// G-strkey.
///
/// This function is **infallible** for inputs from XDR decode — see
/// [`muxed_account_to_strkey`] for the rationale.
fn account_id_to_strkey(account_id: &stellar_xdr::AccountId) -> String {
    let stellar_xdr::AccountId(ref pk) = *account_id;
    match pk {
        stellar_xdr::PublicKey::PublicKeyTypeEd25519(uint256) => {
            // Same `heapless::String` → `std::string::String` conversion as
            // in `muxed_account_to_strkey`.
            format!("{}", stellar_strkey::ed25519::PublicKey(uint256.0))
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// XDR asset → "CODE:Gissuer" / "XLM" string
// ─────────────────────────────────────────────────────────────────────────────

/// Converts a `stellar_xdr::Asset` to the string form used in the
/// policy-engine args JSON.
///
/// - `Asset::Native` → `"XLM"`.
/// - `Asset::CreditAlphanum4` → `"CODE:Gissuer"`.
/// - `Asset::CreditAlphanum12` → `"CODE:Gissuer"`.
///
/// The asset code is trimmed of trailing null bytes (XDR pads fixed-length
/// code fields to 4 or 12 bytes with `\0`).
///
/// # Errors
///
/// Returns [`EnvelopeDecodeError::IssuerEncodeFailed`] if the issuer
/// G-strkey cannot be encoded (defensive; unreachable for valid XDR-decoded
/// keys — the XDR decoder enforces exact 32-byte layout).
fn xdr_asset_to_string(asset: &stellar_xdr::Asset) -> Result<String, EnvelopeDecodeError> {
    match asset {
        stellar_xdr::Asset::Native => Ok("XLM".to_owned()),
        stellar_xdr::Asset::CreditAlphanum4(a) => {
            let code = std::str::from_utf8(&a.asset_code.0)
                .unwrap_or("")
                .trim_end_matches('\0')
                .to_owned();
            // account_id_to_strkey is infallible for XDR-decoded keys.
            let issuer = account_id_to_strkey(&a.issuer);
            Ok(format!("{code}:{issuer}"))
        }
        stellar_xdr::Asset::CreditAlphanum12(a) => {
            let code = std::str::from_utf8(&a.asset_code.0)
                .unwrap_or("")
                .trim_end_matches('\0')
                .to_owned();
            // account_id_to_strkey is infallible for XDR-decoded keys.
            let issuer = account_id_to_strkey(&a.issuer);
            Ok(format!("{code}:{issuer}"))
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Public entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Returns the effective G-strkey source of a single-operation v1 envelope.
///
/// The operation source overrides the transaction source.
///
/// # Errors
/// Returns an error for malformed XDR, other envelope kinds, or operation counts.
pub fn envelope_source_account(envelope_xdr_b64: &str) -> Result<String, EnvelopeDecodeError> {
    decode_single_operation(envelope_xdr_b64).map(|(_, _, source)| source)
}

/// The kind of a transaction memo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MemoKind {
    /// `Memo::None`: the transaction carries no memo.
    None,
    /// `Memo::Text`.
    Text,
    /// `Memo::Id`.
    Id,
    /// `Memo::Hash`.
    Hash,
    /// `Memo::Return`.
    Return,
}

/// The memo kind of a single-payment envelope and the form of its
/// destination.
///
/// [`decode_authoritative_args`] reports an id memo as `memo: null`, so the
/// absence of a memo cannot be read from its output. This shape keeps the
/// memo kind and whether the destination is an M address. The output's
/// `destination` holds the complete M address with its ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct PaymentMemoShape {
    /// The transaction's memo kind.
    pub memo: MemoKind,
    /// Whether the payment's destination is an M address, whose ID names a
    /// recipient within its base G account.
    pub destination_muxed: bool,
}

/// Returns the memo kind and the destination form of a single-operation v1
/// payment envelope: a plain payment or a strict-send or strict-receive path
/// payment.
///
/// The decode is bounded like [`decode_authoritative_args`].
///
/// # Errors
/// Returns an error for malformed XDR, other envelope kinds, operation counts
/// other than one, or an operation that is not a payment.
pub fn payment_memo_shape(
    envelope_xdr_b64: &str,
    tool: &'static str,
) -> Result<PaymentMemoShape, EnvelopeDecodeError> {
    use stellar_xdr::{Memo, MuxedAccount, OperationBody};
    let (tx, op, _) = decode_single_operation(envelope_xdr_b64)?;
    let destination = match &op.body {
        OperationBody::Payment(p) => &p.destination,
        OperationBody::PathPaymentStrictReceive(pp) => &pp.destination,
        OperationBody::PathPaymentStrictSend(pp) => &pp.destination,
        other => {
            return Err(EnvelopeDecodeError::OperationKindMismatch {
                tool,
                expected: "Payment, PathPaymentStrictReceive, or PathPaymentStrictSend",
                found: op_body_kind_name(other).to_owned(),
            });
        }
    };
    let memo = match tx.memo {
        Memo::None => MemoKind::None,
        Memo::Text(_) => MemoKind::Text,
        Memo::Id(_) => MemoKind::Id,
        Memo::Hash(_) => MemoKind::Hash,
        Memo::Return(_) => MemoKind::Return,
    };
    Ok(PaymentMemoShape {
        memo,
        destination_muxed: matches!(destination, MuxedAccount::MuxedEd25519(_)),
    })
}

/// The accepted form of a caller-supplied transaction envelope.
///
/// A decoder error quotes a byte of the input, so a refusal states this form
/// in its place.
pub const TRANSACTION_ENVELOPE_XDR_FORM: &str = "must be base64-encoded TransactionEnvelope XDR";

// This local input budget includes base64 whitespace. The protocol's Soroban
// byte limit is configurable through ConfigSettingContractBandwidthV0.tx_max_size_bytes.
pub(crate) const MAX_ENVELOPE_BASE64_LEN: usize = 2 * 1024 * 1024;
pub(crate) const ENVELOPE_INPUT_TOO_LONG: &str = "the envelope exceeds the input length limit";

#[derive(Debug)]
pub(crate) enum EnvelopeReadError {
    InputTooLong,
    Xdr(stellar_xdr::Error),
}

/// Reads an envelope within fixed input and protocol collection bounds.
///
/// `stellar-xdr` limits `Transaction.operations` to 100 and `CreateClaimableBalanceOp.claimants` to 10.
/// Its `VecM::read_xdr` checks each bound before reading the collection's elements.
pub(crate) fn read_envelope(
    envelope_xdr_b64: &str,
) -> Result<stellar_xdr::TransactionEnvelope, EnvelopeReadError> {
    use stellar_xdr::ReadXdr;

    if envelope_xdr_b64.len() > MAX_ENVELOPE_BASE64_LEN {
        return Err(EnvelopeReadError::InputTooLong);
    }
    stellar_xdr::TransactionEnvelope::from_xdr_base64(
        envelope_xdr_b64,
        stellar_agent_xdr_limits::untrusted_decode_limits(envelope_xdr_b64.len()),
    )
    .map_err(EnvelopeReadError::Xdr)
}

/// The accepted form of a caller-supplied `ScVal`, in the place of a decoder
/// error that quotes a byte of the input.
pub const SCVAL_XDR_FORM: &str = "must be base64-encoded ScVal XDR";

/// Describes a decode failure of a caller-supplied envelope by its class.
///
/// `stellar_xdr` reads the base64 text through an I/O reader, and the base64
/// decoder's error inside that I/O error quotes the offending symbol of the
/// envelope, so every I/O failure maps to a fixed text. The other variants
/// render a fixed text or a byte position, never envelope content.
fn describe_xdr_decode_error(error: &stellar_xdr::Error) -> String {
    match error {
        stellar_xdr::Error::Io(io) if io.kind() == std::io::ErrorKind::InvalidData => {
            "the envelope is not valid standard base64".to_owned()
        }
        stellar_xdr::Error::Io(io) if io.kind() == std::io::ErrorKind::UnexpectedEof => {
            "the envelope ends before the value is complete".to_owned()
        }
        stellar_xdr::Error::Io(_) => "the envelope could not be read".to_owned(),
        other => other.to_string(),
    }
}

fn decode_single_operation(
    envelope_xdr_b64: &str,
) -> Result<(stellar_xdr::Transaction, stellar_xdr::Operation, String), EnvelopeDecodeError> {
    use stellar_xdr::TransactionEnvelope;
    let envelope = read_envelope(envelope_xdr_b64).map_err(|e| EnvelopeDecodeError::XdrDecode {
        detail: match e {
            EnvelopeReadError::InputTooLong => ENVELOPE_INPUT_TOO_LONG.to_owned(),
            EnvelopeReadError::Xdr(error) => describe_xdr_decode_error(&error),
        },
    })?;

    // 3. Extract the TransactionV1 body.
    let tx = match envelope {
        TransactionEnvelope::Tx(v1) => v1.tx,
        // FeeBump and legacy Tx envelopes are not produced by the wallet and
        // are not handled by the policy layer.
        _ => return Err(EnvelopeDecodeError::NotTransactionV1),
    };

    // 4. Enforce exactly-1-operation invariant.
    if tx.operations.len() != 1 {
        return Err(EnvelopeDecodeError::UnexpectedOperationCount {
            count: tx.operations.len(),
        });
    }
    // SAFETY: len == 1 asserted above; index 0 is valid.
    let op = tx.operations[0].clone();

    // 5. Resolve the effective source account (op-level overrides tx-level).
    let effective_source_muxed: &stellar_xdr::MuxedAccount = match &op.source_account {
        Some(op_src) => op_src,
        None => &tx.source_account,
    };
    // muxed_account_to_strkey is infallible for XDR-decoded keys.
    let source_strkey = muxed_account_to_strkey(effective_source_muxed);

    Ok((tx, op, source_strkey))
}

/// Decodes a base64 XDR `TransactionEnvelope` and extracts authoritative
/// operation fields for the named `tool`.
///
/// The returned `serde_json::Value` is shaped identically to the
/// `args_value` object that the `*_commit` handlers currently build from
/// caller-supplied args.  Passing this to `dispatch_gate` ensures the policy
/// engine evaluates the fields that are **actually encoded in the
/// HMAC-bound envelope** rather than the attacker-controllable commit args.
///
/// # Returned shape for `"stellar_pay_commit"`
///
/// ```json
/// {
///   "chain_id": "<from caller — not encoded in XDR>",
///   "source": "G...",
///   "total_fee_stroops": <u32>,
///   "sequence_number": <i64>,
///   "destination": "G..." | "M...",
///   "amount_stroops": "<decimal i64 stroops>",
///   "asset": "XLM" | "CODE:Gissuer",
///   "memo": "text" | null,
///   "memo_kind": "none" | "text" | "id" | "hash" | "return",
///   "memo_id": "<canonical u64 decimal, only for Memo::Id>",
///   "memo_hash": "<64 lowercase hex chars, only for Memo::Hash>",
///   "memo_return": "<64 lowercase hex chars, only for Memo::Return>"
/// }
/// ```
///
/// Every supported operation also carries these memo facts. A known no-memo
/// envelope has `memo_kind = "none"` and `memo = null`. Payload fields for other
/// kinds are absent. Text must be valid UTF-8 and retains its exact bytes.
///
/// `chain_id` is **not** encoded in the XDR and must be supplied separately
/// by the caller (it is present in the outer `*CommitArgs` struct and is
/// already validated by the preceding `dispatch_gate` + CAIP-2 check).
///
/// # Returned shape for `"stellar_create_account_commit"`
///
/// ```json
/// {
///   "chain_id": "<from caller>",
///   "source": "G...",
///   "total_fee_stroops": <u32>,
///   "destination": "G...",
///   "starting_balance_stroops": "<decimal i64 stroops>"
/// }
/// ```
///
/// # Returned shape for `"stellar_trustline_commit"`
///
/// ```json
/// {
///   "chain_id": "<from caller>",
///   "source": "G...",
///   "total_fee_stroops": <u32>,
///   "asset_code": "USDC",
///   "asset_issuer": "G...",
///   "limit_stroops": "<decimal i64 stroops>"
/// }
/// ```
///
/// `limit_stroops` is the decimal string `"9223372036854775807"` (`i64::MAX`) when the caller
/// built the envelope with the Stellar "unlimited trustline" default.
/// `asset_code` is uppercase, null-trimmed.
/// `asset_issuer` is the canonical G-strkey of the issuer.
///
/// # Source account resolution
///
/// If the operation carries its own `source_account`, that account is used.
/// Otherwise the transaction-level `source_account` is used.  Both
/// `MuxedAccount::Ed25519` and `MuxedAccount::MuxedEd25519` are resolved to
/// their underlying G-strkey (mux-ID discarded; policy engine works at
/// account granularity).
///
/// # Errors
///
/// - [`EnvelopeDecodeError::UnsupportedTool`] — `tool` not in the known set.
/// - [`EnvelopeDecodeError::Base64Decode`] — `envelope_xdr_b64` is not valid base64.
/// - [`EnvelopeDecodeError::XdrDecode`] — XDR decode failed after base64 decode.
/// - [`EnvelopeDecodeError::NotTransactionV1`] — envelope is not a `Tx` v1 envelope.
/// - [`EnvelopeDecodeError::UnexpectedOperationCount`] — transaction has ≠ 1 operations.
/// - [`EnvelopeDecodeError::OperationKindMismatch`] — op body does not match the tool.
/// - [`EnvelopeDecodeError::IssuerEncodeFailed`] — asset issuer G-strkey encode error.
///   Source and destination accounts always encode: the source as its G
///   account, a payment destination as its complete G or M address.
/// - Note: `Memo::Hash` and `Memo::Return` keep `memo = null` and additionally
///   surface `memo_hash` / `memo_return`; a tampered memo XDR is still caught by
///   the caller's envelope-rebuild divergence check.
///
/// # Examples
///
/// ```rust,ignore
/// use stellar_agent_core::envelope_decode::decode_authoritative_args;
///
/// // In a stellar_pay_commit handler:
/// let auth_args = decode_authoritative_args(&args.envelope_xdr, "stellar_pay_commit")
///     .map_err(|e| rmcp::ErrorData::internal_error(
///         format!("simulation.divergence: {e}"), None))?;
/// // Use auth_args instead of caller-supplied args for policy evaluation.
/// ```
pub fn decode_authoritative_args(
    envelope_xdr_b64: &str,
    tool: &'static str,
) -> Result<serde_json::Value, EnvelopeDecodeError> {
    // 1. Validate tool name before touching the XDR (fail fast on bad tool).
    match tool {
        "stellar_pay_commit"
        | "stellar_create_account_commit"
        | "stellar_trustline_commit"
        | "stellar_claim_commit" => {}
        _ => {
            return Err(EnvelopeDecodeError::UnsupportedTool);
        }
    }

    let (tx, op, source_strkey) = decode_single_operation(envelope_xdr_b64)?;
    let op = &op;

    // 6. Dispatch by tool.
    let mut args = match tool {
        "stellar_pay_commit" => decode_pay_args(tx.fee, tx.seq_num.0, op, &source_strkey, tool),
        "stellar_create_account_commit" => {
            decode_create_account_args(tx.fee, op, &source_strkey, tool)
        }
        "stellar_trustline_commit" => decode_change_trust_args(tx.fee, op, &source_strkey, tool),
        "stellar_claim_commit" => decode_claim_args(tx.fee, op, &source_strkey, tool),
        // The validation above is exhaustive; this arm is unreachable.
        _ => unreachable!("tool name validated in step 1"),
    }?;
    for (key, value) in ClassicMemo::try_from(&tx.memo)?.policy_fields() {
        args[key] = value;
    }
    Ok(args)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool-specific decoders
// ─────────────────────────────────────────────────────────────────────────────

/// Extracts `stellar_pay` policy-engine args from a `Payment`,
/// `PathPaymentStrictReceive`, or `PathPaymentStrictSend` operation.
///
/// # Debit sizing for path payments
///
/// The wallet's spendable-balance debit for a path payment is the SEND side,
/// not the destination side: `PathPaymentStrictReceiveOp.send_max` is the
/// maximum the signer authorizes to spend (the operation fails on-chain if
/// the actual send amount would exceed it); `PathPaymentStrictSendOp.send_amount`
/// is the exact amount the signer pays. `asset` / `amount_stroops` carry this
/// send-side value for both path-payment kinds, matching the plain `Payment`
/// case where `asset` / `amount_stroops` are already the debit.
///
/// The destination side is surfaced separately as `dest_asset` /
/// `dest_amount_stroops` — informational only (what the recipient receives or
/// receives at minimum), not sized by value caps. `destination` names the
/// recipient account regardless of which asset is debited, so counterparty
/// checks are unaffected by this distinction.
fn decode_pay_args(
    total_fee_stroops: u32,
    sequence_number: i64,
    op: &stellar_xdr::Operation,
    source_strkey: &str,
    tool: &'static str,
) -> Result<serde_json::Value, EnvelopeDecodeError> {
    use stellar_xdr::OperationBody;

    enum PayShape<'a> {
        Simple {
            dest: &'a stellar_xdr::MuxedAccount,
            asset: &'a stellar_xdr::Asset,
            amount: i64,
        },
        PathPayment {
            dest: &'a stellar_xdr::MuxedAccount,
            send_asset: &'a stellar_xdr::Asset,
            send_debit_ceiling: i64,
            dest_asset: &'a stellar_xdr::Asset,
            dest_amount: i64,
        },
    }

    let shape = match &op.body {
        OperationBody::Payment(p) => PayShape::Simple {
            dest: &p.destination,
            asset: &p.asset,
            amount: p.amount,
        },

        OperationBody::PathPaymentStrictReceive(pp) => PayShape::PathPayment {
            dest: &pp.destination,
            send_asset: &pp.send_asset,
            // send_max is the maximum the signer authorizes to spend — the
            // debit ceiling for a strict-receive path payment. A value cap
            // or window-state record sized from this figure bounds the
            // AUTHORIZED spend, not necessarily the exact settled amount
            // (path payments on-chain may settle for less, never more).
            send_debit_ceiling: pp.send_max,
            dest_asset: &pp.dest_asset,
            dest_amount: pp.dest_amount,
        },

        OperationBody::PathPaymentStrictSend(pp) => PayShape::PathPayment {
            dest: &pp.destination,
            send_asset: &pp.send_asset,
            // send_amount is the exact amount the signer pays.
            send_debit_ceiling: pp.send_amount,
            dest_asset: &pp.dest_asset,
            // dest_min is the floor the recipient is guaranteed to receive;
            // the actual receive amount depends on the path at execution
            // time, so the floor is the best informational value available.
            dest_amount: pp.dest_min,
        },

        other => {
            return Err(EnvelopeDecodeError::OperationKindMismatch {
                tool,
                expected: "Payment, PathPaymentStrictReceive, or PathPaymentStrictSend",
                found: op_body_kind_name(other).to_owned(),
            });
        }
    };

    let mut args = match shape {
        PayShape::Simple {
            dest,
            asset,
            amount,
        } => {
            let dest_strkey = muxed_account_to_display_strkey(dest);
            let asset_str = xdr_asset_to_string(asset)?;
            serde_json::json!({
                "source": source_strkey,
                "total_fee_stroops": total_fee_stroops,
                "destination": dest_strkey,
                "amount_stroops": amount.to_string(),
                "asset": asset_str,
            })
        }
        PayShape::PathPayment {
            dest,
            send_asset,
            send_debit_ceiling,
            dest_asset,
            dest_amount,
        } => {
            let dest_strkey = muxed_account_to_display_strkey(dest);
            let send_asset_str = xdr_asset_to_string(send_asset)?;
            let dest_asset_str = xdr_asset_to_string(dest_asset)?;
            serde_json::json!({
                "source": source_strkey,
                "total_fee_stroops": total_fee_stroops,
                "destination": dest_strkey,
                "amount_stroops": send_debit_ceiling.to_string(),
                "asset": send_asset_str,
                "dest_amount_stroops": dest_amount.to_string(),
                "dest_asset": dest_asset_str,
            })
        }
    };
    args["sequence_number"] = sequence_number.into();
    Ok(args)
}

/// Extracts `stellar_create_account` policy-engine args from a `CreateAccount`
/// operation.
fn decode_create_account_args(
    total_fee_stroops: u32,
    op: &stellar_xdr::Operation,
    source_strkey: &str,
    tool: &'static str,
) -> Result<serde_json::Value, EnvelopeDecodeError> {
    use stellar_xdr::OperationBody;

    let ca = match &op.body {
        OperationBody::CreateAccount(ca) => ca,
        other => {
            return Err(EnvelopeDecodeError::OperationKindMismatch {
                tool,
                expected: "CreateAccount",
                found: op_body_kind_name(other).to_owned(),
            });
        }
    };

    // account_id_to_strkey is infallible for XDR-decoded keys.
    let dest_strkey = account_id_to_strkey(&ca.destination);

    Ok(serde_json::json!({
        "source": source_strkey,
        "total_fee_stroops": total_fee_stroops,
        "destination": dest_strkey,
        "starting_balance_stroops": ca.starting_balance.to_string(),
    }))
}

/// Extracts `stellar_trustline` policy-engine args from a `ChangeTrust`
/// operation.
///
/// # Returned JSON shape
///
/// ```json
/// {
///   "source": "G...",
///   "total_fee_stroops": <u32>,
///   "asset_code": "USDC",
///   "asset_issuer": "G...",
///   "limit_stroops": "<decimal i64 stroops>"
/// }
/// ```
///
/// `limit_stroops` mirrors `ChangeTrustOp.limit` exactly, as a decimal
/// string.  When the caller
/// built the envelope without an explicit limit, the baselib sets
/// `ChangeTrustOp.limit = i64::MAX` (Stellar default unlimited trustline).
///
/// # Errors
///
/// Returns [`EnvelopeDecodeError::OperationKindMismatch`] when the single
/// operation is not a `ChangeTrust`.  Returns
/// [`EnvelopeDecodeError::IssuerEncodeFailed`] if the issuer G-strkey
/// cannot be encoded (defensive; unreachable for valid XDR-decoded keys).
fn decode_change_trust_args(
    total_fee_stroops: u32,
    op: &stellar_xdr::Operation,
    source_strkey: &str,
    tool: &'static str,
) -> Result<serde_json::Value, EnvelopeDecodeError> {
    use stellar_xdr::{ChangeTrustAsset, OperationBody};

    let ct = match &op.body {
        OperationBody::ChangeTrust(ct) => ct,
        other => {
            return Err(EnvelopeDecodeError::OperationKindMismatch {
                tool,
                expected: "ChangeTrust",
                found: op_body_kind_name(other).to_owned(),
            });
        }
    };

    // Extract code and issuer from the ChangeTrustAsset.
    // ChangeTrustAsset mirrors the Asset encoding with an additional PoolShare
    // variant (see stellar-xdr generated.rs for the XDR discriminant layout).
    let (asset_code, asset_issuer) = match &ct.line {
        ChangeTrustAsset::Native => {
            // Trustlines on XLM are not valid per Stellar protocol, but handle
            // defensively so we surface a coherent args shape.
            ("XLM".to_owned(), String::new())
        }
        ChangeTrustAsset::CreditAlphanum4(a) => {
            let code = std::str::from_utf8(&a.asset_code.0)
                .unwrap_or("")
                .trim_end_matches('\0')
                .to_owned();
            // account_id_to_strkey is infallible for XDR-decoded keys.
            let issuer = account_id_to_strkey(&a.issuer);
            (code, issuer)
        }
        ChangeTrustAsset::CreditAlphanum12(a) => {
            let code = std::str::from_utf8(&a.asset_code.0)
                .unwrap_or("")
                .trim_end_matches('\0')
                .to_owned();
            let issuer = account_id_to_strkey(&a.issuer);
            (code, issuer)
        }
        ChangeTrustAsset::PoolShare(_) => {
            return Err(EnvelopeDecodeError::OperationKindMismatch {
                tool,
                expected: "ChangeTrust with credit asset",
                found: "ChangeTrust(PoolShare)".to_owned(),
            });
        }
    };

    Ok(serde_json::json!({
        "source": source_strkey,
        "total_fee_stroops": total_fee_stroops,
        "asset_code": asset_code,
        "asset_issuer": asset_issuer,
        "limit_stroops": ct.limit.to_string(),
    }))
}

/// Extracts `stellar_claim` policy-engine args from a `ClaimClaimableBalance`
/// operation.
///
/// # Returned JSON shape
///
/// ```json
/// {
///   "source": "G...",
///   "total_fee_stroops": <u32>,
///   "balance_id_hex72": "00000000<64-hex-hash>",
///   "balance_id_strkey": "B..."
/// }
/// ```
///
/// Both id renderings are re-derived from the HMAC-bound XDR (not taken from
/// caller-supplied args), matching this module's authoritative-args
/// discipline: policy evaluation and the balance-id used for the
/// commit-phase entry re-fetch both come from the envelope, not from
/// arguments an attacker could have tampered with between simulate and
/// commit.
///
/// # Errors
///
/// Returns [`EnvelopeDecodeError::OperationKindMismatch`] when the single
/// operation is not a `ClaimClaimableBalance`.
fn decode_claim_args(
    total_fee_stroops: u32,
    op: &stellar_xdr::Operation,
    source_strkey: &str,
    tool: &'static str,
) -> Result<serde_json::Value, EnvelopeDecodeError> {
    use stellar_xdr::{ClaimableBalanceId, OperationBody};

    let claim = match &op.body {
        OperationBody::ClaimClaimableBalance(c) => c,
        other => {
            return Err(EnvelopeDecodeError::OperationKindMismatch {
                tool,
                expected: "ClaimClaimableBalance",
                found: op_body_kind_name(other).to_owned(),
            });
        }
    };

    // ClaimableBalanceId currently has exactly one variant (V0); the
    // destructure below is irrefutable. If the protocol ever adds a second
    // variant, this becomes a compile error (not a silent mismatch), which
    // is the desired failure mode for a wire-format change of this kind.
    let ClaimableBalanceId::ClaimableBalanceIdTypeV0(hash) = &claim.balance_id;
    let balance_id_hex72 = format!("00000000{}", crate::hex::encode(&hash.0));
    let balance_id_strkey_heapless = stellar_strkey::ClaimableBalance::V0(hash.0).to_string();
    let balance_id_strkey = format!("{balance_id_strkey_heapless}");

    Ok(serde_json::json!({
        "source": source_strkey,
        "total_fee_stroops": total_fee_stroops,
        "balance_id_hex72": balance_id_hex72,
        "balance_id_strkey": balance_id_strkey,
    }))
}

// ─────────────────────────────────────────────────────────────────────────────
// Classic transaction summary for approval surfaces
// ─────────────────────────────────────────────────────────────────────────────

/// The classic transaction kind a pending approval holds.
///
/// Each kind names the operations its envelope may carry, the same set the
/// matching `*_commit` tool accepts in [`decode_authoritative_args`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClassicTransactionKind {
    /// A payment approval: a `Payment`, a path payment, or a `CreateAccount`.
    Payment,
    /// A `ChangeTrust` approval.
    Trustline,
    /// A `ClaimClaimableBalance` approval.
    Claim,
}

/// The memo of a classic transaction.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
#[non_exhaustive]
pub enum ClassicMemo {
    /// The transaction carries no memo.
    None,
    /// A text memo, exactly as the envelope carries it.
    Text(String),
    /// An id memo.
    Id(#[serde(with = "crate::wire_stroops::u64")] u64),
    /// A hash memo.
    Hash([u8; 32]),
    /// A return memo.
    Return([u8; 32]),
}

impl ClassicMemo {
    /// The authoritative policy facts, retaining the legacy text-or-null
    /// `memo` field. IDs are canonical decimal strings and hashes are lowercase
    /// hex, so neither integer precision nor the memo kind is lost.
    #[must_use]
    pub fn policy_fields(&self) -> serde_json::Map<String, serde_json::Value> {
        use serde_json::Value;
        let (kind, payload) = match self {
            Self::None => ("none", None),
            Self::Text(text) => ("text", Some(("memo", text.clone()))),
            Self::Id(id) => ("id", Some(("memo_id", id.to_string()))),
            Self::Hash(hash) => ("hash", Some(("memo_hash", crate::hex::encode(hash)))),
            Self::Return(hash) => ("return", Some(("memo_return", crate::hex::encode(hash)))),
        };
        let mut fields = serde_json::Map::from_iter([
            ("memo_kind".to_owned(), Value::String(kind.to_owned())),
            ("memo".to_owned(), Value::Null),
        ]);
        if let Some((key, value)) = payload {
            fields.insert(key.to_owned(), Value::String(value));
        }
        fields
    }

    /// Missing, malformed or contradictory facts carry no known memo.
    pub(crate) fn from_policy_args(args: &serde_json::Value) -> Option<Self> {
        let memo = match args.get("memo_kind")?.as_str()? {
            "none" => Self::None,
            "text" => {
                let text = args.get("memo")?.as_str()?;
                if text.len() > 28 {
                    return None;
                }
                Self::Text(text.to_owned())
            }
            "id" => Self::Id(args.get("memo_id")?.as_str()?.parse().ok()?),
            "hash" => Self::Hash(crate::hex::decode_hex32(args.get("memo_hash")?.as_str()?).ok()?),
            "return" => {
                Self::Return(crate::hex::decode_hex32(args.get("memo_return")?.as_str()?).ok()?)
            }
            _ => return None,
        };
        let expected = memo.policy_fields();
        ["memo_kind", "memo", "memo_id", "memo_hash", "memo_return"]
            .iter()
            .all(|key| args.get(*key) == expected.get(*key))
            .then_some(memo)
    }

    /// Formats the memo with its signed type. The caller escapes this text
    /// for its output surface.
    #[must_use]
    pub fn display(&self) -> String {
        match self {
            Self::None => "none".to_owned(),
            Self::Text(text) => format!("text \"{text}\""),
            Self::Id(id) => format!("id {id}"),
            Self::Hash(hash) => format!("hash {}", crate::hex::encode(hash)),
            Self::Return(hash) => format!("return {}", crate::hex::encode(hash)),
        }
    }
}

impl TryFrom<&stellar_xdr::Memo> for ClassicMemo {
    type Error = EnvelopeDecodeError;

    /// Preserves the signed kind and bytes, refusing text that is not UTF-8.
    fn try_from(memo: &stellar_xdr::Memo) -> Result<Self, Self::Error> {
        use stellar_xdr::Memo;
        Ok(match memo {
            Memo::None => Self::None,
            Memo::Text(bytes) => {
                Self::Text(String::from_utf8(bytes.as_slice().to_vec()).map_err(|_| {
                    EnvelopeDecodeError::XdrDecode {
                        detail: "memo text is not valid UTF-8".to_owned(),
                    }
                })?)
            }
            Memo::Id(id) => Self::Id(*id),
            Memo::Hash(hash) => Self::Hash(hash.0),
            Memo::Return(hash) => Self::Return(hash.0),
        })
    }
}

/// The operation of a classic transaction, with every value it moves.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClassicOperation {
    /// A `Payment`.
    Payment {
        /// The destination as the envelope names it: a G-strkey, or an
        /// M-strkey for a muxed destination.
        destination: String,
        /// `"XLM"` or `"CODE:Gissuer"`.
        asset: String,
        /// The amount in stroops.
        amount_stroops: i64,
    },
    /// A `PathPaymentStrictSend` or `PathPaymentStrictReceive`.
    PathPayment {
        /// The destination as the envelope names it.
        destination: String,
        /// The asset the source pays.
        send_asset: String,
        /// The most the source pays: `send_amount` for strict send,
        /// `send_max` for strict receive.
        send_amount_stroops: i64,
        /// The asset the destination receives.
        dest_asset: String,
        /// What the destination receives: `dest_amount` for strict receive,
        /// the floor `dest_min` for strict send.
        dest_amount_stroops: i64,
    },
    /// A `CreateAccount`.
    CreateAccount {
        /// The account created.
        destination: String,
        /// The starting balance in stroops of XLM.
        starting_balance_stroops: i64,
    },
    /// A `ChangeTrust` on a credit asset.
    ChangeTrust {
        /// The asset code.
        asset_code: String,
        /// The issuer G-strkey.
        asset_issuer: String,
        /// The limit in stroops; `None` is the unlimited limit `i64::MAX`.
        limit_stroops: Option<i64>,
    },
    /// A `ClaimClaimableBalance`.
    ClaimClaimableBalance {
        /// The canonical 72-hex balance id.
        balance_id_hex72: String,
        /// The `B...` strkey of the balance id.
        balance_id_strkey: String,
    },
}

/// The details of a single-operation classic transaction an approval surface
/// shows, every one decoded from the envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ClassicSummary {
    /// The effective source G-strkey: the operation source, else the
    /// transaction source.
    pub source: String,
    /// The transaction fee in stroops.
    pub fee_stroops: u32,
    /// The transaction sequence number.
    pub seq_num: i64,
    /// The transaction memo.
    pub memo: ClassicMemo,
    /// The single operation.
    pub operation: ClassicOperation,
}

/// Decodes the details an approval surface shows for a classic pending
/// approval from its envelope.
///
/// The decode is the one [`decode_authoritative_args`] runs: the same
/// bounded XDR read, the single-operation rule, the operation-source
/// override, and the operation kinds the matching `*_commit` tool accepts.
/// It refuses what an approval surface cannot show faithfully: a text memo
/// that is not UTF-8, an asset code that is not 1 to 12 ASCII letters and
/// digits padded with NUL bytes, and a trustline on a pool share or on XLM.
///
/// # Errors
///
/// Returns the [`EnvelopeDecodeError`] of a malformed envelope, a fee-bump
/// or legacy envelope, an operation count other than one, an operation the
/// kind does not accept, or one of the refusals above
/// ([`EnvelopeDecodeError::XdrDecode`] for the memo,
/// [`EnvelopeDecodeError::AssetCodeInvalid`] for an asset code,
/// [`EnvelopeDecodeError::OperationKindMismatch`] for the trustline asset).
pub fn classic_summary(
    envelope_xdr_b64: &str,
    kind: ClassicTransactionKind,
) -> Result<ClassicSummary, EnvelopeDecodeError> {
    use stellar_xdr::{ChangeTrustAsset, ClaimableBalanceId, OperationBody};

    let (tx, op, source) = decode_single_operation(envelope_xdr_b64)?;
    let memo = ClassicMemo::try_from(&tx.memo)?;
    let mismatch = |tool: &'static str, expected: &'static str, body: &OperationBody| {
        EnvelopeDecodeError::OperationKindMismatch {
            tool,
            expected,
            found: op_body_kind_name(body).to_owned(),
        }
    };

    let operation = match (kind, &op.body) {
        (ClassicTransactionKind::Payment, OperationBody::Payment(p)) => ClassicOperation::Payment {
            destination: muxed_account_to_display_strkey(&p.destination),
            asset: strict_asset_string(&p.asset)?,
            amount_stroops: p.amount,
        },
        (ClassicTransactionKind::Payment, OperationBody::PathPaymentStrictReceive(pp)) => {
            ClassicOperation::PathPayment {
                destination: muxed_account_to_display_strkey(&pp.destination),
                send_asset: strict_asset_string(&pp.send_asset)?,
                send_amount_stroops: pp.send_max,
                dest_asset: strict_asset_string(&pp.dest_asset)?,
                dest_amount_stroops: pp.dest_amount,
            }
        }
        (ClassicTransactionKind::Payment, OperationBody::PathPaymentStrictSend(pp)) => {
            ClassicOperation::PathPayment {
                destination: muxed_account_to_display_strkey(&pp.destination),
                send_asset: strict_asset_string(&pp.send_asset)?,
                send_amount_stroops: pp.send_amount,
                dest_asset: strict_asset_string(&pp.dest_asset)?,
                dest_amount_stroops: pp.dest_min,
            }
        }
        (ClassicTransactionKind::Payment, OperationBody::CreateAccount(ca)) => {
            ClassicOperation::CreateAccount {
                destination: account_id_to_strkey(&ca.destination),
                starting_balance_stroops: ca.starting_balance,
            }
        }
        (ClassicTransactionKind::Payment, other) => {
            return Err(mismatch(
                "stellar_pay_commit",
                "Payment, PathPaymentStrictReceive, PathPaymentStrictSend, or CreateAccount",
                other,
            ));
        }
        (ClassicTransactionKind::Trustline, OperationBody::ChangeTrust(ct)) => {
            let (code_bytes, issuer): (&[u8], _) = match &ct.line {
                ChangeTrustAsset::CreditAlphanum4(a) => (&a.asset_code.0, &a.issuer),
                ChangeTrustAsset::CreditAlphanum12(a) => (&a.asset_code.0, &a.issuer),
                ChangeTrustAsset::Native | ChangeTrustAsset::PoolShare(_) => {
                    return Err(EnvelopeDecodeError::OperationKindMismatch {
                        tool: "stellar_trustline_commit",
                        expected: "ChangeTrust with credit asset",
                        found: "ChangeTrust on a non-credit asset".to_owned(),
                    });
                }
            };
            ClassicOperation::ChangeTrust {
                asset_code: strict_asset_code(code_bytes)?,
                asset_issuer: account_id_to_strkey(issuer),
                limit_stroops: (ct.limit != i64::MAX).then_some(ct.limit),
            }
        }
        (ClassicTransactionKind::Trustline, other) => {
            return Err(mismatch("stellar_trustline_commit", "ChangeTrust", other));
        }
        (ClassicTransactionKind::Claim, OperationBody::ClaimClaimableBalance(claim)) => {
            let ClaimableBalanceId::ClaimableBalanceIdTypeV0(hash) = &claim.balance_id;
            ClassicOperation::ClaimClaimableBalance {
                balance_id_hex72: format!("00000000{}", crate::hex::encode(&hash.0)),
                balance_id_strkey: format!("{}", stellar_strkey::ClaimableBalance::V0(hash.0)),
            }
        }
        (ClassicTransactionKind::Claim, other) => {
            return Err(mismatch(
                "stellar_claim_commit",
                "ClaimClaimableBalance",
                other,
            ));
        }
    };

    Ok(ClassicSummary {
        source,
        fee_stroops: tx.fee,
        seq_num: tx.seq_num.0,
        memo,
        operation,
    })
}

/// Renders a `MuxedAccount` as the strkey it is: a G-strkey for a plain
/// account, an M-strkey (account and mux id) for a muxed one.
fn muxed_account_to_display_strkey(muxed: &stellar_xdr::MuxedAccount) -> String {
    match muxed {
        stellar_xdr::MuxedAccount::Ed25519(_) => muxed_account_to_strkey(muxed),
        stellar_xdr::MuxedAccount::MuxedEd25519(med) => format!(
            "{}",
            stellar_strkey::ed25519::MuxedAccount {
                ed25519: med.ed25519.0,
                id: med.id,
            }
        ),
    }
}

/// Renders an asset as `"XLM"` or `"CODE:Gissuer"`, refusing an asset code
/// outside the protocol's alphabet.
fn strict_asset_string(asset: &stellar_xdr::Asset) -> Result<String, EnvelopeDecodeError> {
    match asset {
        stellar_xdr::Asset::Native => Ok("XLM".to_owned()),
        stellar_xdr::Asset::CreditAlphanum4(a) => Ok(format!(
            "{}:{}",
            strict_asset_code(&a.asset_code.0)?,
            account_id_to_strkey(&a.issuer)
        )),
        stellar_xdr::Asset::CreditAlphanum12(a) => Ok(format!(
            "{}:{}",
            strict_asset_code(&a.asset_code.0)?,
            account_id_to_strkey(&a.issuer)
        )),
    }
}

/// Returns the asset code of a fixed-width XDR code field: one or more ASCII
/// letters and digits, followed only by NUL padding.
fn strict_asset_code(bytes: &[u8]) -> Result<String, EnvelopeDecodeError> {
    let len = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    let (code, padding) = bytes.split_at(len);
    if code.is_empty()
        || !code.iter().all(u8::is_ascii_alphanumeric)
        || padding.iter().any(|b| *b != 0)
    {
        return Err(EnvelopeDecodeError::AssetCodeInvalid);
    }
    // ASCII alphanumeric bytes are UTF-8.
    Ok(code.iter().map(|b| char::from(*b)).collect())
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: OperationBody name without echoing field values
// ─────────────────────────────────────────────────────────────────────────────

/// Returns a short, non-sensitive name for an `OperationBody` variant.
///
/// Used in [`EnvelopeDecodeError::OperationKindMismatch`] to describe the
/// found variant without echoing any field values.
fn op_body_kind_name(body: &stellar_xdr::OperationBody) -> &'static str {
    use stellar_xdr::OperationBody;
    match body {
        OperationBody::CreateAccount(_) => "CreateAccount",
        OperationBody::Payment(_) => "Payment",
        OperationBody::PathPaymentStrictReceive(_) => "PathPaymentStrictReceive",
        OperationBody::ManageSellOffer(_) => "ManageSellOffer",
        OperationBody::CreatePassiveSellOffer(_) => "CreatePassiveSellOffer",
        OperationBody::SetOptions(_) => "SetOptions",
        OperationBody::ChangeTrust(_) => "ChangeTrust",
        OperationBody::AllowTrust(_) => "AllowTrust",
        OperationBody::AccountMerge(_) => "AccountMerge",
        OperationBody::Inflation => "Inflation",
        OperationBody::ManageData(_) => "ManageData",
        OperationBody::BumpSequence(_) => "BumpSequence",
        OperationBody::ManageBuyOffer(_) => "ManageBuyOffer",
        OperationBody::PathPaymentStrictSend(_) => "PathPaymentStrictSend",
        OperationBody::CreateClaimableBalance(_) => "CreateClaimableBalance",
        OperationBody::ClaimClaimableBalance(_) => "ClaimClaimableBalance",
        OperationBody::BeginSponsoringFutureReserves(_) => "BeginSponsoringFutureReserves",
        OperationBody::EndSponsoringFutureReserves => "EndSponsoringFutureReserves",
        OperationBody::RevokeSponsorship(_) => "RevokeSponsorship",
        OperationBody::Clawback(_) => "Clawback",
        OperationBody::ClawbackClaimableBalance(_) => "ClawbackClaimableBalance",
        OperationBody::SetTrustLineFlags(_) => "SetTrustLineFlags",
        OperationBody::LiquidityPoolDeposit(_) => "LiquidityPoolDeposit",
        OperationBody::LiquidityPoolWithdraw(_) => "LiquidityPoolWithdraw",
        OperationBody::InvokeHostFunction(_) => "InvokeHostFunction",
        OperationBody::ExtendFootprintTtl(_) => "ExtendFootprintTtl",
        OperationBody::RestoreFootprint(_) => "RestoreFootprint",
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
        reason = "test-only; panics and unwraps acceptable in unit tests"
    )]

    #[test]
    fn envelope_reader_distinguishes_the_byte_budget_from_truncation() {
        use base64::Engine as _;
        use stellar_xdr::{HostFunction, InvokeHostFunctionOp, Limits, ReadXdr, WriteXdr};

        let env = build_envelope(
            SOURCE_G,
            Operation {
                source_account: None,
                body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                    host_function: HostFunction::UploadContractWasm(Default::default()),
                    auth: Default::default(),
                }),
            },
            Memo::None,
        );
        let mut raw = env.to_xdr(Limits::none()).unwrap();
        // The empty WASM length precedes the auth, extension, and signature counts.
        let offset = raw.len() - 16;
        raw[offset..offset + 4].copy_from_slice(&4096u32.to_be_bytes());
        let encoded = base64::engine::general_purpose::STANDARD.encode(raw);
        assert!(matches!(
            read_envelope(&encoded),
            Err(EnvelopeReadError::Xdr(
                stellar_xdr::Error::LengthLimitExceeded
            ))
        ));
        assert!(matches!(
            TransactionEnvelope::from_xdr_base64(&encoded, Limits::none()),
            Err(stellar_xdr::Error::Io(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof
        ));
        let too_long = "!".repeat(MAX_ENVELOPE_BASE64_LEN + 1);
        assert!(matches!(
            read_envelope(&too_long),
            Err(EnvelopeReadError::InputTooLong)
        ));
        assert!(matches!(
            decode_authoritative_args(&too_long, "stellar_pay_commit"),
            Err(EnvelopeDecodeError::XdrDecode { detail }) if detail == ENVELOPE_INPUT_TOO_LONG
        ));
    }

    use stellar_xdr::{
        AccountId, Asset, CreateAccountOp, Limits, Memo, MuxedAccount, MuxedAccountMed25519,
        Operation, OperationBody, PaymentOp, PublicKey, SequenceNumber, StringM, Transaction,
        TransactionEnvelope, TransactionExt, TransactionV1Envelope, Uint256, VecM, WriteXdr,
    };

    use super::*;

    // ─────────────────────────────────────────────────────────────────────────
    // XDR fixture helpers
    //
    // These helpers construct known-provenance XDR envelopes from first
    // principles using `stellar_xdr` types, ensuring the fixture XDR
    // is reproducible and does not depend on an external builder crate.
    // ─────────────────────────────────────────────────────────────────────────

    /// Valid testnet G-strkey for the funding / source account.
    /// Derived from seed `[1u8; 32]` via ed25519-dalek (canonical test vector).
    const SOURCE_G: &str = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY";

    /// Valid testnet G-strkey for the recipient account.
    const DEST_G: &str = "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL";

    /// USDC issuer G-strkey (well-known testnet issuer).
    const USDC_ISSUER_G: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";

    /// Extracts the 32-byte public key from a G-strkey.
    fn g_to_bytes(g: &str) -> [u8; 32] {
        stellar_strkey::ed25519::PublicKey::from_string(g)
            .expect("valid G-strkey in test fixture")
            .0
    }

    /// Wraps 32-byte ed25519 public key as `MuxedAccount::Ed25519`.
    fn g_to_muxed(g: &str) -> MuxedAccount {
        MuxedAccount::Ed25519(Uint256(g_to_bytes(g)))
    }

    /// Wraps 32-byte ed25519 public key as `AccountId`.
    fn g_to_account_id(g: &str) -> AccountId {
        AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(g_to_bytes(g))))
    }

    /// Builds a minimal `TransactionV1Envelope` with a single operation.
    ///
    /// The transaction-level `source_account` is `SOURCE_G` unless overridden
    /// by passing `op_source_override = Some(g)`.  The memo defaults to
    /// `Memo::None` unless `memo` is provided.
    fn build_envelope(tx_source: &str, op: Operation, memo: Memo) -> TransactionEnvelope {
        let tx = Transaction {
            source_account: g_to_muxed(tx_source),
            fee: 100,
            seq_num: SequenceNumber(101),
            cond: stellar_xdr::Preconditions::None,
            memo,
            operations: vec![op].try_into().expect("single op vec"),
            ext: TransactionExt::V0,
        };
        TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: VecM::default(),
        })
    }

    /// Serialises a `TransactionEnvelope` to base64 XDR.
    fn to_b64(env: &TransactionEnvelope) -> String {
        env.to_xdr_base64(Limits::none())
            .expect("XDR encoding must succeed")
    }

    // ─────────────────────────────────────────────────────────────────────────
    // stroops_to_human
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn stroops_to_human_one_xlm() {
        assert_eq!(stroops_to_human(10_000_000), "1.0000000");
    }

    #[test]
    fn stroops_to_human_fractional() {
        assert_eq!(stroops_to_human(1_500_000), "0.1500000");
    }

    #[test]
    fn stroops_to_human_zero() {
        assert_eq!(stroops_to_human(0), "0.0000000");
    }

    #[test]
    fn stroops_to_human_negative() {
        assert_eq!(stroops_to_human(-10_000_000), "-1.0000000");
    }

    #[test]
    fn stroops_to_human_large() {
        // 1000 XLM = 10_000_000_000 stroops
        assert_eq!(stroops_to_human(10_000_000_000), "1000.0000000");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Happy path: Payment (native XLM) with text memo
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn happy_path_payment_xlm_with_text_memo() {
        let op = Operation {
            source_account: None,
            body: OperationBody::Payment(PaymentOp {
                destination: g_to_muxed(DEST_G),
                asset: Asset::Native,
                amount: 10_000_000, // 1 XLM
            }),
        };
        let memo_bytes: StringM<28> = b"test-memo"
            .as_slice()
            .try_into()
            .expect("memo within 28 bytes");
        let memo = Memo::Text(memo_bytes);
        let env = build_envelope(SOURCE_G, op, memo);
        let xdr_b64 = to_b64(&env);

        let result = decode_authoritative_args(&xdr_b64, "stellar_pay_commit").unwrap();

        assert_eq!(result["source"], SOURCE_G);
        assert_eq!(result["destination"], DEST_G);
        assert_eq!(result["amount_stroops"], "10000000");
        assert_eq!(result["asset"], "XLM");
        assert_eq!(result["memo"], "test-memo");
        assert!(result.get("memo_hash").is_none());
        assert!(result.get("memo_return").is_none());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Happy path: Payment (USDC non-native)
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn happy_path_payment_usdc_non_native() {
        use stellar_xdr::{AlphaNum4, AssetCode4};
        let mut code_bytes = [0u8; 4];
        code_bytes[..4].copy_from_slice(b"USDC");
        let op = Operation {
            source_account: None,
            body: OperationBody::Payment(PaymentOp {
                destination: g_to_muxed(DEST_G),
                asset: Asset::CreditAlphanum4(AlphaNum4 {
                    asset_code: AssetCode4(code_bytes),
                    issuer: g_to_account_id(USDC_ISSUER_G),
                }),
                amount: 50_000_000, // 5 USDC
            }),
        };
        let env = build_envelope(SOURCE_G, op, Memo::None);
        let xdr_b64 = to_b64(&env);

        let result = decode_authoritative_args(&xdr_b64, "stellar_pay_commit").unwrap();

        assert_eq!(result["source"], SOURCE_G);
        assert_eq!(result["destination"], DEST_G);
        assert_eq!(result["amount_stroops"], "50000000");
        let expected_asset = format!("USDC:{USDC_ISSUER_G}");
        assert_eq!(result["asset"], expected_asset);
        assert_eq!(result["memo"], serde_json::Value::Null);
        assert!(result.get("memo_hash").is_none());
        assert!(result.get("memo_return").is_none());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Happy path: CreateAccount
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn happy_path_create_account() {
        let op = Operation {
            source_account: None,
            body: OperationBody::CreateAccount(CreateAccountOp {
                destination: g_to_account_id(DEST_G),
                starting_balance: 10_000_000, // 1 XLM
            }),
        };
        let env = build_envelope(SOURCE_G, op, Memo::None);
        let xdr_b64 = to_b64(&env);

        let result = decode_authoritative_args(&xdr_b64, "stellar_create_account_commit").unwrap();

        assert_eq!(result["source"], SOURCE_G);
        assert_eq!(result["destination"], DEST_G);
        assert_eq!(result["starting_balance_stroops"], "10000000");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Source account from tx-level when op-level is absent
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn source_derived_from_tx_level_when_op_level_absent() {
        // Operation has no source_account override → tx-level SOURCE_G is used.
        let op = Operation {
            source_account: None,
            body: OperationBody::CreateAccount(CreateAccountOp {
                destination: g_to_account_id(DEST_G),
                starting_balance: 5_000_000,
            }),
        };
        let env = build_envelope(SOURCE_G, op, Memo::None);
        let xdr_b64 = to_b64(&env);

        let result = decode_authoritative_args(&xdr_b64, "stellar_create_account_commit").unwrap();
        assert_eq!(result["source"], SOURCE_G, "source must come from tx-level");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Source account from op-level when present (overrides tx-level)
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn source_derived_from_op_level_when_present() {
        // Op-level source overrides tx-level source.
        let op = Operation {
            source_account: Some(g_to_muxed(DEST_G)), // deliberately use DEST_G as op-source
            body: OperationBody::CreateAccount(CreateAccountOp {
                destination: g_to_account_id(USDC_ISSUER_G),
                starting_balance: 5_000_000,
            }),
        };
        // tx-level source is SOURCE_G; op-level is DEST_G — op-level must win.
        let env = build_envelope(SOURCE_G, op, Memo::None);
        let xdr_b64 = to_b64(&env);

        let result = decode_authoritative_args(&xdr_b64, "stellar_create_account_commit").unwrap();
        assert_eq!(
            result["source"], DEST_G,
            "op-level source must override tx-level source"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // MuxedEd25519 source resolves to G-strkey (discards mux ID)
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn muxed_source_account_resolves_to_g_strkey() {
        let muxed_src = MuxedAccount::MuxedEd25519(MuxedAccountMed25519 {
            id: 42,
            ed25519: Uint256(g_to_bytes(SOURCE_G)),
        });
        let tx = Transaction {
            source_account: muxed_src,
            fee: 100,
            seq_num: SequenceNumber(1),
            cond: stellar_xdr::Preconditions::None,
            memo: Memo::None,
            operations: vec![Operation {
                source_account: None,
                body: OperationBody::CreateAccount(CreateAccountOp {
                    destination: g_to_account_id(DEST_G),
                    starting_balance: 5_000_000,
                }),
            }]
            .try_into()
            .expect("single op"),
            ext: TransactionExt::V0,
        };
        let env = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: VecM::default(),
        });
        let xdr_b64 = to_b64(&env);

        let result = decode_authoritative_args(&xdr_b64, "stellar_create_account_commit").unwrap();
        // Mux ID (42) must be discarded; underlying ed25519 key encodes to SOURCE_G.
        assert_eq!(result["source"], SOURCE_G);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Error: mismatched tool
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn mismatched_tool_returns_operation_kind_mismatch() {
        // CreateAccount operation presented as stellar_pay_commit.
        let op = Operation {
            source_account: None,
            body: OperationBody::CreateAccount(CreateAccountOp {
                destination: g_to_account_id(DEST_G),
                starting_balance: 10_000_000,
            }),
        };
        let env = build_envelope(SOURCE_G, op, Memo::None);
        let xdr_b64 = to_b64(&env);

        let err = decode_authoritative_args(&xdr_b64, "stellar_pay_commit")
            .expect_err("must return OperationKindMismatch");
        assert!(
            matches!(err, EnvelopeDecodeError::OperationKindMismatch { .. }),
            "expected OperationKindMismatch, got: {err}"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Error: unexpected operation count
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn unexpected_op_count_returns_typed_error() {
        // Build an envelope with 0 operations by hand.
        let tx = Transaction {
            source_account: g_to_muxed(SOURCE_G),
            fee: 100,
            seq_num: SequenceNumber(1),
            cond: stellar_xdr::Preconditions::None,
            memo: Memo::None,
            // Empty operations vector.
            operations: VecM::default(),
            ext: TransactionExt::V0,
        };
        let env = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: VecM::default(),
        });
        let xdr_b64 = to_b64(&env);

        let err = decode_authoritative_args(&xdr_b64, "stellar_pay_commit")
            .expect_err("must return UnexpectedOperationCount");
        assert!(
            matches!(
                err,
                EnvelopeDecodeError::UnexpectedOperationCount { count: 0 }
            ),
            "expected UnexpectedOperationCount(0), got: {err}"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Memo::Hash keeps memo null and surfaces memo_hash.
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn memo_hash_returns_ok_with_null_memo() {
        use stellar_xdr::Hash;
        let op = Operation {
            source_account: None,
            body: OperationBody::Payment(PaymentOp {
                destination: g_to_muxed(DEST_G),
                asset: Asset::Native,
                amount: 10_000_000,
            }),
        };
        let env = build_envelope(SOURCE_G, op, Memo::Hash(Hash([0xab_u8; 32])));
        let xdr_b64 = to_b64(&env);

        let result = decode_authoritative_args(&xdr_b64, "stellar_pay_commit")
            .expect("Memo::Hash must not cause a decode error");
        assert_eq!(
            result["memo"],
            serde_json::Value::Null,
            "Memo::Hash should preserve null legacy memo field"
        );
        assert_eq!(result["memo_hash"], "ab".repeat(32));
        assert!(result.get("memo_return").is_none());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Memo::Return keeps memo null and surfaces memo_return.
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn memo_return_returns_ok_with_null_memo() {
        use stellar_xdr::Hash;
        let op = Operation {
            source_account: None,
            body: OperationBody::Payment(PaymentOp {
                destination: g_to_muxed(DEST_G),
                asset: Asset::Native,
                amount: 10_000_000,
            }),
        };
        let env = build_envelope(SOURCE_G, op, Memo::Return(Hash([0xcd_u8; 32])));
        let xdr_b64 = to_b64(&env);

        let result = decode_authoritative_args(&xdr_b64, "stellar_pay_commit")
            .expect("Memo::Return must not cause a decode error");
        assert_eq!(
            result["memo"],
            serde_json::Value::Null,
            "Memo::Return should preserve null legacy memo field"
        );
        assert_eq!(result["memo_return"], "cd".repeat(32));
        assert!(result.get("memo_hash").is_none());
    }

    #[test]
    fn memo_id_retains_decimal_fact_with_null_legacy_memo() {
        let op = Operation {
            source_account: None,
            body: OperationBody::Payment(PaymentOp {
                destination: g_to_muxed(DEST_G),
                asset: Asset::Native,
                amount: 10_000_000,
            }),
        };
        for (id, decimal) in [(0, "0"), (42, "42"), (u64::MAX, "18446744073709551615")] {
            let env = build_envelope(SOURCE_G, op.clone(), Memo::Id(id));
            let xdr_b64 = to_b64(&env);
            let result = decode_authoritative_args(&xdr_b64, "stellar_pay_commit")
                .expect("Memo::Id must not cause a decode error");
            assert_eq!(result["memo"], serde_json::Value::Null);
            assert_eq!(result["memo_kind"], "id");
            assert_eq!(result["memo_id"], decimal);
            assert!(result.get("memo_hash").is_none());
            assert!(result.get("memo_return").is_none());
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Memo::Text with invalid UTF-8 → XdrDecode error
    // ─────────────────────────────────────────────────────────────────────────

    fn memo_evaluation(
        args: &serde_json::Value,
        tool_name: &'static str,
        requirement: Option<crate::policy::v1::criteria::memo_binding::MemoRequirement>,
    ) -> crate::policy::Evaluation {
        use crate::policy::v1::criteria::memo_binding::{MemoBinding, MemoBindingCriterion};
        use crate::policy::v1::loader::{PolicyDocument, PolicyRule, RuleMatch, ScopeId};
        use crate::policy::{
            Decision, McpToolRegistration, PolicyEngine, ToolDescriptor, ToolValueKind,
        };
        let engine = crate::policy::v1::PolicyEngineV1::new(
            PolicyDocument {
                version: 1,
                scope: ScopeId::AllProfiles,
                rules: vec![PolicyRule {
                    r#match: RuleMatch {
                        tool: "*".into(),
                        chain: "*".into(),
                    },
                    criteria: requirement.map_or_else(Vec::new, |requirement| {
                        vec![Box::new(MemoBindingCriterion::new(vec![
                            MemoBinding::new(DEST_G, requirement).unwrap(),
                        ]))
                            as Box<dyn crate::policy::v1::criteria::Criterion>]
                    }),
                    decision: Decision::Allow,
                    allow_opaque_signing: false,
                }],
                signature: None,
            },
            "memo".into(),
        );
        let mut tool = ToolDescriptor::from_registration(&McpToolRegistration {
            name: tool_name,
            destructive_hint: true,
            read_only_hint: false,
            chain_id_required: true,
            value_kind: ToolValueKind::MovesValue,
        });
        tool.chain_id = "stellar:testnet".into();
        let profile =
            crate::profile::Profile::builder_testnet("memo", "acct", "svc", "nonce").build();
        engine
            .evaluate_full(&tool, args, &profile, None, None, None, None, None, 1000)
            .unwrap()
    }

    #[test]
    #[serial_test::serial]
    fn classic_policy_memo_facts_match_signed_xdr() {
        use crate::policy::Decision;
        use crate::policy::v1::criteria::memo_binding::MemoRequirement;
        use stellar_xdr::{
            CreateAccountOp, Hash, MuxedAccountMed25519, PathPaymentStrictReceiveOp,
            PathPaymentStrictSendOp,
        };
        let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
        let cases = [
            (Memo::None, ClassicMemo::None, MemoRequirement::Any),
            (
                Memo::Text(Vec::new().try_into().unwrap()),
                ClassicMemo::Text(String::new()),
                MemoRequirement::Text(String::new()),
            ),
            (
                Memo::Text("支払\n".as_bytes().to_vec().try_into().unwrap()),
                ClassicMemo::Text("支払\n".into()),
                MemoRequirement::Text("支払\n".into()),
            ),
            (Memo::Id(0), ClassicMemo::Id(0), MemoRequirement::Id(0)),
            (
                Memo::Id(u64::MAX),
                ClassicMemo::Id(u64::MAX),
                MemoRequirement::Id(u64::MAX),
            ),
            (
                Memo::Hash(Hash([0xab; 32])),
                ClassicMemo::Hash([0xab; 32]),
                MemoRequirement::Hash([0xab; 32]),
            ),
            (
                Memo::Return(Hash([0xab; 32])),
                ClassicMemo::Return([0xab; 32]),
                MemoRequirement::Return([0xab; 32]),
            ),
        ];
        for id in [None, Some(0), Some(u64::MAX)] {
            let destination = id.map_or_else(
                || g_to_muxed(DEST_G),
                |id| {
                    MuxedAccount::MuxedEd25519(MuxedAccountMed25519 {
                        id,
                        ed25519: Uint256(g_to_bytes(DEST_G)),
                    })
                },
            );
            let full_destination = id.map_or_else(
                || DEST_G.to_owned(),
                |id| {
                    stellar_strkey::ed25519::MuxedAccount {
                        ed25519: g_to_bytes(DEST_G),
                        id,
                    }
                    .to_string()
                    .to_string()
                },
            );
            for (memo, expected, requirement) in &cases {
                for body in [
                    OperationBody::Payment(PaymentOp {
                        destination: destination.clone(),
                        asset: Asset::Native,
                        amount: 17,
                    }),
                    OperationBody::PathPaymentStrictSend(PathPaymentStrictSendOp {
                        send_asset: Asset::Native,
                        send_amount: 17,
                        destination: destination.clone(),
                        dest_asset: Asset::Native,
                        dest_min: 3,
                        path: Default::default(),
                    }),
                    OperationBody::PathPaymentStrictReceive(PathPaymentStrictReceiveOp {
                        send_asset: Asset::Native,
                        send_max: 17,
                        destination: destination.clone(),
                        dest_asset: Asset::Native,
                        dest_amount: 3,
                        path: Default::default(),
                    }),
                    OperationBody::CreateAccount(CreateAccountOp {
                        destination: g_to_account_id(DEST_G),
                        starting_balance: 17,
                    }),
                ] {
                    let create = matches!(body, OperationBody::CreateAccount(_));
                    let tool = if create {
                        "stellar_create_account_commit"
                    } else {
                        "stellar_pay_commit"
                    };
                    let xdr = to_b64(&build_envelope(
                        SOURCE_G,
                        Operation {
                            source_account: None,
                            body,
                        },
                        memo.clone(),
                    ));
                    let args = decode_authoritative_args(&xdr, tool).unwrap();
                    let evaluation = memo_evaluation(&args, tool, None);
                    let effects = evaluation.value_effects.unwrap();
                    assert_eq!(effects.memo(), Some(expected), "signed memo {memo:?}");
                    assert_eq!(effects.legs()[0].amount, Some(17));
                    assert_eq!(effects.legs()[0].asset.as_deref(), Some("native"));
                    assert_eq!(
                        effects.legs()[0].destination.as_deref(),
                        Some(if create { DEST_G } else { &full_destination })
                    );
                    if effects.legs().len() == 2 {
                        assert_eq!(effects.legs()[1].amount, Some(3));
                        assert!(!effects.legs()[1].kind.carries_debit());
                    }
                    let decision = memo_evaluation(&args, tool, Some(requirement.clone())).decision;
                    if *expected == ClassicMemo::None {
                        assert!(matches!(
                            decision,
                            Decision::Deny(crate::policy::DenyReason::MemoBindingMismatch { .. })
                        ));
                    } else {
                        assert_eq!(decision, Decision::Allow, "signed memo binding {memo:?}");
                    }
                    let wrong_kind = match expected {
                        ClassicMemo::Id(id) => MemoRequirement::Text(id.to_string()),
                        ClassicMemo::Hash(bytes) => MemoRequirement::Return(*bytes),
                        ClassicMemo::Return(bytes) => MemoRequirement::Hash(*bytes),
                        _ => MemoRequirement::Id(1),
                    };
                    assert!(matches!(
                        memo_evaluation(&args, tool, Some(wrong_kind)).decision,
                        Decision::Deny(crate::policy::DenyReason::MemoBindingMismatch { .. })
                    ));
                }
            }
        }
    }

    #[test]
    #[serial_test::serial]
    fn classic_policy_malformed_memo_facts_are_absent() {
        use crate::policy::v1::criteria::memo_binding::MemoRequirement;
        use serde_json::json;
        let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
        for facts in [
            json!({}),
            json!({"memo": null}),
            json!({"memo_kind": "none"}),
            json!({"memo_kind": "none", "memo": "forged"}),
            json!({"memo_kind": "none", "memo": null, "memo_id": "0"}),
            json!({"memo_kind": "unknown", "memo": null}),
            json!({"memo_kind": "id", "memo": null, "memo_id": "18446744073709551616"}),
            json!({"memo_kind": "id", "memo": null, "memo_id": "-1"}),
            json!({"memo_kind": "id", "memo": null, "memo_id": "+1"}),
            json!({"memo_kind": "id", "memo": null, "memo_id": "01"}),
            json!({"memo_kind": "id", "memo": null, "memo_id": 1}),
            json!({"memo_kind": "text", "memo": "x".repeat(29)}),
            json!({"memo_kind": "hash", "memo": null, "memo_hash": "AB".repeat(32)}),
            json!({"memo_kind": "return", "memo": null, "memo_return": "ab".repeat(31)}),
            json!({"memo_kind": "hash", "memo": null, "memo_hash": "ab".repeat(32), "memo_return": "ab".repeat(32)}),
        ] {
            let mut args = json!({"destination": DEST_G, "asset": "native", "amount_stroops": "1"});
            args.as_object_mut()
                .unwrap()
                .extend(facts.as_object().unwrap().clone());
            assert_eq!(
                memo_evaluation(&args, "stellar_pay", None)
                    .value_effects
                    .unwrap()
                    .memo(),
                None,
                "{facts}"
            );
            assert!(matches!(
                memo_evaluation(&args, "stellar_pay", Some(MemoRequirement::Any)).decision,
                crate::policy::Decision::Deny(
                    crate::policy::DenyReason::MemoBindingMismatch { .. }
                )
            ));
        }
    }

    #[test]
    fn invalid_utf8_memo_text_returns_xdr_decode_error() {
        use stellar_xdr::StringM;
        // Build a Memo::Text with invalid UTF-8 bytes [0xFF, 0xFE].
        // StringM<28> accepts any bytes (XDR string<28> is opaque).
        let invalid_bytes: &[u8] = &[0xFF_u8, 0xFE_u8];
        let memo_bytes: StringM<28> = invalid_bytes
            .try_into()
            .expect("2 bytes is within the 28-byte limit");
        let memo = Memo::Text(memo_bytes);

        let op = Operation {
            source_account: None,
            body: OperationBody::Payment(PaymentOp {
                destination: g_to_muxed(DEST_G),
                asset: Asset::Native,
                amount: 10_000_000,
            }),
        };
        let env = build_envelope(SOURCE_G, op, memo);
        let xdr_b64 = to_b64(&env);

        // Invalid UTF-8 in Memo::Text must return XdrDecode, not silently substitute U+FFFD.
        let err = decode_authoritative_args(&xdr_b64, "stellar_pay_commit")
            .expect_err("invalid-UTF-8 memo must return an error");
        assert!(
            matches!(err, EnvelopeDecodeError::XdrDecode { ref detail } if detail.contains("UTF-8")),
            "expected XdrDecode with UTF-8 detail, got: {err}"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Error: unsupported tool name
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn unsupported_tool_returns_typed_error() {
        let err = decode_authoritative_args("aGVsbG8=", "stellar_balances")
            .expect_err("must return UnsupportedTool");
        assert!(
            matches!(err, EnvelopeDecodeError::UnsupportedTool),
            "expected UnsupportedTool, got: {err}"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Error: invalid base64
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn invalid_base64_returns_xdr_decode_error() {
        // The `from_xdr_base64` method handles both base64 decode and XDR
        // decode in one call; a non-base64 string produces an XdrDecode error.
        let err = decode_authoritative_args("!!! not base64 !!!", "stellar_pay_commit")
            .expect_err("must return XdrDecode");
        assert!(
            matches!(err, EnvelopeDecodeError::XdrDecode { .. }),
            "expected XdrDecode error, got: {err}"
        );
    }

    /// An envelope that is not base64 is refused by class; the detail names
    /// neither the envelope text nor the symbol the base64 decoder stopped at.
    #[test]
    fn envelope_base64_marker_is_not_echoed() {
        use stellar_agent_test_support::rejected_value::{CREDENTIAL_MARKER, assert_no_marker};

        // The invalid symbol leads, so the base64 decoder fails on the first
        // read, before any XDR value is parsed.
        let envelope = format!("~{CREDENTIAL_MARKER}");
        let err = decode_authoritative_args(&envelope, "stellar_pay_commit")
            .expect_err("a non-base64 envelope is refused");
        assert!(
            matches!(
                &err,
                EnvelopeDecodeError::XdrDecode { detail }
                    if detail == "the envelope is not valid standard base64"
            ),
            "{err:?}"
        );
        assert_no_marker(&err, CREDENTIAL_MARKER);
        // The base64 decoder reports the offending symbol as its byte value.
        assert_no_marker(&err, "126");
        assert_no_marker(&err, "symbol");
        let err = envelope_source_account(&envelope).expect_err("refused through the source path");
        assert!(
            matches!(
                &err,
                EnvelopeDecodeError::XdrDecode { detail }
                    if detail == "the envelope is not valid standard base64"
            ),
            "{err:?}"
        );
        assert_no_marker(&err, CREDENTIAL_MARKER);
        assert_no_marker(&err, "symbol");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Error: valid base64 but wrong XDR content
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn invalid_xdr_returns_decode_error() {
        // base64-encode some random bytes that are not a valid TransactionEnvelope.
        use base64::Engine as _;
        let garbage = base64::engine::general_purpose::STANDARD.encode(b"not-xdr-content");
        let err = decode_authoritative_args(&garbage, "stellar_pay_commit")
            .expect_err("must return XdrDecode");
        assert!(
            matches!(err, EnvelopeDecodeError::XdrDecode { .. }),
            "expected XdrDecode error, got: {err}"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Path-payment debit sizing: the debit leg is the SEND side, not the
    // destination side (#51).
    // ─────────────────────────────────────────────────────────────────────────

    /// `PathPaymentStrictSend`: the debit (`asset` / `amount_stroops`) is the
    /// send side (`send_asset` / `send_amount`, exact). The destination side
    /// is surfaced separately as `dest_asset` / `dest_amount_stroops` — here
    /// `dest_min`, the floor the recipient is guaranteed to receive.
    #[test]
    fn path_payment_strict_send_debit_is_send_side_not_dest_side() {
        use stellar_xdr::{AlphaNum4, AssetCode4, PathPaymentStrictSendOp};
        let mut code_bytes = [0u8; 4];
        code_bytes[..4].copy_from_slice(b"USDC");
        let op = Operation {
            source_account: None,
            body: OperationBody::PathPaymentStrictSend(PathPaymentStrictSendOp {
                send_asset: Asset::Native,
                send_amount: 5_000_000, // 0.5 XLM sent — the debit (authoritative for policy cap)
                destination: g_to_muxed(DEST_G),
                dest_asset: Asset::CreditAlphanum4(AlphaNum4 {
                    asset_code: AssetCode4(code_bytes),
                    issuer: g_to_account_id(USDC_ISSUER_G),
                }),
                dest_min: 4_900_000,
                path: VecM::default(),
            }),
        };
        let env = build_envelope(SOURCE_G, op, Memo::None);
        let xdr_b64 = to_b64(&env);

        let result = decode_authoritative_args(&xdr_b64, "stellar_pay_commit").unwrap();
        assert_eq!(
            result["amount_stroops"], "5000000",
            "debit amount must be send_amount"
        );
        assert_eq!(result["asset"], "XLM", "debit asset must be send_asset");
        assert_eq!(
            result["dest_amount_stroops"], "4900000",
            "informational receive amount must be dest_min"
        );
        assert_eq!(
            result["dest_asset"],
            format!("USDC:{USDC_ISSUER_G}"),
            "informational receive asset must be dest_asset"
        );
        assert_eq!(result["destination"], DEST_G);
    }

    /// `PathPaymentStrictReceive`: the debit (`asset` / `amount_stroops`) is
    /// the send side (`send_asset` / `send_max`, the ceiling the signer
    /// authorizes to spend) — NOT the destination side (`dest_asset` /
    /// `dest_amount`, what the recipient actually receives). `send_max`
    /// bounds the wallet's actual spend, so a value cap sized off
    /// `dest_amount`/`dest_asset` could be bypassed by routing through an
    /// asset the cap does not cover.
    #[test]
    fn path_payment_strict_receive_debit_is_send_side_not_dest_side() {
        use stellar_xdr::{AlphaNum4, AssetCode4, PathPaymentStrictReceiveOp};
        let mut code_bytes = [0u8; 4];
        code_bytes[..4].copy_from_slice(b"USDC");
        let op = Operation {
            source_account: None,
            body: OperationBody::PathPaymentStrictReceive(PathPaymentStrictReceiveOp {
                send_asset: Asset::Native,
                send_max: 6_000_000, // ceiling the signer authorizes — the debit
                destination: g_to_muxed(DEST_G),
                dest_asset: Asset::CreditAlphanum4(AlphaNum4 {
                    asset_code: AssetCode4(code_bytes),
                    issuer: g_to_account_id(USDC_ISSUER_G),
                }),
                dest_amount: 5_000_000,
                path: VecM::default(),
            }),
        };
        let env = build_envelope(SOURCE_G, op, Memo::None);
        let xdr_b64 = to_b64(&env);

        let result = decode_authoritative_args(&xdr_b64, "stellar_pay_commit").unwrap();
        assert_eq!(
            result["amount_stroops"], "6000000",
            "debit amount must be send_max, not dest_amount"
        );
        assert_eq!(result["asset"], "XLM", "debit asset must be send_asset");
        assert_eq!(
            result["dest_amount_stroops"], "5000000",
            "informational receive amount must be dest_amount"
        );
        assert_eq!(
            result["dest_asset"],
            format!("USDC:{USDC_ISSUER_G}"),
            "informational receive asset must be dest_asset"
        );
        assert_eq!(result["destination"], DEST_G);
    }

    /// A plain `Payment` carries neither `dest_asset` nor
    /// `dest_amount_stroops` — the single-leg shape is unchanged by the
    /// path-payment fix.
    #[test]
    fn plain_payment_carries_no_dest_fields() {
        let op = Operation {
            source_account: None,
            body: OperationBody::Payment(stellar_xdr::PaymentOp {
                destination: g_to_muxed(DEST_G),
                asset: Asset::Native,
                amount: 1_000_000,
            }),
        };
        let env = build_envelope(SOURCE_G, op, Memo::None);
        let xdr_b64 = to_b64(&env);

        let result = decode_authoritative_args(&xdr_b64, "stellar_pay_commit").unwrap();
        assert_eq!(result["amount_stroops"], "1000000");
        assert_eq!(result["asset"], "XLM");
        assert!(
            result.get("dest_amount_stroops").is_none(),
            "a plain Payment must not carry dest_amount_stroops"
        );
        assert!(
            result.get("dest_asset").is_none(),
            "a plain Payment must not carry dest_asset"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // stellar_trustline_commit: ChangeTrust decoder KATs
    // ─────────────────────────────────────────────────────────────────────────

    /// Happy path: ChangeTrust with USDC (alphanum4) and explicit limit.
    #[test]
    fn change_trust_usdc_explicit_limit() {
        use stellar_xdr::{AlphaNum4, AssetCode4, ChangeTrustAsset, ChangeTrustOp};
        let mut code_bytes = [0u8; 4];
        code_bytes[..4].copy_from_slice(b"USDC");
        let op = Operation {
            source_account: None,
            body: OperationBody::ChangeTrust(ChangeTrustOp {
                line: ChangeTrustAsset::CreditAlphanum4(AlphaNum4 {
                    asset_code: AssetCode4(code_bytes),
                    issuer: g_to_account_id(USDC_ISSUER_G),
                }),
                limit: 1_000_000_000, // 100 USDC at 7 decimals
            }),
        };
        let env = build_envelope(SOURCE_G, op, Memo::None);
        let xdr_b64 = to_b64(&env);

        let result = decode_authoritative_args(&xdr_b64, "stellar_trustline_commit").unwrap();
        assert_eq!(result["source"], SOURCE_G);
        assert_eq!(result["total_fee_stroops"], serde_json::json!(100_u32));
        assert_eq!(result["asset_code"], "USDC");
        assert_eq!(result["asset_issuer"], USDC_ISSUER_G);
        assert_eq!(result["limit_stroops"], "1000000000");
    }

    /// Happy path: ChangeTrust with unlimited limit (`i64::MAX`) — the Stellar
    /// "default unlimited trustline" sentinel value.
    #[test]
    fn change_trust_unlimited_limit_i64_max() {
        use stellar_xdr::{AlphaNum4, AssetCode4, ChangeTrustAsset, ChangeTrustOp};
        let mut code_bytes = [0u8; 4];
        code_bytes[..4].copy_from_slice(b"USDC");
        let op = Operation {
            source_account: None,
            body: OperationBody::ChangeTrust(ChangeTrustOp {
                line: ChangeTrustAsset::CreditAlphanum4(AlphaNum4 {
                    asset_code: AssetCode4(code_bytes),
                    issuer: g_to_account_id(USDC_ISSUER_G),
                }),
                limit: i64::MAX, // unlimited
            }),
        };
        let env = build_envelope(SOURCE_G, op, Memo::None);
        let xdr_b64 = to_b64(&env);

        let result = decode_authoritative_args(&xdr_b64, "stellar_trustline_commit").unwrap();
        assert_eq!(result["asset_code"], "USDC");
        assert_eq!(result["limit_stroops"], "9223372036854775807");
        // The decimal-string encoding round-trips i64::MAX exactly — the
        // concrete precision loss a JSON number would have introduced
        // (f64 cannot represent 9_223_372_036_854_775_807 exactly).
        let round_tripped: i64 = result["limit_stroops"]
            .as_str()
            .expect("limit_stroops is a decimal string")
            .parse()
            .expect("limit_stroops decimal string must parse as i64");
        assert_eq!(round_tripped, i64::MAX);
    }

    /// Happy path: ChangeTrust with an alphanum12 asset code (12-byte code field).
    #[test]
    fn change_trust_alphanum12_asset() {
        use stellar_xdr::{AlphaNum12, AssetCode12, ChangeTrustAsset, ChangeTrustOp};
        let mut code_bytes = [0u8; 12];
        let code_str = b"STELARGO";
        code_bytes[..code_str.len()].copy_from_slice(code_str);
        let op = Operation {
            source_account: None,
            body: OperationBody::ChangeTrust(ChangeTrustOp {
                line: ChangeTrustAsset::CreditAlphanum12(AlphaNum12 {
                    asset_code: AssetCode12(code_bytes),
                    issuer: g_to_account_id(USDC_ISSUER_G),
                }),
                limit: 500_000_000,
            }),
        };
        let env = build_envelope(SOURCE_G, op, Memo::None);
        let xdr_b64 = to_b64(&env);

        let result = decode_authoritative_args(&xdr_b64, "stellar_trustline_commit").unwrap();
        assert_eq!(result["asset_code"], "STELARGO");
        assert_eq!(result["asset_issuer"], USDC_ISSUER_G);
        assert_eq!(result["limit_stroops"], "500000000");
    }

    /// Error path: Payment operation presented as stellar_trustline_commit →
    /// OperationKindMismatch.
    #[test]
    fn change_trust_tool_mismatch_payment_body() {
        let op = Operation {
            source_account: None,
            body: OperationBody::Payment(PaymentOp {
                destination: g_to_muxed(DEST_G),
                asset: Asset::Native,
                amount: 10_000_000,
            }),
        };
        let env = build_envelope(SOURCE_G, op, Memo::None);
        let xdr_b64 = to_b64(&env);

        let err = decode_authoritative_args(&xdr_b64, "stellar_trustline_commit")
            .expect_err("Payment body must not match stellar_trustline_commit");
        assert!(
            matches!(err, EnvelopeDecodeError::OperationKindMismatch { .. }),
            "expected OperationKindMismatch, got: {err}"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // stellar_claim_commit: ClaimClaimableBalance decoder KATs
    // ─────────────────────────────────────────────────────────────────────────

    /// Happy path: `ClaimClaimableBalance` decodes to both id renderings.
    #[test]
    fn happy_path_claim_claimable_balance() {
        use stellar_xdr::{ClaimClaimableBalanceOp, ClaimableBalanceId, Hash};

        let hash_bytes = [0x11_u8; 32];
        let op = Operation {
            source_account: None,
            body: OperationBody::ClaimClaimableBalance(ClaimClaimableBalanceOp {
                balance_id: ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash(hash_bytes)),
            }),
        };
        let env = build_envelope(SOURCE_G, op, Memo::None);
        let xdr_b64 = to_b64(&env);

        let result = decode_authoritative_args(&xdr_b64, "stellar_claim_commit").unwrap();

        assert_eq!(result["source"], SOURCE_G);
        assert_eq!(result["total_fee_stroops"], serde_json::json!(100_u32));
        let expected_hex72 = format!("00000000{}", "11".repeat(32));
        assert_eq!(result["balance_id_hex72"], expected_hex72);
        let strkey = result["balance_id_strkey"].as_str().expect("string field");
        assert!(
            strkey.starts_with('B'),
            "expected B... strkey, got: {strkey}"
        );
    }

    /// Error path: Payment operation presented as stellar_claim_commit →
    /// OperationKindMismatch.
    #[test]
    fn claim_tool_mismatch_payment_body() {
        let op = Operation {
            source_account: None,
            body: OperationBody::Payment(PaymentOp {
                destination: g_to_muxed(DEST_G),
                asset: Asset::Native,
                amount: 10_000_000,
            }),
        };
        let env = build_envelope(SOURCE_G, op, Memo::None);
        let xdr_b64 = to_b64(&env);

        let err = decode_authoritative_args(&xdr_b64, "stellar_claim_commit")
            .expect_err("Payment body must not match stellar_claim_commit");
        assert!(
            matches!(err, EnvelopeDecodeError::OperationKindMismatch { .. }),
            "expected OperationKindMismatch, got: {err}"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Depth-bomb regression: a 600-deep sub_invocations chain must be rejected
    // by the bounded decoder and must NOT abort the process via stack exhaustion.
    // ─────────────────────────────────────────────────────────────────────────

    /// Verifies that a `TransactionEnvelope` carrying a 600-deep
    /// `SorobanAuthorizedInvocation.sub_invocations` chain is rejected by
    /// `decode_authoritative_args` with `XdrDecode` and does NOT exhaust the
    /// stack.
    ///
    /// The depth (600) exceeds `XDR_DECODE_MAX_DEPTH` (500).  The bounded
    /// decoder decrements a depth counter on each recursive `with_limited_depth`
    /// call and returns an error before the stack can overflow.
    ///
    /// The deep fixture is encoded with `Limits::none()` (write-only; write
    /// recursion at depth 600 fits the test stack).  Only the BOUNDED production
    /// path decodes it.
    #[test]
    fn deep_sub_invocations_chain_is_rejected_before_stack_exhaustion() {
        use stellar_xdr::{
            ContractId, Hash, InvokeContractArgs, InvokeHostFunctionOp, Limits, Memo, Operation,
            OperationBody, ScAddress, SequenceNumber, SorobanAuthorizationEntry,
            SorobanAuthorizedFunction, SorobanAuthorizedInvocation, SorobanCredentials,
            TransactionEnvelope, TransactionExt, TransactionV1Envelope, Uint256, VecM, WriteXdr,
        };

        // Build a 600-deep chain ITERATIVELY to avoid recursive stack frames in
        // the test itself.  Start from the innermost leaf and wrap outward.
        let leaf_fn = SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
            contract_address: ScAddress::Contract(ContractId(Hash([0xABu8; 32]))),
            function_name: "f".try_into().expect("short name"),
            args: VecM::default(),
        });

        let mut innermost = SorobanAuthorizedInvocation {
            function: leaf_fn.clone(),
            sub_invocations: VecM::default(),
        };

        // Wrap 599 more times (total depth = 600).
        for _ in 0..599 {
            innermost = SorobanAuthorizedInvocation {
                function: leaf_fn.clone(),
                sub_invocations: vec![innermost]
                    .try_into()
                    .expect("single-element VecM must fit"),
            };
        }

        // Build a minimal SorobanAuthorizationEntry carrying the deep invocation.
        let auth_entry = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::SourceAccount,
            root_invocation: innermost,
        };

        // Wrap in an InvokeHostFunctionOp with one auth entry.
        let invoke_op = Operation {
            source_account: None,
            body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                host_function: stellar_xdr::HostFunction::InvokeContract(InvokeContractArgs {
                    contract_address: ScAddress::Contract(ContractId(Hash([0xCDu8; 32]))),
                    function_name: "invoke".try_into().expect("short name"),
                    args: VecM::default(),
                }),
                auth: vec![auth_entry].try_into().expect("single-entry VecM"),
            }),
        };

        // Build the TransactionEnvelope.
        let source_bytes = [1u8; 32];
        let tx = stellar_xdr::Transaction {
            source_account: stellar_xdr::MuxedAccount::Ed25519(Uint256(source_bytes)),
            fee: 100,
            seq_num: SequenceNumber(1),
            cond: stellar_xdr::Preconditions::None,
            memo: Memo::None,
            operations: vec![invoke_op].try_into().expect("single op"),
            ext: TransactionExt::V0,
        };
        let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: VecM::default(),
        });

        // ENCODE with Limits::none() — write recursion at depth 600 fits the
        // test stack; this does NOT invoke the bounded read path.
        let deep_b64 = envelope
            .to_xdr_base64(Limits::none())
            .expect("encoding a deep structure must succeed");

        // Feed the encoded deep fixture through the BOUNDED production path.
        // This MUST return an Err (XdrDecode), not panic or SIGABRT.
        let result = decode_authoritative_args(&deep_b64, "stellar_pay_commit");
        assert!(
            result.is_err(),
            "a 600-deep sub_invocations chain must be rejected by the bounded decoder"
        );
        let err = result.unwrap_err();
        assert!(
            matches!(err, EnvelopeDecodeError::XdrDecode { .. }),
            "expected XdrDecode from depth-exceeded decode, got: {err:?}"
        );
    }

    /// stellar_trustline_commit is rejected by stellar_pay_commit tool.
    #[test]
    fn change_trust_body_rejected_by_pay_tool() {
        use stellar_xdr::{AlphaNum4, AssetCode4, ChangeTrustAsset, ChangeTrustOp};
        let mut code_bytes = [0u8; 4];
        code_bytes[..4].copy_from_slice(b"USDC");
        let op = Operation {
            source_account: None,
            body: OperationBody::ChangeTrust(ChangeTrustOp {
                line: ChangeTrustAsset::CreditAlphanum4(AlphaNum4 {
                    asset_code: AssetCode4(code_bytes),
                    issuer: g_to_account_id(USDC_ISSUER_G),
                }),
                limit: i64::MAX,
            }),
        };
        let env = build_envelope(SOURCE_G, op, Memo::None);
        let xdr_b64 = to_b64(&env);

        let err = decode_authoritative_args(&xdr_b64, "stellar_pay_commit")
            .expect_err("ChangeTrust body must not match stellar_pay_commit");
        assert!(
            matches!(err, EnvelopeDecodeError::OperationKindMismatch { .. }),
            "expected OperationKindMismatch, got: {err}"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // classic_summary
    // ─────────────────────────────────────────────────────────────────────────

    fn usdc() -> Asset {
        use stellar_xdr::{AlphaNum4, AssetCode4};
        Asset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4(*b"USDC"),
            issuer: g_to_account_id(USDC_ISSUER_G),
        })
    }

    /// The summary of a payment carries the values the policy decoder
    /// evaluates for the same envelope, plus the memo, fee and sequence.
    #[test]
    fn classic_summary_payment_agrees_with_the_policy_decoder() {
        use stellar_xdr::ReadXdr as _;
        const G: &str = "GCTKNJVGU2TKNJVGU2TKNJVGU2TKNJVGU2TKNJVGU2TKNJVGU2TKNG7S";
        const M0: &str = "MCTKNJVGU2TKNJVGU2TKNJVGU2TKNJVGU2TKNJVGU2TKNJVGU2TKMAAAAAAAAAAAABA5O";
        const MMAX: &str = "MCTKNJVGU2TKNJVGU2TKNJVGU2TKNJVGU2TKNJVGU2TKNJVGU2TKN7777777777776QHC";
        for destination in [G, M0, MMAX] {
            for (asset, asset_text) in [
                (Asset::Native, "XLM".to_owned()),
                (usdc(), format!("USDC:{USDC_ISSUER_G}")),
            ] {
                for sequence in [101, i64::MAX] {
                    for (memo, expected_memo) in [
                        (Memo::None, ClassicMemo::None),
                        (
                            Memo::Text(Vec::new().try_into().unwrap()),
                            ClassicMemo::Text(String::new()),
                        ),
                        (
                            Memo::Text("é".as_bytes().try_into().unwrap()),
                            ClassicMemo::Text("é".to_owned()),
                        ),
                        (Memo::Id(0), ClassicMemo::Id(0)),
                        (Memo::Id(u64::MAX), ClassicMemo::Id(u64::MAX)),
                        (
                            Memo::Hash(stellar_xdr::Hash([0xab; 32])),
                            ClassicMemo::Hash([0xab; 32]),
                        ),
                        (
                            Memo::Return(stellar_xdr::Hash([0xab; 32])),
                            ClassicMemo::Return([0xab; 32]),
                        ),
                    ] {
                        let op = Operation {
                            source_account: Some(g_to_muxed(DEST_G)),
                            body: OperationBody::Payment(PaymentOp {
                                destination: crate::payment_accounts::PaymentAccount::parse(
                                    destination,
                                )
                                .unwrap()
                                .to_muxed_account(),
                                asset: asset.clone(),
                                amount: 123_456_789,
                            }),
                        };
                        let mut env = build_envelope(SOURCE_G, op, memo);
                        let TransactionEnvelope::Tx(ref mut v1) = env else {
                            unreachable!()
                        };
                        v1.tx.seq_num = SequenceNumber(sequence);
                        let retained = to_b64(&env);
                        assert_eq!(
                            to_b64(
                                &TransactionEnvelope::from_xdr_base64(&retained, Limits::none())
                                    .unwrap()
                            ),
                            retained
                        );
                        let summary =
                            classic_summary(&retained, ClassicTransactionKind::Payment).unwrap();
                        let policy =
                            decode_authoritative_args(&retained, "stellar_pay_commit").unwrap();
                        assert_eq!(policy["sequence_number"], sequence);
                        assert_eq!(summary.seq_num, sequence);
                        assert_eq!(policy["source"], DEST_G);
                        assert_eq!(policy["destination"], destination);
                        assert_eq!(policy["amount_stroops"], "123456789");
                        assert_eq!(policy["asset"], asset_text);
                        assert_eq!(summary.memo, expected_memo);
                        match expected_memo {
                            ClassicMemo::None => assert!(policy["memo"].is_null()),
                            ClassicMemo::Text(text) => assert_eq!(policy["memo"], text),
                            ClassicMemo::Id(id) => assert_eq!(policy["memo_id"], id.to_string()),
                            ClassicMemo::Hash(_) => assert_eq!(
                                policy["memo_hash"],
                                "abababababababababababababababababababababababababababababababab"
                            ),
                            ClassicMemo::Return(_) => assert_eq!(
                                policy["memo_return"],
                                "abababababababababababababababababababababababababababababababab"
                            ),
                        }
                    }
                }
            }
        }
        let op = Operation {
            source_account: Some(g_to_muxed(DEST_G)),
            body: OperationBody::Payment(PaymentOp {
                destination: g_to_muxed(USDC_ISSUER_G),
                asset: usdc(),
                amount: 123_456_789,
            }),
        };
        let memo = Memo::Text(b"inv \x1b[2K".as_slice().try_into().unwrap());
        let xdr_b64 = to_b64(&build_envelope(SOURCE_G, op, memo));

        let summary = classic_summary(&xdr_b64, ClassicTransactionKind::Payment).unwrap();
        let policy = decode_authoritative_args(&xdr_b64, "stellar_pay_commit").unwrap();
        assert_eq!(summary.source, policy["source"]);
        assert_eq!(summary.source, DEST_G);
        assert_eq!(summary.fee_stroops, 100);
        assert_eq!(summary.seq_num, 101);
        assert_eq!(summary.memo, ClassicMemo::Text("inv \u{1b}[2K".to_owned()));
        assert_eq!(summary.memo.display(), "text \"inv \u{1b}[2K\"");
        let ClassicOperation::Payment {
            destination,
            asset,
            amount_stroops,
        } = &summary.operation
        else {
            panic!("{:?}", summary.operation)
        };
        assert_eq!(destination, &policy["destination"]);
        assert_eq!(asset, &policy["asset"]);
        assert_eq!(amount_stroops.to_string(), policy["amount_stroops"]);
    }

    #[test]
    fn classic_summary_memo_kinds_name_themselves() {
        let pay = |memo| {
            let op = Operation {
                source_account: None,
                body: OperationBody::Payment(PaymentOp {
                    destination: g_to_muxed(DEST_G),
                    asset: Asset::Native,
                    amount: 1,
                }),
            };
            classic_summary(
                &to_b64(&build_envelope(SOURCE_G, op, memo)),
                ClassicTransactionKind::Payment,
            )
            .unwrap()
            .memo
            .display()
        };
        assert_eq!(pay(Memo::None), "none");
        assert_ne!(
            pay(Memo::Text(b"id 7".to_vec().try_into().unwrap())),
            pay(Memo::Id(7))
        );
        assert_ne!(
            pay(Memo::Text(b"(none)".to_vec().try_into().unwrap())),
            pay(Memo::None)
        );
        assert_eq!(pay(Memo::Id(7)), "id 7");
        assert_eq!(
            pay(Memo::Hash(stellar_xdr::Hash([0xab; 32]))),
            format!("hash {}", "ab".repeat(32))
        );
        assert_eq!(
            pay(Memo::Return(stellar_xdr::Hash([0x01; 32]))),
            format!("return {}", "01".repeat(32))
        );
    }

    /// A summary refuses what it cannot show faithfully: an asset code with a
    /// byte outside ASCII letters and digits, a text memo that is not UTF-8,
    /// and an operation of another kind.
    #[test]
    fn classic_summary_refuses_unshowable_envelopes() {
        use stellar_xdr::{AlphaNum4, AssetCode4};
        for code in [*b"US\x1bD", *b"\0USD", *b"U\0SD", [0; 4]] {
            let op = Operation {
                source_account: None,
                body: OperationBody::Payment(PaymentOp {
                    destination: g_to_muxed(DEST_G),
                    asset: Asset::CreditAlphanum4(AlphaNum4 {
                        asset_code: AssetCode4(code),
                        issuer: g_to_account_id(USDC_ISSUER_G),
                    }),
                    amount: 1,
                }),
            };
            let xdr_b64 = to_b64(&build_envelope(SOURCE_G, op, Memo::None));
            assert!(
                matches!(
                    classic_summary(&xdr_b64, ClassicTransactionKind::Payment),
                    Err(EnvelopeDecodeError::AssetCodeInvalid)
                ),
                "{code:?}"
            );
        }

        let op = Operation {
            source_account: None,
            body: OperationBody::Payment(PaymentOp {
                destination: g_to_muxed(DEST_G),
                asset: Asset::Native,
                amount: 1,
            }),
        };
        let memo = Memo::Text(vec![0xff, 0xfe].try_into().unwrap());
        let xdr_b64 = to_b64(&build_envelope(SOURCE_G, op.clone(), memo));
        assert!(matches!(
            classic_summary(&xdr_b64, ClassicTransactionKind::Payment),
            Err(EnvelopeDecodeError::XdrDecode { .. })
        ));

        let xdr_b64 = to_b64(&build_envelope(SOURCE_G, op, Memo::None));
        for kind in [
            ClassicTransactionKind::Trustline,
            ClassicTransactionKind::Claim,
        ] {
            assert!(matches!(
                classic_summary(&xdr_b64, kind),
                Err(EnvelopeDecodeError::OperationKindMismatch { .. })
            ));
        }
        assert!(classic_summary("AAAA", ClassicTransactionKind::Payment).is_err());
    }

    #[test]
    fn classic_summary_change_trust_and_claim() {
        use stellar_xdr::{
            AlphaNum12, AssetCode12, ChangeTrustAsset, ChangeTrustOp, ClaimClaimableBalanceOp,
            ClaimableBalanceId, Hash,
        };
        let mut code = [0u8; 12];
        code[..6].copy_from_slice(b"LONGER");
        let trust = |limit| Operation {
            source_account: None,
            body: OperationBody::ChangeTrust(ChangeTrustOp {
                line: ChangeTrustAsset::CreditAlphanum12(AlphaNum12 {
                    asset_code: AssetCode12(code),
                    issuer: g_to_account_id(USDC_ISSUER_G),
                }),
                limit,
            }),
        };
        let summary = classic_summary(
            &to_b64(&build_envelope(SOURCE_G, trust(i64::MAX), Memo::None)),
            ClassicTransactionKind::Trustline,
        )
        .unwrap();
        assert_eq!(
            summary.operation,
            ClassicOperation::ChangeTrust {
                asset_code: "LONGER".to_owned(),
                asset_issuer: USDC_ISSUER_G.to_owned(),
                limit_stroops: None,
            }
        );
        let summary = classic_summary(
            &to_b64(&build_envelope(SOURCE_G, trust(0), Memo::None)),
            ClassicTransactionKind::Trustline,
        )
        .unwrap();
        assert!(matches!(
            summary.operation,
            ClassicOperation::ChangeTrust {
                limit_stroops: Some(0),
                ..
            }
        ));

        let claim = Operation {
            source_account: None,
            body: OperationBody::ClaimClaimableBalance(ClaimClaimableBalanceOp {
                balance_id: ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash([0x5a; 32])),
            }),
        };
        let xdr_b64 = to_b64(&build_envelope(SOURCE_G, claim, Memo::None));
        let summary = classic_summary(&xdr_b64, ClassicTransactionKind::Claim).unwrap();
        let policy = decode_authoritative_args(&xdr_b64, "stellar_claim_commit").unwrap();
        assert_eq!(
            summary.operation,
            ClassicOperation::ClaimClaimableBalance {
                balance_id_hex72: policy["balance_id_hex72"].as_str().unwrap().to_owned(),
                balance_id_strkey: policy["balance_id_strkey"].as_str().unwrap().to_owned(),
            }
        );
        assert_eq!(summary.source, SOURCE_G);
    }
}
