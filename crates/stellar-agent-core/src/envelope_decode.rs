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

/// Errors returned by [`decode_authoritative_args`].
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
    /// `"stellar_create_account_commit"`, and `"stellar_trustline_commit"`.
    #[error("unsupported tool name: {tool}")]
    UnsupportedTool {
        /// The unrecognised tool name.
        tool: String,
    },

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
/// `MuxedEd25519` carries an additional `id` mux-component; that component is
/// discarded here because the policy engine works at the G-strkey granularity
/// (all muxed sub-accounts share the same on-chain account entry).
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
// Memo re-derivation
// ─────────────────────────────────────────────────────────────────────────────

/// Extracts the memo from a `stellar_xdr::Memo` to an
/// `Option<String>` suitable for the policy-engine args JSON.
///
/// - `Memo::None` → `Ok(None)`.
/// - `Memo::Text(bytes)` → `Ok(Some(utf8_string))` when bytes are valid UTF-8;
///   `Err(XdrDecode)` when bytes are not valid UTF-8.
/// - `Memo::Id(u64)` → `Ok(None)` (numeric memos are not forwarded through the
///   policy path; the envelope divergence check is the integrity backstop).
/// - `Memo::Hash(_)` → `Ok(None)` for the legacy `memo` text field.
/// - `Memo::Return(_)` → `Ok(None)` for the legacy `memo` text field.
///
/// # Rationale for strict UTF-8 enforcement on `Memo::Text`
///
/// Stellar `Memo::Text` is XDR `string<28>` — opaque bytes, not UTF-8
/// constrained.  Using `String::from_utf8_lossy` would silently substitute
/// U+FFFD for malformed bytes, allowing a forger to craft an envelope whose
/// on-chain memo bytes differ from the string the policy engine evaluates.
/// `String::from_utf8` with an explicit error path closes this attack surface.
///
/// # Rationale for `Memo::Id` / `Memo::Hash` / `Memo::Return` in `memo`
///
/// Returning `Ok(None)` preserves the invariant that `memo` in the args JSON is
/// either a UTF-8 string or `null`. Hash and return memos are surfaced by
/// `decode_pay_args` as separate `memo_hash` / `memo_return` fields so existing
/// text-memo consumers do not change shape.
fn memo_to_optional_string(
    memo: &stellar_xdr::Memo,
) -> Result<Option<String>, EnvelopeDecodeError> {
    match memo {
        stellar_xdr::Memo::None => Ok(None),
        stellar_xdr::Memo::Text(bytes) => {
            // Strict UTF-8: reject malformed bytes rather than substituting
            // U+FFFD — see module-level rationale above.
            String::from_utf8(bytes.as_slice().to_vec())
                .map(Some)
                .map_err(|_| EnvelopeDecodeError::XdrDecode {
                    detail: "memo text is not valid UTF-8".to_owned(),
                })
        }
        // Numeric memos: not forwarded through the policy path.
        // The envelope divergence check is the integrity backstop.
        stellar_xdr::Memo::Id(_) => Ok(None),
        // Hash and Return memos remain absent from the legacy text `memo`
        // field. `decode_pay_args` surfaces their bytes separately.
        stellar_xdr::Memo::Hash(_) | stellar_xdr::Memo::Return(_) => Ok(None),
    }
}

fn structured_memo_field(memo: &stellar_xdr::Memo) -> Option<(&'static str, String)> {
    match memo {
        stellar_xdr::Memo::Hash(hash) => Some(("memo_hash", crate::hex::encode(&hash.0))),
        stellar_xdr::Memo::Return(hash) => Some(("memo_return", crate::hex::encode(&hash.0))),
        _ => None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Public entry point
// ─────────────────────────────────────────────────────────────────────────────

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
///   "destination": "G...",
///   "amount_stroops": "<decimal i64 stroops>",
///   "asset": "XLM" | "CODE:Gissuer",
///   "memo": "text" | null,
///   "memo_hash": "<64 lowercase hex chars, only for Memo::Hash>",
///   "memo_return": "<64 lowercase hex chars, only for Memo::Return>"
/// }
/// ```
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
/// - `EnvelopeDecodeError::SourceAccountEncodeFailed` — source G-strkey encode error.
/// - `EnvelopeDecodeError::DestinationAccountEncodeFailed` — destination G-strkey encode error.
/// - [`EnvelopeDecodeError::IssuerEncodeFailed`] — asset issuer G-strkey encode error.
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
    use stellar_xdr::{ReadXdr, TransactionEnvelope};

    // 1. Validate tool name before touching the XDR (fail fast on bad tool).
    match tool {
        "stellar_pay_commit"
        | "stellar_create_account_commit"
        | "stellar_trustline_commit"
        | "stellar_claim_commit" => {}
        _ => {
            return Err(EnvelopeDecodeError::UnsupportedTool {
                tool: tool.to_owned(),
            });
        }
    }

    // 2. Decode base64 → raw XDR bytes (via from_xdr_base64).
    //    Bounded limits are required because the envelope is caller-supplied and
    //    untrusted. A deeply nested `SorobanAuthorizedInvocation.sub_invocations`
    //    chain would otherwise exhaust the stack (the XDR reader calls
    //    `with_limited_depth` per recursive node). Both depth and len are capped:
    //    depth prevents stack exhaustion, len prevents an oversized-allocation
    //    attack from a forged length field.
    let envelope = TransactionEnvelope::from_xdr_base64(
        envelope_xdr_b64,
        stellar_agent_xdr_limits::untrusted_decode_limits(envelope_xdr_b64.len()),
    )
    .map_err(|e| {
        // Do NOT include raw bytes in the detail — only the error kind.
        // Decode failures must not echo XDR byte content.
        EnvelopeDecodeError::XdrDecode {
            detail: e.to_string(),
        }
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
    let op = &tx.operations[0];

    // 5. Resolve the effective source account (op-level overrides tx-level).
    let effective_source_muxed: &stellar_xdr::MuxedAccount = match &op.source_account {
        Some(op_src) => op_src,
        None => &tx.source_account,
    };
    // muxed_account_to_strkey is infallible for XDR-decoded keys.
    let source_strkey = muxed_account_to_strkey(effective_source_muxed);

    // 6. Dispatch by tool.
    match tool {
        "stellar_pay_commit" => decode_pay_args(&tx.memo, tx.fee, op, &source_strkey, tool),
        "stellar_create_account_commit" => {
            decode_create_account_args(tx.fee, op, &source_strkey, tool)
        }
        "stellar_trustline_commit" => decode_change_trust_args(tx.fee, op, &source_strkey, tool),
        "stellar_claim_commit" => decode_claim_args(tx.fee, op, &source_strkey, tool),
        // The validation above is exhaustive; this arm is unreachable.
        _ => unreachable!("tool name validated in step 1"),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool-specific decoders
// ─────────────────────────────────────────────────────────────────────────────

/// Extracts `stellar_pay` policy-engine args from a `Payment`,
/// `PathPaymentStrictReceive`, or `PathPaymentStrictSend` operation.
fn decode_pay_args(
    memo: &stellar_xdr::Memo,
    total_fee_stroops: u32,
    op: &stellar_xdr::Operation,
    source_strkey: &str,
    tool: &'static str,
) -> Result<serde_json::Value, EnvelopeDecodeError> {
    use stellar_xdr::OperationBody;

    let (dest_muxed, asset, amount_stroops) = match &op.body {
        OperationBody::Payment(p) => (&p.destination, &p.asset, p.amount),

        OperationBody::PathPaymentStrictReceive(pp) => {
            // For path payments, destination and dest_asset are the
            // policy-engine's "destination" and "asset" fields; the amount
            // is dest_amount (what the recipient actually receives).
            (&pp.destination, &pp.dest_asset, pp.dest_amount)
        }

        OperationBody::PathPaymentStrictSend(pp) => {
            // For strict-send, destination and dest_asset are the target;
            // send_amount is the amount the sender pays (authoritative).
            // The policy engine receives the sent amount for cap checks.
            (&pp.destination, &pp.dest_asset, pp.send_amount)
        }

        other => {
            return Err(EnvelopeDecodeError::OperationKindMismatch {
                tool,
                expected: "Payment, PathPaymentStrictReceive, or PathPaymentStrictSend",
                found: op_body_kind_name(other).to_owned(),
            });
        }
    };

    // muxed_account_to_strkey is infallible for XDR-decoded keys.
    let dest_strkey = muxed_account_to_strkey(dest_muxed);

    // xdr_asset_to_string returns EnvelopeDecodeError directly.
    let asset_str = xdr_asset_to_string(asset)?;

    let memo_opt = memo_to_optional_string(memo)?;

    let mut args = serde_json::json!({
        "source": source_strkey,
        "total_fee_stroops": total_fee_stroops,
        "destination": dest_strkey,
        "amount_stroops": amount_stroops.to_string(),
        "asset": asset_str,
        "memo": memo_opt,
    });
    if let Some((field, value)) = structured_memo_field(memo)
        && let Some(obj) = args.as_object_mut()
    {
        obj.insert(field.to_owned(), serde_json::Value::String(value));
    }

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
    fn memo_id_returns_null_without_structured_memo_fields() {
        let op = Operation {
            source_account: None,
            body: OperationBody::Payment(PaymentOp {
                destination: g_to_muxed(DEST_G),
                asset: Asset::Native,
                amount: 10_000_000,
            }),
        };
        let env = build_envelope(SOURCE_G, op, Memo::Id(42));
        let xdr_b64 = to_b64(&env);

        let result = decode_authoritative_args(&xdr_b64, "stellar_pay_commit")
            .expect("Memo::Id must not cause a decode error");
        assert_eq!(result["memo"], serde_json::Value::Null);
        assert!(result.get("memo_hash").is_none());
        assert!(result.get("memo_return").is_none());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Memo::Text with invalid UTF-8 → XdrDecode error
    // ─────────────────────────────────────────────────────────────────────────

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
            matches!(err, EnvelopeDecodeError::UnsupportedTool { .. }),
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
    // PathPaymentStrictSend extracted with send_amount (authoritative amount)
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn path_payment_strict_send_extracts_send_amount() {
        use stellar_xdr::{AlphaNum4, AssetCode4, PathPaymentStrictSendOp};
        let mut code_bytes = [0u8; 4];
        code_bytes[..4].copy_from_slice(b"USDC");
        let op = Operation {
            source_account: None,
            body: OperationBody::PathPaymentStrictSend(PathPaymentStrictSendOp {
                send_asset: Asset::Native,
                send_amount: 5_000_000, // 0.5 XLM sent (authoritative for policy cap)
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
        assert_eq!(result["amount_stroops"], "5000000");
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
}
