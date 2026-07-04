//! WebAuthn `WebAuthnSigData` host-side mirror and XDR encoders.
//!
//! Provides the wallet-side encoders that produce the inner-encoding bytes
//! for an External-arm signer entry in the `AuthPayload` `signers` Map.
//! The [`WebAuthnAssertion`] data type itself lives next to the `Signer`
//! trait at `crates/stellar-agent-network/src/signing/mod.rs`
//! at `stellar-agent-network::signing`; this module re-exports it via
//! `pub use` for ergonomic callers within `stellar-agent-smart-account`.
//!
//! # Wire shape (canonical source)
//!
//! OpenZeppelin stellar-contracts v0.7.2
//! declares the on-chain contracttype. The `soroban-sdk-macros` derive path
//! (`derive_struct.rs`, `derive_type_struct`) sorts struct fields
//! **alphabetically by field name** before emitting the ScVal::Map entries.
//! For `WebAuthnSigData`, the wire-encoded key order is therefore:
//!
//! 1. `authenticator_data` → `ScVal::Bytes`
//! 2. `client_data`        → `ScVal::Bytes`
//! 3. `signature`          → `ScVal::Bytes(BytesN<64>)` (64-byte compact r||s)
//!
//! # Double-XDR pattern
//!
//! The `<inner-encoding>` bytes placed as the value of an External-arm signer
//! entry in the `AuthPayload` `signers` Map are the XDR serialisation of the
//! `WebAuthnSigData` `ScVal::Map`. This is the "double-XDR" pattern: the
//! ScVal is XDR-encoded to bytes, and those bytes are then wrapped in
//! `ScVal::Bytes(<inner-encoding>)`. For
//! ed25519 (Delegated arm) the inner-XDR step is degenerate (raw 64 bytes);
//! for WebAuthn (External arm) the inner-XDR step encodes the full
//! `WebAuthnSigData` ScVal::Map.

use stellar_xdr::{BytesM, Limits, ScBytes, ScMap, ScMapEntry, ScSymbol, ScVal, VecM, WriteXdr};

pub use stellar_agent_network::signing::WebAuthnAssertion;

use crate::SaError;

// ─────────────────────────────────────────────────────────────────────────────
// Public encoders
// ─────────────────────────────────────────────────────────────────────────────

/// Encode a [`WebAuthnAssertion`] as the canonical `WebAuthnSigData`
/// `ScVal::Map`.
///
/// # Canonical source
///
/// OpenZeppelin stellar-contracts v0.7.2
/// (`#[contracttype]` declaration). The on-chain `from_xdr` deserialiser
/// expects the three named fields keyed by `authenticator_data` /
/// `client_data` / `signature`.
///
/// # Wire shape
///
/// `ScVal::Map` with three `ScMapEntry` rows. ScMap key order follows the
/// alphabetical sort applied by `soroban-sdk-macros` `derive_type_struct`
/// (`derive_struct.rs`).
/// For `WebAuthnSigData` the wire-encoded order is:
///
/// 1. `authenticator_data` → `ScVal::Bytes`
/// 2. `client_data`        → `ScVal::Bytes`
/// 3. `signature`          → `ScVal::Bytes(BytesN<64>)`
///
/// **Empirical verification:** the byte-parity gate
/// `webauthn_sigdata_inner_encoding_parity_with_onchain_canonical` at
/// `tests/wallet_install_arg_parity.rs` exercises this against a fixed
/// fixture cross-encoded through the soroban-sdk-side `WebAuthnSigData`
/// type imported from the OZ `stellar-accounts` v0.7.2 crate.
///
/// # Errors
///
/// Returns [`SaError::AuthEntryConstructionFailed`] with `stage: "auth_payload"`
/// if `ScSymbol::try_from`, `BytesM::try_from`, or `VecM::try_from` reject
/// the input (unreachable on well-formed inputs within on-chain size limits).
pub fn encode_webauthn_sig_data_scval(a: &WebAuthnAssertion) -> Result<ScVal, SaError> {
    let auth_payload_err = |reason: String| SaError::AuthEntryConstructionFailed {
        stage: "auth_payload",
        redacted_reason: reason,
    };

    // `authenticator_data` field — key alphabetically first.
    let auth_data_sym = ScSymbol::try_from("authenticator_data")
        .map_err(|e| auth_payload_err(format!("encode authenticator_data symbol: {e:?}")))?;
    let auth_data_bytesm: BytesM = a
        .authenticator_data
        .clone()
        .try_into()
        .map_err(|e| auth_payload_err(format!("encode authenticator_data BytesM: {e:?}")))?;
    let auth_data_val = ScVal::Bytes(ScBytes(auth_data_bytesm));

    // `client_data` field — key alphabetically second.
    let client_data_sym = ScSymbol::try_from("client_data")
        .map_err(|e| auth_payload_err(format!("encode client_data symbol: {e:?}")))?;
    let client_data_bytesm: BytesM = a
        .client_data_json
        .clone()
        .try_into()
        .map_err(|e| auth_payload_err(format!("encode client_data BytesM: {e:?}")))?;
    let client_data_val = ScVal::Bytes(ScBytes(client_data_bytesm));

    // `signature` field — key alphabetically third (BytesN<64> on-chain, BytesM
    // wallet-side; 64-byte payload length is invariant).
    //
    // On-chain type is `BytesN<64>` per the OpenZeppelin smart-account contract;
    // the XDR encoding of `BytesN<N>` and `Bytes(N bytes)` is byte-identical
    // because both produce `ScVal::Bytes(ScBytes(BytesM))` with the same byte
    // payload. The `soroban-sdk` `From<&BytesN<N>> for ScVal` path calls
    // `ScVal::try_from_val`, routing the `BytesObject` host value to
    // `ScVal::Bytes(ScBytes(BytesM))`. `ScBytes` is a `BytesM` wrapper and
    // `BytesM` is a length-bounded `Vec<u8>`. XDR-encoding of a `BytesM` is
    // `len(u32) + bytes + padding-to-4`, identical regardless of the Rust
    // wrapper type. The wallet's `BytesM` at fixed 64 bytes is therefore
    // byte-equivalent to the on-chain `BytesN<64>` payload — empirically
    // pinned by the byte-parity gate
    // `webauthn_sigdata_inner_encoding_parity_with_onchain_canonical` at
    // `tests/wallet_install_arg_parity.rs`.
    let signature_sym = ScSymbol::try_from("signature")
        .map_err(|e| auth_payload_err(format!("encode signature symbol: {e:?}")))?;
    let signature_bytesm: BytesM = a
        .signature_compact
        .to_vec()
        .try_into()
        .map_err(|e| auth_payload_err(format!("encode signature BytesM: {e:?}")))?;
    let signature_val = ScVal::Bytes(ScBytes(signature_bytesm));

    // ScMap with three entries in alphabetical key order.
    let entries: VecM<ScMapEntry> = vec![
        ScMapEntry {
            key: ScVal::Symbol(auth_data_sym),
            val: auth_data_val,
        },
        ScMapEntry {
            key: ScVal::Symbol(client_data_sym),
            val: client_data_val,
        },
        ScMapEntry {
            key: ScVal::Symbol(signature_sym),
            val: signature_val,
        },
    ]
    .try_into()
    .map_err(|e| auth_payload_err(format!("encode WebAuthnSigData ScMap: {e:?}")))?;

    Ok(ScVal::Map(Some(ScMap(entries))))
}

/// Produce the `<inner-encoding>` bytes for an External-arm signer entry —
/// the byte-string that goes into `ScVal::Bytes(<inner-encoding>)` as the
/// value of the `AuthPayload` `signers` Map for a WebAuthn signer.
///
/// This is the "double-XDR" pattern: the `WebAuthnSigData` ScVal is
/// XDR-encoded to bytes BEFORE being wrapped in `ScVal::Bytes`. For
/// ed25519 (Delegated arm) the inner-XDR step is degenerate (raw 64 bytes
/// pass through via `auth_entry.rs`); for WebAuthn (External arm) the
/// inner-XDR step encodes the `WebAuthnSigData` ScVal::Map.
///
/// # Errors
///
/// Returns [`SaError::AuthEntryConstructionFailed`] with `stage: "auth_payload"`
/// if [`encode_webauthn_sig_data_scval`] fails or if the resulting ScVal
/// cannot be XDR-encoded (the latter is unreachable for well-formed inputs
/// within on-chain size limits).
pub fn encode_webauthn_signature_value_bytes(a: &WebAuthnAssertion) -> Result<Vec<u8>, SaError> {
    let auth_payload_err = |reason: String| SaError::AuthEntryConstructionFailed {
        stage: "auth_payload",
        redacted_reason: reason,
    };

    let sig_data_scval = encode_webauthn_sig_data_scval(a)?;

    WriteXdr::to_xdr(&sig_data_scval, Limits::none())
        .map_err(|e| auth_payload_err(format!("XDR-encode WebAuthnSigData ScVal: {e:?}")))
}
