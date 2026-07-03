//! SAC `transfer` invocation builder for Soroban SEP-41 tokens.
//!
//! Builds the [`InvokeContractArgs`] for a `transfer(from, to, amount)` call
//! against any SEP-41 token contract (e.g. a USDC Stellar Asset Contract).
//!
//! # Encoding
//!
//! Amounts are encoded as `ScVal::I128` via the canonical `From<i128>`
//! conversion provided by `stellar-xdr`.
//!
//! # SEP-41 interface
//!
//! The `transfer(from: Address, to: Address, amount: i128)` method is defined
//! by the SEP-41 token standard.  The invocation shape matches the
//! @x402/stellar reference implementation.

use stellar_strkey::Strkey;
use stellar_xdr::{ContractId, InvokeContractArgs, ScAddress, ScSymbol, ScVal, StringM, VecM};

use crate::X402Error;

// ─────────────────────────────────────────────────────────────────────────────
// ScVal helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Converts a G- or C-strkey to [`ScAddress`] for the SAC asset contract.
///
/// Accepts G-strkeys (classic accounts, `PublicKeyEd25519`) and C-strkeys
/// (contract addresses). Muxed (M) strkeys are rejected here; the recipient
/// converter [`strkey_to_recipient_sc_address`] is the one that accepts muxed
/// addresses.
///
/// # Errors
///
/// - [`X402Error::InvalidAssetAddress`] if the strkey is malformed or not a
///   G- or C-type.
fn strkey_to_sc_address(strkey: &str) -> Result<ScAddress, X402Error> {
    use stellar_xdr::{AccountId, Hash, PublicKey, Uint256};

    let parsed = Strkey::from_string(strkey).map_err(|e| X402Error::InvalidAssetAddress {
        detail: format!("strkey parse failed for {strkey:?}: {e}"),
    })?;
    match parsed {
        Strkey::PublicKeyEd25519(pk) => {
            let account_id = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk.0)));
            Ok(ScAddress::Account(account_id))
        }
        Strkey::Contract(c) => {
            // Contract strkey carries a raw 32-byte hash used as the contract
            // ID.  ScAddress::Contract wraps ContractId(Hash([u8; 32])).
            Ok(ScAddress::Contract(ContractId(Hash(c.0))))
        }
        other => Err(X402Error::InvalidAssetAddress {
            detail: format!("strkey {strkey:?} is not a G- or C-strkey (got {other:?})"),
        }),
    }
}

/// Converts a recipient strkey (G-, C-, or M-strkey) to [`ScAddress`].
///
/// The x402 `pay_to` recipient may be a classic account (G), a contract (C), or
/// a muxed account (M); the `@x402/stellar` scheme accepts all three. A muxed
/// recipient's `id` is preserved in the on-chain `ScAddress::MuxedAccount`.
///
/// # Errors
///
/// - [`X402Error::InvalidRecipientAddress`] if the strkey is malformed or is not
///   a G-, C-, or M-strkey.
fn strkey_to_recipient_sc_address(strkey: &str) -> Result<ScAddress, X402Error> {
    use stellar_xdr::{AccountId, ContractId, Hash, MuxedEd25519Account, PublicKey, Uint256};

    let parsed = Strkey::from_string(strkey).map_err(|e| X402Error::InvalidRecipientAddress {
        detail: format!("recipient strkey parse failed for {strkey:?}: {e}"),
    })?;
    match parsed {
        Strkey::PublicKeyEd25519(pk) => Ok(ScAddress::Account(AccountId(
            PublicKey::PublicKeyTypeEd25519(Uint256(pk.0)),
        ))),
        Strkey::Contract(c) => Ok(ScAddress::Contract(ContractId(Hash(c.0)))),
        Strkey::MuxedAccountEd25519(m) => Ok(ScAddress::MuxedAccount(MuxedEd25519Account {
            id: m.id,
            ed25519: Uint256(m.ed25519),
        })),
        other => Err(X402Error::InvalidRecipientAddress {
            detail: format!(
                "recipient strkey {strkey:?} is not a G-, C-, or M-strkey (got {other:?})"
            ),
        }),
    }
}

/// Converts the payer's G-strkey to its `ScAddress::Account` representation.
///
/// The payer of a SAC `transfer` must be a classic account; C- and M-strkeys
/// are rejected.
///
/// # Errors
///
/// - [`X402Error::InvalidPayerAddress`] if the strkey is malformed or not a
///   G-strkey.
pub(crate) fn g_strkey_to_account_address(g_strkey: &str) -> Result<ScAddress, X402Error> {
    use stellar_xdr::{AccountId, PublicKey, Uint256};
    match Strkey::from_string(g_strkey) {
        Ok(Strkey::PublicKeyEd25519(pk)) => Ok(ScAddress::Account(AccountId(
            PublicKey::PublicKeyTypeEd25519(Uint256(pk.0)),
        ))),
        Ok(_other) => Err(X402Error::InvalidPayerAddress {
            detail: format!("payer strkey {g_strkey:?} is not a G-strkey"),
        }),
        Err(e) => Err(X402Error::InvalidPayerAddress {
            detail: format!("payer strkey parse failed for {g_strkey:?}: {e}"),
        }),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SAC transfer builder
// ─────────────────────────────────────────────────────────────────────────────

/// Builds an [`InvokeContractArgs`] for a SEP-41 SAC `transfer` invocation.
///
/// Constructs the `transfer(from: Address, to: Address, amount: i128)` call
/// shape for any SEP-41 token contract.
///
/// # Arguments
///
/// - `sac_contract` — C-strkey of the SAC contract address.
/// - `from` — G-strkey of the sender (the payer; signs the auth entry).
/// - `to` — G-, C-, or M-strkey of the recipient (`payTo`).
/// - `amount` — atomic token units (e.g. 7-decimal USDC: 1 USDC = 10_000_000).
///
/// # Errors
///
/// - [`X402Error::InvalidAssetAddress`] if `sac_contract` or `to` fails to parse.
/// - [`X402Error::InvalidPayerAddress`] if `from` is not a valid G-strkey.
/// - [`X402Error::TransactionBuildFailed`] if the arg-list `VecM` construction
///   fails (only if arg count exceeds `VecM` capacity, which cannot occur here).
///
/// # Examples
///
/// ```
/// use stellar_agent_x402::sac_transfer::build_sac_transfer_invoke;
///
/// // Build a SAC transfer using structurally valid strkeys.
/// // G-strkey below is derived from an all-zero 32-byte ed25519 public key.
/// let sac  = "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA";
/// let from = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
/// let to   = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
/// let _ = build_sac_transfer_invoke(sac, from, to, 10_000_000_i128).unwrap();
/// ```
pub fn build_sac_transfer_invoke(
    sac_contract: &str,
    from: &str,
    to: &str,
    amount: i128,
) -> Result<InvokeContractArgs, X402Error> {
    let contract_address = strkey_to_sc_address(sac_contract)?;
    let from_sc = g_strkey_to_account_address(from)?;
    let to_sc = strkey_to_recipient_sc_address(to)?;

    // SEP-41 `transfer` signature:
    //   transfer(from: Address, to: Address, amount: i128) -> ()
    let args_vec: Vec<ScVal> = vec![
        ScVal::Address(from_sc),
        ScVal::Address(to_sc),
        ScVal::from(amount),
    ];

    let args: VecM<ScVal> = args_vec
        .try_into()
        .map_err(|e| X402Error::TransactionBuildFailed {
            detail: format!("SAC transfer args VecM construction failed: {e:?}"),
        })?;

    // `ScSymbol` wraps a `StringM<32>` (max 32 bytes).
    // "transfer" is 8 bytes — well within the limit.
    let function_name_str: StringM<32> =
        "transfer"
            .try_into()
            .map_err(|e| X402Error::TransactionBuildFailed {
                detail: format!("ScSymbol construction failed: {e:?}"),
            })?;
    let function_name = ScSymbol(function_name_str);

    Ok(InvokeContractArgs {
        contract_address,
        function_name,
        args,
    })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics and unwraps acceptable in unit tests"
    )]

    use super::*;

    // ── g_strkey_to_account_address ────────────────────────────────────────────

    #[test]
    fn g_strkey_to_account_address_g_strkey_ok() {
        let g = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
        let result = g_strkey_to_account_address(g);
        assert!(
            matches!(result, Ok(ScAddress::Account(_))),
            "G-strkey must convert to ScAddress::Account, got {result:?}"
        );
    }

    #[test]
    fn g_strkey_to_account_address_c_strkey_rejected() {
        let c = "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA";
        assert!(
            matches!(
                g_strkey_to_account_address(c),
                Err(X402Error::InvalidPayerAddress { .. })
            ),
            "C-strkey must be rejected as payer with InvalidPayerAddress"
        );
    }

    #[test]
    fn g_strkey_to_account_address_invalid_rejected() {
        assert!(
            matches!(
                g_strkey_to_account_address("not-a-strkey"),
                Err(X402Error::InvalidPayerAddress { .. })
            ),
            "malformed strkey must be rejected as payer with InvalidPayerAddress"
        );
    }

    // ── build_sac_transfer_invoke ──────────────────────────────────────────────

    #[test]
    fn build_sac_transfer_invoke_succeeds_with_valid_strkeys() {
        // G-strkey from all-zero 32-byte ed25519 public key (structurally valid).
        let sac = "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA";
        let from = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
        let to = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
        let result = build_sac_transfer_invoke(sac, from, to, 10_000_000);
        assert!(result.is_ok());
        let invoke = result.unwrap();
        // Verify function name is "transfer"
        assert_eq!(invoke.function_name.0.to_utf8_string_lossy(), "transfer");
        // Verify arg count: from, to, amount
        assert_eq!(invoke.args.len(), 3);
        // Third arg must be I128
        assert!(matches!(&invoke.args[2], ScVal::I128(_)));
    }

    #[test]
    fn build_sac_transfer_invoke_rejects_bad_asset_strkey() {
        let from = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
        let result = build_sac_transfer_invoke("not-a-strkey", from, from, 1);
        assert!(matches!(result, Err(X402Error::InvalidAssetAddress { .. })));
    }

    #[test]
    fn build_sac_transfer_invoke_rejects_c_strkey_as_payer() {
        // The `from` argument must be a G-strkey; C-strkeys are rejected.
        let sac = "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA";
        let to = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
        let result = build_sac_transfer_invoke(sac, sac, to, 1);
        assert!(
            matches!(result, Err(X402Error::InvalidPayerAddress { .. })),
            "C-strkey as payer must return InvalidPayerAddress, got {result:?}"
        );
    }

    #[test]
    fn build_sac_transfer_zero_amount() {
        let sac = "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA";
        let from = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
        let to = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
        let invoke = build_sac_transfer_invoke(sac, from, to, 0).unwrap();
        // The amount arg must encode as ScVal::I128 with value zero.
        assert!(
            matches!(
                &invoke.args[2],
                ScVal::I128(stellar_xdr::Int128Parts { hi: 0, lo: 0 })
            ),
            "zero amount must encode as I128(0,0), got {:?}",
            invoke.args[2]
        );
    }

    #[test]
    fn build_sac_transfer_function_name_is_transfer() {
        let sac = "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA";
        let from = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
        let to = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
        let invoke = build_sac_transfer_invoke(sac, from, to, 1_i128).unwrap();
        assert_eq!(invoke.function_name.0.to_utf8_string_lossy(), "transfer");
    }

    #[test]
    fn build_sac_transfer_invoke_accepts_muxed_recipient() {
        // A muxed (M) recipient must be accepted and encoded as
        // ScAddress::MuxedAccount with the multiplexing id preserved.
        let sac = "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA";
        let from = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
        let muxed_to = stellar_strkey::ed25519::MuxedAccount {
            ed25519: [0u8; 32],
            id: 7,
        }
        .to_string();
        let invoke = build_sac_transfer_invoke(sac, from, &muxed_to, 1_i128).unwrap();
        assert!(
            matches!(&invoke.args[1], ScVal::Address(ScAddress::MuxedAccount(m)) if m.id == 7),
            "muxed recipient must encode as ScAddress::MuxedAccount with the id preserved"
        );
    }

    #[test]
    fn build_sac_transfer_invoke_rejects_malformed_recipient() {
        let sac = "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA";
        let from = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
        let result = build_sac_transfer_invoke(sac, from, "not-a-strkey", 1);
        assert!(
            matches!(result, Err(X402Error::InvalidRecipientAddress { .. })),
            "malformed recipient must surface as InvalidRecipientAddress, got {result:?}"
        );
    }
}
