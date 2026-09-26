//! Strkey rendering for XDR [`stellar_xdr::ScAddress`] values.
//!
//! Account (`G...`) and contract (`C...`) addresses have a canonical strkey
//! form that every wallet surface renders. The remaining `ScAddress` variants
//! (muxed account, claimable balance, liquidity pool) are never valid
//! principals on the wallet's signing, pinning or storage-inspection paths,
//! so [`crate::sc_address::scaddress_to_strkey`] returns a typed
//! [`crate::sc_address::ScAddressStrkeyError`] for them and callers that only
//! display the address render
//! [`crate::sc_address::UNSUPPORTED_ADDRESS_PLACEHOLDER`] instead.

use stellar_xdr::{AccountId, ContractId, Hash, PublicKey, ScAddress, Uint256};

/// Fixed display text for an [`ScAddress`] that has no account or contract
/// strkey form.
///
/// Display-only callers render this placeholder so a ledger-supplied address
/// of an unexpected variant never reaches a message as its `Debug` form.
pub const UNSUPPORTED_ADDRESS_PLACEHOLDER: &str = "<unsupported address>";

/// Error returned by [`scaddress_to_strkey`] for an address variant that has
/// no account or contract strkey form.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("address variant {variant} has no account or contract strkey form")]
pub struct ScAddressStrkeyError {
    /// XDR variant name of the rejected address (for example `MuxedAccount`).
    pub variant: &'static str,
}

/// Renders an account or contract [`ScAddress`] as its canonical strkey.
///
/// `stellar_strkey` returns a fixed-capacity `heapless::String` from its
/// inherent `to_string`; the result is converted through `as_str()` so the
/// returned value is an owned `std::string::String`.
///
/// # Errors
///
/// Returns [`ScAddressStrkeyError`] for every variant other than
/// `ScAddress::Account` and `ScAddress::Contract`.
pub fn scaddress_to_strkey(addr: &ScAddress) -> Result<String, ScAddressStrkeyError> {
    match addr {
        ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(bytes)))) => {
            Ok(stellar_strkey::ed25519::PublicKey(*bytes)
                .to_string()
                .as_str()
                .to_owned())
        }
        ScAddress::Contract(ContractId(Hash(bytes))) => Ok(stellar_strkey::Contract(*bytes)
            .to_string()
            .as_str()
            .to_owned()),
        // Every other variant, including feature-gated ones, shares the same
        // typed refusal: none of them is a wallet principal.
        other => Err(ScAddressStrkeyError {
            variant: other.name(),
        }),
    }
}

/// Renders an [`ScAddress`] for a log line or error string: the
/// first-5-last-5 redacted strkey of an account or contract address, or
/// [`UNSUPPORTED_ADDRESS_PLACEHOLDER`] for any other variant.
#[must_use]
pub fn scaddress_redacted(addr: &ScAddress) -> String {
    scaddress_to_strkey(addr).map_or_else(
        |_| UNSUPPORTED_ADDRESS_PLACEHOLDER.to_owned(),
        |strkey| crate::observability::redact_strkey_first5_last5(&strkey),
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test-only assertions")]

    use super::*;
    use stellar_xdr::{ClaimableBalanceId, MuxedEd25519Account, PoolId};

    #[test]
    fn account_address_renders_g_strkey() {
        let addr = ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
            [0u8; 32],
        ))));
        assert_eq!(
            scaddress_to_strkey(&addr).unwrap(),
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF"
        );
    }

    #[test]
    fn contract_address_renders_c_strkey() {
        let addr = ScAddress::Contract(ContractId(Hash([0u8; 32])));
        assert_eq!(
            scaddress_to_strkey(&addr).unwrap(),
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4"
        );
    }

    #[test]
    fn scaddress_redacted_renders_first5_last5_or_placeholder() {
        let contract = ScAddress::Contract(ContractId(Hash([0u8; 32])));
        assert_eq!(scaddress_redacted(&contract), "CAAAA...ABSC4");
        let pool = ScAddress::LiquidityPool(PoolId(Hash([3u8; 32])));
        assert_eq!(scaddress_redacted(&pool), UNSUPPORTED_ADDRESS_PLACEHOLDER);
    }

    #[test]
    fn non_principal_variants_return_typed_error_naming_the_variant() {
        let cases = [
            (
                ScAddress::MuxedAccount(MuxedEd25519Account {
                    id: 7,
                    ed25519: Uint256([1u8; 32]),
                }),
                "MuxedAccount",
            ),
            (
                ScAddress::ClaimableBalance(ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash(
                    [2u8; 32],
                ))),
                "ClaimableBalance",
            ),
            (
                ScAddress::LiquidityPool(PoolId(Hash([3u8; 32]))),
                "LiquidityPool",
            ),
        ];
        for (addr, variant) in cases {
            assert_eq!(
                scaddress_to_strkey(&addr),
                Err(ScAddressStrkeyError { variant }),
                "variant {variant}"
            );
        }
    }
}
