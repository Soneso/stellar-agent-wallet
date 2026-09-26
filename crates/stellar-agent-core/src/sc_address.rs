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
//!
//! The module also builds the ledger key of a CAP-85 executable-tag entry
//! ([`crate::sc_address::executable_tag_ledger_key`]) and its SHA-256 digest
//! ([`crate::sc_address::executable_tag_key_digest`]), which identifies one
//! owner and tag pair across the network fetch, the smart-account pin and the
//! audit log.

use sha2::{Digest as _, Sha256};
use stellar_xdr::{
    AccountId, ContractDataDurability, ContractId, Hash, LedgerKey, LedgerKeyContractData, Limits,
    PublicKey, ScAddress, ScString, ScVal, Uint256, WriteXdr,
};

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

/// Returns the ledger key of the persistent `ContractData` entry in which
/// `owner` stores the Wasm hash for an external-reference `tag`
/// (`ScVal::ExecutableTag(tag)`, persistent durability).
///
/// A CAP-85 instance whose executable is
/// `ContractExecutable::ExternalRef { executable_owner, tag }` runs the Wasm
/// whose hash this entry holds.
#[must_use]
pub fn executable_tag_ledger_key(owner: &ScAddress, tag: &ScString) -> LedgerKey {
    LedgerKey::ContractData(LedgerKeyContractData {
        contract: owner.clone(),
        key: ScVal::ExecutableTag(tag.clone()),
        durability: ContractDataDurability::Persistent,
    })
}

/// Returns the SHA-256 digest of the XDR encoding of
/// [`executable_tag_ledger_key`] for `owner` and `tag`.
///
/// Two external references name the same owner-managed code slot exactly when
/// their digests are equal, so the digest is the identity a pin records and a
/// later observation is compared against. The owner and the tag are
/// ledger-supplied; the digest carries neither in readable form.
///
/// # Errors
///
/// Returns the XDR encoder's error when the key cannot be encoded. The key is
/// built from values that already passed XDR length checks and is encoded
/// without depth or length limits, so no current input produces an error.
pub fn executable_tag_key_digest(
    owner: &ScAddress,
    tag: &ScString,
) -> Result<[u8; 32], stellar_xdr::Error> {
    let key_xdr = executable_tag_ledger_key(owner, tag).to_xdr(Limits::none())?;
    Ok(Sha256::digest(key_xdr).into())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, reason = "test-only assertions")]

    use super::*;
    use stellar_xdr::{ClaimableBalanceId, MuxedEd25519Account, PoolId};

    fn tag(bytes: &[u8]) -> ScString {
        ScString(bytes.to_vec().try_into().unwrap())
    }

    #[test]
    fn executable_tag_ledger_key_is_the_owner_persistent_executable_tag_key() {
        let owner = ScAddress::Contract(ContractId(Hash([7u8; 32])));
        let LedgerKey::ContractData(key) = executable_tag_ledger_key(&owner, &tag(b"v1")) else {
            panic!("executable tag key must be a contract-data key");
        };
        assert_eq!(key.contract, owner);
        assert_eq!(key.key, ScVal::ExecutableTag(tag(b"v1")));
        assert_eq!(key.durability, ContractDataDurability::Persistent);
    }

    #[test]
    fn executable_tag_key_digest_is_the_sha256_of_the_key_xdr() {
        let owner = ScAddress::Contract(ContractId(Hash([7u8; 32])));
        let key_xdr = executable_tag_ledger_key(&owner, &tag(b"v1"))
            .to_xdr(Limits::none())
            .unwrap();
        let expected: [u8; 32] = Sha256::digest(key_xdr).into();
        assert_eq!(
            executable_tag_key_digest(&owner, &tag(b"v1")).unwrap(),
            expected
        );
    }

    #[test]
    fn executable_tag_key_digest_separates_owner_and_tag() {
        let owner = ScAddress::Contract(ContractId(Hash([7u8; 32])));
        let other_owner = ScAddress::Contract(ContractId(Hash([8u8; 32])));
        let base = executable_tag_key_digest(&owner, &tag(b"v1")).unwrap();
        assert_eq!(
            base,
            executable_tag_key_digest(&owner, &tag(b"v1")).unwrap()
        );
        assert_ne!(
            base,
            executable_tag_key_digest(&owner, &tag(b"v2")).unwrap()
        );
        assert_ne!(
            base,
            executable_tag_key_digest(&other_owner, &tag(b"v1")).unwrap()
        );
    }

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
