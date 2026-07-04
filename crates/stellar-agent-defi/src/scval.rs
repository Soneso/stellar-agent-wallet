//! Shared `ScVal`-encoding primitives for the DeFi protocol adapter crates.
//!
//! Blend, DeFindex, and the DEX adapter each build Soroban `InvokeContractArgs`
//! for their own protocol's contract calls. The two primitives below are the
//! encoding steps that do not vary by protocol — contract-address resolution
//! and `i128` encoding — so one implementation backs all three call sites
//! instead of three copies that could silently drift. Protocol-specific
//! argument shapes (which fields, in which order) stay in each protocol
//! crate's own `scval` module.

use stellar_xdr::{ContractId, Hash, Int128Parts, ScAddress, ScVal};

/// Converts a contract C-strkey to a [`ScAddress::Contract`].
///
/// # Errors
///
/// Returns [`stellar_strkey::DecodeError`] when `address` is not a valid
/// Stellar C-strkey.
pub fn contract_strkey_to_sc_address(
    address: &str,
) -> Result<ScAddress, stellar_strkey::DecodeError> {
    let contract = stellar_strkey::Contract::from_string(address)?;
    Ok(ScAddress::Contract(ContractId(Hash(contract.0))))
}

/// Encodes an `i128` value as `ScVal::I128(Int128Parts { hi, lo })`.
///
/// Encoding per stellar-xdr `types.rs`: `lo = v as u64`, `hi = (v >> 64) as i64`.
#[must_use]
pub fn encode_i128(v: i128) -> ScVal {
    ScVal::I128(Int128Parts {
        #[allow(clippy::cast_possible_truncation)]
        lo: v as u64,
        #[allow(clippy::cast_possible_truncation)]
        hi: (v >> 64) as i64,
    })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only"
    )]
    use stellar_xdr::ScVal;

    use super::*;

    #[test]
    fn contract_strkey_round_trips_to_sc_address() {
        // A syntactically valid C-strkey (32 zero payload bytes + checksum).
        let contract = stellar_strkey::Contract([0u8; 32]);
        let strkey = contract.to_string();
        let addr = contract_strkey_to_sc_address(&strkey).expect("valid C-strkey must decode");
        assert_eq!(addr, ScAddress::Contract(ContractId(Hash([0u8; 32]))));
    }

    #[test]
    fn rejects_non_contract_strkey() {
        // A G-strkey (ed25519 public key) is not a valid contract strkey.
        let g_strkey = stellar_strkey::ed25519::PublicKey([0u8; 32]).to_string();
        assert!(contract_strkey_to_sc_address(&g_strkey).is_err());
    }

    #[test]
    fn encode_i128_zero() {
        assert_eq!(encode_i128(0), ScVal::I128(Int128Parts { hi: 0, lo: 0 }));
    }

    #[test]
    fn encode_i128_positive() {
        assert_eq!(encode_i128(1), ScVal::I128(Int128Parts { hi: 0, lo: 1 }));
    }

    #[test]
    fn encode_i128_negative() {
        // -1_i128 as (hi, lo) is (-1, u64::MAX) per two's-complement split.
        assert_eq!(
            encode_i128(-1),
            ScVal::I128(Int128Parts {
                hi: -1,
                lo: u64::MAX
            })
        );
    }
}
