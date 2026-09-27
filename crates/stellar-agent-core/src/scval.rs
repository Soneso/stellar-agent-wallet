//! Variant names for XDR [`stellar_xdr::ScVal`] values.
//!
//! An `ScVal` read from the ledger or returned by a contract is untrusted and
//! may be large (a string or byte payload up to the XDR length limit) or carry
//! addresses. Error messages and log lines that describe an unexpected value
//! name its variant through [`crate::scval::scval_variant_name`] and never
//! render the value.

use stellar_xdr::ScVal;

/// Returns the XDR variant name of `val` (for example `"String"` or `"Map"`).
///
/// The result is a fixed string drawn from the 23 `ScVal` variants, so it is
/// bounded in length and carries no byte of the value's payload. Callers use
/// it to describe an unexpected value in an error message or log line.
#[must_use]
pub fn scval_variant_name(val: &ScVal) -> &'static str {
    match val {
        ScVal::Bool(_) => "Bool",
        ScVal::Void => "Void",
        ScVal::Error(_) => "Error",
        ScVal::U32(_) => "U32",
        ScVal::I32(_) => "I32",
        ScVal::U64(_) => "U64",
        ScVal::I64(_) => "I64",
        ScVal::Timepoint(_) => "Timepoint",
        ScVal::Duration(_) => "Duration",
        ScVal::U128(_) => "U128",
        ScVal::I128(_) => "I128",
        ScVal::U256(_) => "U256",
        ScVal::I256(_) => "I256",
        ScVal::Bytes(_) => "Bytes",
        ScVal::String(_) => "String",
        ScVal::Symbol(_) => "Symbol",
        ScVal::Vec(_) => "Vec",
        ScVal::Map(_) => "Map",
        ScVal::Address(_) => "Address",
        ScVal::LedgerKeyContractInstance => "LedgerKeyContractInstance",
        ScVal::LedgerKeyNonce(_) => "LedgerKeyNonce",
        ScVal::ContractInstance(_) => "ContractInstance",
        ScVal::ExecutableTag(_) => "ExecutableTag",
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only fixture construction"
    )]

    use stellar_xdr::{Int128Parts, ScSymbol, ScVal, UInt128Parts};

    use super::*;

    /// Asserts the exact discriminant name string for ALL 23 stable `ScVal`
    /// variants.  A constant-returning implementation would be caught because
    /// at most one variant can return any single string.
    #[test]
    fn scval_variant_name_exact_name_for_all_23_variants() {
        use stellar_xdr::{
            ContractExecutable, Duration, Int256Parts, ScAddress, ScBytes, ScContractInstance,
            ScError, ScErrorCode, ScMap, ScNonceKey, ScString, ScVec, TimePoint, UInt256Parts,
            Uint256,
        };

        // Bool
        assert_eq!(scval_variant_name(&ScVal::Bool(true)), "Bool");
        assert_eq!(scval_variant_name(&ScVal::Bool(false)), "Bool");
        // Void
        assert_eq!(scval_variant_name(&ScVal::Void), "Void");
        // Error: ScError is an enum; use the Value(ScErrorCode) variant.
        assert_eq!(
            scval_variant_name(&ScVal::Error(ScError::Value(ScErrorCode::InvalidInput))),
            "Error"
        );
        // U32
        assert_eq!(scval_variant_name(&ScVal::U32(0)), "U32");
        // I32
        assert_eq!(scval_variant_name(&ScVal::I32(0)), "I32");
        // U64
        assert_eq!(scval_variant_name(&ScVal::U64(0)), "U64");
        // I64
        assert_eq!(scval_variant_name(&ScVal::I64(0)), "I64");
        // Timepoint
        assert_eq!(
            scval_variant_name(&ScVal::Timepoint(TimePoint(0))),
            "Timepoint"
        );
        // Duration
        assert_eq!(
            scval_variant_name(&ScVal::Duration(Duration(0))),
            "Duration"
        );
        // U128
        assert_eq!(
            scval_variant_name(&ScVal::U128(UInt128Parts { hi: 0, lo: 0 })),
            "U128"
        );
        // I128
        assert_eq!(
            scval_variant_name(&ScVal::I128(Int128Parts { hi: 0, lo: 0 })),
            "I128"
        );
        // U256
        assert_eq!(
            scval_variant_name(&ScVal::U256(UInt256Parts {
                hi_hi: 0,
                hi_lo: 0,
                lo_hi: 0,
                lo_lo: 0,
            })),
            "U256"
        );
        // I256
        assert_eq!(
            scval_variant_name(&ScVal::I256(Int256Parts {
                hi_hi: 0,
                hi_lo: 0,
                lo_hi: 0,
                lo_lo: 0,
            })),
            "I256"
        );
        // Bytes
        assert_eq!(
            scval_variant_name(&ScVal::Bytes(ScBytes(vec![].try_into().unwrap()))),
            "Bytes"
        );
        // String
        assert_eq!(
            scval_variant_name(&ScVal::String(ScString("x".try_into().unwrap()))),
            "String"
        );
        // Symbol
        assert_eq!(
            scval_variant_name(&ScVal::Symbol(ScSymbol("x".try_into().unwrap()))),
            "Symbol"
        );
        // Vec (None)
        assert_eq!(scval_variant_name(&ScVal::Vec(None)), "Vec");
        // Vec (Some empty)
        assert_eq!(
            scval_variant_name(&ScVal::Vec(Some(ScVec(vec![].try_into().unwrap())))),
            "Vec"
        );
        // Map (None)
        assert_eq!(scval_variant_name(&ScVal::Map(None)), "Map");
        // Map (Some empty)
        assert_eq!(
            scval_variant_name(&ScVal::Map(Some(ScMap(vec![].try_into().unwrap())))),
            "Map"
        );
        // Address: an all-zero Ed25519 public key (account address).
        assert_eq!(
            scval_variant_name(&ScVal::Address(ScAddress::Account(stellar_xdr::AccountId(
                stellar_xdr::PublicKey::PublicKeyTypeEd25519(Uint256([0u8; 32],))
            )))),
            "Address"
        );
        // LedgerKeyContractInstance (unit variant, no inner value).
        assert_eq!(
            scval_variant_name(&ScVal::LedgerKeyContractInstance),
            "LedgerKeyContractInstance"
        );
        // LedgerKeyNonce: ScVal::LedgerKeyNonce(ScNonceKey { nonce: i64 }).
        assert_eq!(
            scval_variant_name(&ScVal::LedgerKeyNonce(ScNonceKey { nonce: 0 })),
            "LedgerKeyNonce"
        );
        // ContractInstance
        assert_eq!(
            scval_variant_name(&ScVal::ContractInstance(ScContractInstance {
                executable: ContractExecutable::StellarAsset,
                storage: None,
            })),
            "ContractInstance"
        );
        // ExecutableTag (CAP-85 external-reference tag key).
        assert_eq!(
            scval_variant_name(&ScVal::ExecutableTag(ScString("tag".try_into().unwrap()))),
            "ExecutableTag"
        );
    }
}
