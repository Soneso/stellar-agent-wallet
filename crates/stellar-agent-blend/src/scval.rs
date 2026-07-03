//! ScVal encoding for Blend ABI types.
//!
//! # What this module does
//!
//! Converts [`BlendRequest`] into `stellar_xdr::ScVal::Map` for use
//! as Soroban contract invocation arguments.
//!
//! # Byte-layout
//!
//! The soroban-sdk `#[contracttype]` derive on the Blend `Request` struct
//! (v1: `blend-contracts pool/src/pool/actions.rs`;
//!  v2: `blend-contracts-v2 pool/src/pool/actions.rs`)
//! encodes the struct as `ScVal::Map` with entries sorted **alphabetically
//! by field name**, each entry having key `ScVal::Symbol(field_name)` and
//! value the field's ScVal representation.
//!
//! Canonical citation:
//! `soroban-sdk soroban-sdk-macros/src/derive_struct.rs`
//! (25.3.0) — `.sorted_by_key(|field| field.ident.as_ref().unwrap().to_string())`.
//!
//! The field names of `Request` are `address`, `amount`, `request_type`
//! (alphabetical: a < a < r), producing the map entry order:
//!   1. `"address"` → `ScVal::Address(ScAddress::Contract(...))`
//!   2. `"amount"`  → `ScVal::I128(...)` (via `Int128Parts`)
//!   3. `"request_type"` → `ScVal::U32(discriminant)`
//!
//! The `RequestType` enum is NOT annotated with `#[contracttype]`; it is stored
//! as a plain `u32` field in the struct, encoded as `ScVal::U32`.
//! Cited from `blend-contracts pool/src/pool/actions.rs` (`request_type: u32`)
//! and `blend-contracts-v2 pool/src/pool/actions.rs` (same).

use stellar_xdr::{
    ContractId, Hash, Int128Parts, ScAddress, ScMap, ScMapEntry, ScSymbol, ScVal, StringM,
};

use crate::abi::{BlendAbiError, BlendRequest};

// ─────────────────────────────────────────────────────────────────────────────
// BlendScValError
// ─────────────────────────────────────────────────────────────────────────────

/// Error returned when encoding a [`BlendRequest`] to `ScVal`.
///
/// All variants carry non-sensitive diagnostic information.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BlendScValError {
    /// The pool or asset address is not a valid Stellar C-strkey.
    #[error("invalid Blend address (not a C-strkey): {reason}")]
    InvalidAddress {
        /// Non-sensitive reason string.
        reason: String,
    },
    /// An XDR field name string is too long for `ScSymbol` (max 32 bytes).
    ///
    /// This applies only to the map key symbol strings (`"address"`,
    /// `"amount"`, `"request_type"`).
    #[error("ScSymbol field name too long: {name}")]
    SymbolTooLong {
        /// The oversized symbol name.
        name: String,
    },
    /// A `VecM` collection (ScMap entries or ScVec elements) exceeded the
    /// maximum XDR length.
    ///
    /// Distinct from [`BlendScValError::SymbolTooLong`] which covers only the
    /// map-key symbol string length.
    #[error("Blend XDR VecM overflow: {detail}")]
    VecTooLong {
        /// Non-sensitive description of which collection overflowed.
        detail: String,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// encode_blend_request
// ─────────────────────────────────────────────────────────────────────────────

/// Encodes a [`BlendRequest`] as `ScVal::Map` for a Soroban contract call.
///
/// Field order is alphabetical (`address` < `amount` < `request_type`) as
/// required by the soroban-sdk `#[contracttype]` struct derive.  Cited from:
/// - Type shape: `blend-contracts pool/src/pool/actions.rs`.
/// - Field ordering: `soroban-sdk soroban-sdk-macros/src/derive_struct.rs`
///   (25.3.0).
///
/// # Errors
///
/// Returns [`BlendScValError::InvalidAddress`] when `request.address` is not
/// a valid Stellar C-strkey.
///
/// # Examples
///
/// ```no_run
/// use stellar_agent_blend::abi::{BlendRequest, RequestType};
/// use stellar_agent_blend::scval::encode_blend_request;
///
/// let req = BlendRequest::new(
///     RequestType::Supply,
///     "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
///     5_000_000_000,
/// );
/// let scval = encode_blend_request(&req).expect("valid request");
/// // The result is ScVal::Map with 3 entries in alphabetical key order.
/// ```
pub fn encode_blend_request(request: &BlendRequest) -> Result<ScVal, BlendScValError> {
    // ── 1. Encode "address" field → ScVal::Address ─────────────────────────
    // The Blend Request.address field is `soroban_sdk::Address`, which encodes
    // as `ScVal::Address(ScAddress::Contract(ContractId(Hash(bytes))))` for
    // contract addresses (C-strkeys).
    let address_scval = encode_c_strkey_to_sc_address(&request.address)?;

    // ── 2. Encode "amount" field → ScVal::I128 ────────────────────────────
    // `i128` encodes as `ScVal::I128(Int128Parts { hi, lo })` where hi is the
    // upper 64 bits (as i64) and lo is the lower 64 bits (as u64).
    let amount = request.amount;
    let amount_scval = ScVal::I128(Int128Parts {
        hi: (amount >> 64) as i64,
        lo: amount as u64,
    });

    // ── 3. Encode "request_type" field → ScVal::U32 ───────────────────────
    // The Blend Request.request_type is `u32` (not #[contracttype] itself),
    // cited from `blend-contracts pool/src/pool/actions.rs`.
    let request_type_scval = ScVal::U32(request.request_type.discriminant());

    // ── 4. Build the ScMap with alphabetically-sorted field keys ──────────
    // Order: "address" < "amount" < "request_type" (lexicographic).
    // Cited from `soroban-sdk soroban-sdk-macros/src/derive_struct.rs`
    // (25.3.0).
    let entries = vec![
        map_entry("address", address_scval)?,
        map_entry("amount", amount_scval)?,
        map_entry("request_type", request_type_scval)?,
    ];

    let sc_map = ScMap(entries.try_into().map_err(|_| {
        BlendScValError::VecTooLong {
            detail: "ScMap entries VecM conversion failed (unexpected: map has exactly 3 entries)"
                .to_owned(),
        }
    })?);

    Ok(ScVal::Map(Some(sc_map)))
}

/// Converts a contract C-strkey to a [`stellar_xdr::ScAddress`].
///
/// Builds the `contract_address` for the `HostFunction::InvokeContract` call
/// against the Blend pool contract.
///
/// # Errors
///
/// Returns [`BlendScValError::InvalidAddress`] when `address` is not a valid
/// Stellar C-strkey.
pub fn c_strkey_to_sc_address(address: &str) -> Result<ScAddress, BlendScValError> {
    let contract = stellar_strkey::Contract::from_string(address).map_err(|e| {
        BlendScValError::InvalidAddress {
            reason: e.to_string(),
        }
    })?;
    Ok(ScAddress::Contract(ContractId(Hash(contract.0))))
}

/// Encodes a `Vec<BlendRequest>` as `ScVal::Vec` for the `submit` `requests`
/// argument.
///
/// Each element is encoded via [`encode_blend_request`].
///
/// # Errors
///
/// Returns the first [`BlendScValError`] encountered.
pub fn encode_blend_requests(requests: &[BlendRequest]) -> Result<ScVal, BlendAbiError> {
    let mut vals = Vec::with_capacity(requests.len());
    for req in requests {
        vals.push(encode_blend_request(req)?);
    }

    let vec_m: stellar_xdr::VecM<ScVal> = vals.try_into().map_err(|_| {
        BlendAbiError::ScValEncoding(BlendScValError::VecTooLong {
            detail: "requests VecM too long for ScVec (XDR limit exceeded)".to_owned(),
        })
    })?;
    Ok(ScVal::Vec(Some(stellar_xdr::ScVec(vec_m))))
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Converts a C-strkey to `ScVal::Address(ScAddress::Contract(...))`.
fn encode_c_strkey_to_sc_address(address: &str) -> Result<ScVal, BlendScValError> {
    Ok(ScVal::Address(c_strkey_to_sc_address(address)?))
}

/// Builds a `ScMapEntry` with an `ScSymbol` key.
fn map_entry(name: &str, val: ScVal) -> Result<ScMapEntry, BlendScValError> {
    let key_string: StringM<32> = name
        .try_into()
        .map_err(|_| BlendScValError::SymbolTooLong {
            name: name.to_owned(),
        })?;
    Ok(ScMapEntry {
        key: ScVal::Symbol(ScSymbol(key_string)),
        val,
    })
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
        reason = "test-only fixture construction"
    )]

    use super::*;
    use crate::abi::{BlendRequest, RequestType};
    use stellar_xdr::{ReadXdr, WriteXdr};

    /// A known C-strkey that is byte-valid.
    const TEST_CONTRACT: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";

    /// A second distinct C-strkey for multi-element tests.
    const TEST_CONTRACT_2: &str = "CCEBVDYM32YNYCVNRXQKDFFPISJJCV557CDZEIRBEE4NCV4KHPQ44HGF";

    // ── c_strkey_to_sc_address: valid input ─────────────────────────────────

    #[test]
    fn c_strkey_to_sc_address_valid_produces_correct_bytes() {
        let result = c_strkey_to_sc_address(TEST_CONTRACT).expect("valid C-strkey must succeed");
        let expected_bytes = stellar_strkey::Contract::from_string(TEST_CONTRACT)
            .expect("canonical parse")
            .0;
        match result {
            ScAddress::Contract(ContractId(Hash(bytes))) => {
                assert_eq!(
                    bytes, expected_bytes,
                    "inner 32 bytes must equal stellar_strkey parse result"
                );
            }
            other => panic!("expected ScAddress::Contract, got {other:?}"),
        }
    }

    #[test]
    fn c_strkey_to_sc_address_second_contract_round_trips() {
        let result = c_strkey_to_sc_address(TEST_CONTRACT_2).expect("valid C-strkey must succeed");
        let expected_bytes = stellar_strkey::Contract::from_string(TEST_CONTRACT_2)
            .expect("canonical parse")
            .0;
        match result {
            ScAddress::Contract(ContractId(Hash(bytes))) => {
                assert_eq!(
                    bytes, expected_bytes,
                    "inner 32 bytes must equal stellar_strkey parse result for TEST_CONTRACT_2"
                );
            }
            other => panic!("expected ScAddress::Contract, got {other:?}"),
        }
    }

    #[test]
    fn c_strkey_to_sc_address_g_strkey_returns_invalid_address() {
        // A G-strkey (account) is not a C-strkey; must be refused.
        let result =
            c_strkey_to_sc_address("GAHJJJKMOKYE4RVPZEWZTKH5FVI4PA3VL7GK2LFNUBSGBV3CK4KJDJ");
        let err = result.expect_err("G-strkey must be refused");
        assert!(
            matches!(err, BlendScValError::InvalidAddress { .. }),
            "expected InvalidAddress for G-strkey, got {err:?}"
        );
    }

    #[test]
    fn c_strkey_to_sc_address_garbage_returns_invalid_address() {
        let result = c_strkey_to_sc_address("not-a-valid-strkey-at-all");
        let err = result.expect_err("garbage must be refused");
        assert!(
            matches!(err, BlendScValError::InvalidAddress { .. }),
            "expected InvalidAddress for garbage input, got {err:?}"
        );
    }

    // ── encode_blend_requests: empty slice ──────────────────────────────────

    #[test]
    fn encode_blend_requests_empty_slice_yields_empty_scvec() {
        let result = encode_blend_requests(&[]).expect("empty slice must succeed");
        match result {
            ScVal::Vec(Some(ref sc_vec)) => {
                assert_eq!(
                    sc_vec.len(),
                    0,
                    "empty slice must produce ScVec with 0 elements"
                );
            }
            other => panic!("expected ScVal::Vec(Some(<empty>)), got {other:?}"),
        }
    }

    // ── encode_blend_requests: 2-element slice ───────────────────────────────

    #[test]
    fn encode_blend_requests_two_elements_length_and_map_structure() {
        let reqs = [
            BlendRequest::new(RequestType::Supply, TEST_CONTRACT, 1_000_000),
            BlendRequest::new(RequestType::Borrow, TEST_CONTRACT_2, 2_000_000),
        ];
        let result = encode_blend_requests(&reqs).expect("two valid requests must succeed");

        let sc_vec = match result {
            ScVal::Vec(Some(ref v)) => v.clone(),
            other => panic!("expected ScVal::Vec(Some(..)), got {other:?}"),
        };

        assert_eq!(
            sc_vec.len(),
            2,
            "two requests must produce a 2-element ScVec"
        );

        // Element 0 must be a ScVal::Map with keys in alphabetical order:
        // address / amount / request_type.
        let elem0 = &sc_vec[0];
        let map0 = match elem0 {
            ScVal::Map(Some(m)) => m,
            other => panic!("element 0 must be ScVal::Map(Some(..)), got {other:?}"),
        };

        assert_eq!(map0.len(), 3, "element 0 map must have exactly 3 entries");

        // Assert key order: address at index 0, amount at index 1, request_type at index 2.
        let key_sym = |entry: &ScMapEntry| match &entry.key {
            ScVal::Symbol(sym) => sym.0.to_string(),
            other => panic!("expected ScVal::Symbol key, got {other:?}"),
        };

        assert_eq!(
            key_sym(&map0[0]),
            "address",
            "first map key must be 'address'"
        );
        assert_eq!(
            key_sym(&map0[1]),
            "amount",
            "second map key must be 'amount'"
        );
        assert_eq!(
            key_sym(&map0[2]),
            "request_type",
            "third map key must be 'request_type'"
        );

        // Element 0 is Supply (discriminant 0).
        assert_eq!(
            map0[2].val,
            ScVal::U32(0),
            "element 0 request_type must be U32(0) for Supply"
        );

        // Element 1 is Borrow (discriminant 4).
        let map1 = match &sc_vec[1] {
            ScVal::Map(Some(m)) => m,
            other => panic!("element 1 must be ScVal::Map(Some(..)), got {other:?}"),
        };
        assert_eq!(
            map1[2].val,
            ScVal::U32(4),
            "element 1 request_type must be U32(4) for Borrow"
        );
    }

    // ── Alphabetical field ordering ─────────────────────────────────────────

    #[test]
    fn request_map_fields_in_alphabetical_order() {
        let req = BlendRequest::new(RequestType::Supply, TEST_CONTRACT, 1_000);
        let scval = encode_blend_request(&req).expect("valid encoding");

        if let ScVal::Map(Some(sc_map)) = &scval {
            let keys: Vec<String> = sc_map
                .iter()
                .map(|e| {
                    if let ScVal::Symbol(sym) = &e.key {
                        sym.0.to_string()
                    } else {
                        String::from("<not-symbol>")
                    }
                })
                .collect();
            assert_eq!(
                keys,
                vec!["address", "amount", "request_type"],
                "fields must be in alphabetical order per the soroban-sdk struct derive"
            );
        } else {
            panic!("expected ScVal::Map");
        }
    }

    // ── request_type encodes as U32 (not contracttype enum) ─────────────────

    #[test]
    fn request_type_supply_encodes_as_u32_0() {
        let req = BlendRequest::new(RequestType::Supply, TEST_CONTRACT, 1_000);
        let scval = encode_blend_request(&req).expect("valid encoding");

        if let ScVal::Map(Some(sc_map)) = &scval {
            // request_type is the 3rd field (index 2)
            let rt_val = &sc_map[2].val;
            assert_eq!(
                *rt_val,
                ScVal::U32(0),
                "Supply=0 must encode as ScVal::U32(0)"
            );
        } else {
            panic!("expected ScVal::Map");
        }
    }

    #[test]
    fn request_type_borrow_encodes_as_u32_4() {
        let req = BlendRequest::new(RequestType::Borrow, TEST_CONTRACT, 1_000);
        let scval = encode_blend_request(&req).expect("valid encoding");

        if let ScVal::Map(Some(sc_map)) = &scval {
            let rt_val = &sc_map[2].val;
            assert_eq!(
                *rt_val,
                ScVal::U32(4),
                "Borrow=4 must encode as ScVal::U32(4)"
            );
        } else {
            panic!("expected ScVal::Map");
        }
    }

    // ── amount encodes as I128 ───────────────────────────────────────────────

    #[test]
    fn amount_encodes_as_i128_parts() {
        let amount: i128 = 5_000_000_000i128;
        let req = BlendRequest::new(RequestType::Repay, TEST_CONTRACT, amount);
        let scval = encode_blend_request(&req).expect("valid encoding");

        if let ScVal::Map(Some(sc_map)) = &scval {
            let amount_val = &sc_map[1].val;
            if let ScVal::I128(parts) = amount_val {
                let decoded = ((parts.hi as i128) << 64) | (parts.lo as i128);
                assert_eq!(decoded, amount, "amount must round-trip via Int128Parts");
            } else {
                panic!("expected ScVal::I128 for amount field");
            }
        } else {
            panic!("expected ScVal::Map");
        }
    }

    // ── invalid address returns error ────────────────────────────────────────

    #[test]
    fn invalid_address_returns_error() {
        let req = BlendRequest::new(RequestType::Supply, "GNOTACONTRACT", 1_000);
        let err = encode_blend_request(&req).expect_err("should fail on G-strkey");
        assert!(
            matches!(err, BlendScValError::InvalidAddress { .. }),
            "expected InvalidAddress, got {err:?}"
        );
    }

    // ── XDR round-trip ───────────────────────────────────────────────────────

    #[test]
    fn scval_is_xdr_serialisable() {
        let req = BlendRequest::new(RequestType::Supply, TEST_CONTRACT, 100_000_000);
        let scval = encode_blend_request(&req).expect("valid encoding");
        let bytes = scval.to_xdr(stellar_xdr::Limits::none()).expect("to_xdr");
        let back = ScVal::from_xdr(&bytes, stellar_xdr::Limits::none()).expect("from_xdr");
        assert_eq!(scval, back, "ScVal must XDR round-trip");
    }
}
