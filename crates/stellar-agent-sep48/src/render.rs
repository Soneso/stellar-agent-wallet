//! SEP-48 typed-arg rendering.
//!
//! Given a parsed [`soroban_spec_tools::Spec`] and a decoded invocation
//! `(function_name, args: Vec<ScVal>)`, this module renders each argument as a
//! typed JSON value using the function's parameter spec.
//!
//! # Output shape
//!
//! The output is a deterministic JSON object:
//!
//! ```json
//! {
//!   "contract": "CBIELTK6...",
//!   "function": "approve",
//!   "args": {
//!     "from": "GABC...",
//!     "spender": "GABC...",
//!     "amount": "1000000",
//!     "live_until_ledger": 100
//!   }
//! }
//! ```
//!
//! JSON keys are alphabetically sorted (`serde_json::Map` uses `BTreeMap` by
//! default), giving deterministic JSON serialisation. The positional mapping
//! from `ScVal` args to parameter names follows spec declaration order
//! (`inputs` list of `ScSpecFunctionV0`). This mirrors the field-by-field
//! mapping in KMP Stellar SDK `contract/ContractSpec.kt`.
//!
//! # SEP-48 specification
//!
//! The SEP-48 specification: `ScSpecFunctionV0` carries a `params` list of
//! `ScSpecFunctionInputV0 { name: String, type_: SCSpecTypeDef }`. Each param
//! name and type is used to label and coerce the corresponding positional
//! `ScVal` arg.

use serde_json::{Map, Value};
use soroban_spec_tools::Spec;
use stellar_xdr::{ScSpecEntry, ScSpecFunctionV0};

use crate::error::Sep48Error;

/// A fully typed preview of a contract function invocation.
///
/// Produced by [`render_typed_args`]. Serialises as a deterministic JSON
/// object with alphabetically sorted keys.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TypedPreview {
    /// The C-strkey of the invoked contract.
    pub contract: String,
    /// The name of the invoked function.
    pub function: String,
    /// Typed argument values, keyed by parameter name in alphabetical order.
    ///
    /// The underlying `serde_json::Map` uses `BTreeMap` (alphabetically sorted)
    /// which gives deterministic JSON serialisation. Keyed on parameter names
    /// from the SEP-48 spec (`ScSpecFunctionInputV0.name`).
    pub args: serde_json::Map<String, Value>,
    /// Human-readable function documentation from the spec, if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doc: Option<String>,
}

/// Renders a contract invocation as a [`TypedPreview`] by mapping each
/// positional `ScVal` argument to its declared name and type from the SEP-48
/// spec.
///
/// # Arguments
///
/// * `entries` — the parsed `ScSpecEntry` list from the contract's
///   `contractspecv0` custom section.
/// * `contract_strkey` — the C-strkey of the invoked contract (for the output
///   `contract` field).
/// * `function_name` — the name of the invoked function.
/// * `args` — the positional `ScVal` arguments from `InvokeContractArgs.args`.
///
/// # Output
///
/// Returns a [`TypedPreview`] with `args` keyed by parameter name. Keys are
/// in alphabetical order (BTreeMap, deterministic output). The positional
/// argument-to-parameter mapping uses spec declaration order.
///
/// # Errors
///
/// - [`Sep48Error::FunctionNotFound`] — the function is not in the spec.
/// - [`Sep48Error::ArgCountMismatch`] — the number of supplied args does not
///   match the number of parameters declared in the spec. Fail-closed: a
///   surplus arg avoids panics in `soroban_spec_tools::to_json` for exotic
///   `ScAddress` variants; a deficit arg avoids a misleadingly partial preview.
/// - [`Sep48Error::UnsupportedArgType`] — an argument's `ScType` cannot be
///   rendered to JSON by `soroban_spec_tools::Spec::xdr_to_json`.
pub fn render_typed_args(
    entries: &[ScSpecEntry],
    contract_strkey: &str,
    function_name: &str,
    args: &[stellar_xdr::ScVal],
) -> Result<TypedPreview, Sep48Error> {
    let spec = Spec::new(entries);

    let func: &ScSpecFunctionV0 =
        spec.find_function(function_name)
            .map_err(|_| Sep48Error::FunctionNotFound {
                function_name: function_name.to_owned(),
            })?;

    // ── Fail-closed arity check ───────────────────────────────────────────────
    //
    // A Soroban contract function has fixed arity defined by its SEP-48 spec.
    // Mismatch → hard error BEFORE rendering:
    //   - Surplus args: `soroban_spec_tools::to_json` has `todo!()` for certain
    //     exotic `ScAddress` variants (ClaimableBalance, LiquidityPool). The
    //     arity check eliminates the free-function overflow path by ensuring we
    //     never call `to_json` outside the zip loop.
    //   - Deficit args: zip-truncation would silently drop un-rendered params,
    //     producing a misleading partial preview.
    let expected = func.inputs.len();
    let actual = args.len();
    if actual != expected {
        return Err(Sep48Error::ArgCountMismatch { expected, actual });
    }

    let doc_str: Option<String> = {
        let s = func.doc.to_utf8_string_lossy();
        if s.is_empty() { None } else { Some(s) }
    };

    let param_names: Vec<String> = func
        .inputs
        .iter()
        .map(|p| p.name.to_utf8_string_lossy())
        .collect();
    let param_types: Vec<stellar_xdr::ScSpecTypeDef> =
        func.inputs.iter().map(|p| p.type_.clone()).collect();

    // Build ordered args map (declaration order = deterministic output).
    //
    // `soroban_spec_tools::Spec::xdr_to_json` uses `todo!()` for unimplemented
    // type combinations (e.g. `ScVal::Error` vs `ScType::Error`, exotic map
    // keys, UDT/ContractInstance variants, ClaimableBalance/LiquidityPool
    // ScAddress). We retain the `catch_unwind` boundary for IN-SPEC arg
    // combinations that can still hit the remaining `todo!()` paths after the
    // arity check guards the free-function overflow:
    //   - `(ScVal::Error(_), ScType::Error) => todo!()`
    //   - `(v, typed) => todo!("{v:#?} doesn't have a matching {typed:#?}")`
    //   - exotic map/bytes/ContractInstance paths
    let mut args_map = Map::new();
    for (i, (val, param_type)) in args.iter().zip(param_types.iter()).enumerate() {
        // The arity check above guarantees `i < param_names.len()`, so `.get(i)`
        // always yields `Some`. The `arg{i}` branch is a non-panicking fallback
        // per the no-indexing-panic policy and is never reached in correct usage.
        let param_name = param_names
            .get(i)
            .cloned()
            .unwrap_or_else(|| format!("arg{i}"));
        let val_clone = val.clone();
        let type_clone = param_type.clone();
        let spec_clone = spec.clone();
        // `soroban_spec_tools::Spec` is not `UnwindSafe` because it contains `Vec<ScSpecEntry>`.
        // `AssertUnwindSafe` is sound here: on Err(_panic) we return an error immediately
        // without touching any partially-updated state — the args_map is still coherent.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            spec_clone.xdr_to_json(&val_clone, &type_clone)
        }));
        let json_val = match result {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                return Err(Sep48Error::UnsupportedArgType {
                    arg_index: i,
                    type_hint: format!("{param_type:?}: {e}"),
                });
            }
            Err(_panic) => {
                return Err(Sep48Error::UnsupportedArgType {
                    arg_index: i,
                    type_hint: format!(
                        "{param_type:?}: unsupported (soroban_spec_tools todo! path)"
                    ),
                });
            }
        };
        args_map.insert(param_name, json_val);
    }

    Ok(TypedPreview {
        contract: contract_strkey.to_owned(),
        function: function_name.to_owned(),
        args: args_map,
        doc: doc_str,
    })
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics acceptable in unit tests"
)]
mod tests {
    use super::*;
    use stellar_xdr::{ScSpecEntry, ScSpecFunctionInputV0, ScSpecFunctionV0, StringM};

    /// Build a minimal in-memory spec for an `approve(from: Address, amount: i128)` function.
    fn make_approve_spec() -> Vec<ScSpecEntry> {
        use stellar_xdr::{ScSpecTypeDef, VecM};
        let inputs: Vec<ScSpecFunctionInputV0> = vec![
            ScSpecFunctionInputV0 {
                doc: StringM::default(),
                name: "from".try_into().unwrap(),
                type_: ScSpecTypeDef::Address,
            },
            ScSpecFunctionInputV0 {
                doc: StringM::default(),
                name: "amount".try_into().unwrap(),
                type_: ScSpecTypeDef::I128,
            },
        ];
        let func = ScSpecFunctionV0 {
            doc: StringM::default(),
            name: "approve".try_into().unwrap(),
            inputs: inputs.try_into().unwrap(),
            outputs: VecM::default(),
        };
        vec![ScSpecEntry::FunctionV0(func)]
    }

    #[test]
    fn function_not_found_returns_error() {
        let entries = make_approve_spec();
        let result = render_typed_args(&entries, "CTEST...", "nonexistent", &[]);
        assert!(
            matches!(result, Err(Sep48Error::FunctionNotFound { .. })),
            "unknown function must return FunctionNotFound"
        );
    }

    /// Verifies that supplying fewer args than spec params (or zero args) returns
    /// `ArgCountMismatch` rather than silently rendering a partial preview.
    #[test]
    fn arg_count_mismatch_fails_closed() {
        let entries = make_approve_spec();
        // The spec has 2 params (from: Address, amount: i128).
        // Supplying 0 args must return ArgCountMismatch, not an empty map.
        let result = render_typed_args(&entries, "CTEST...", "approve", &[]);
        assert!(
            matches!(
                result,
                Err(Sep48Error::ArgCountMismatch {
                    expected: 2,
                    actual: 0,
                })
            ),
            "zero args for 2-param function must return ArgCountMismatch(expected=2, actual=0), got: {result:?}"
        );
    }

    /// Verifies that supplying MORE args than spec params returns `ArgCountMismatch`
    /// rather than panicking via the `todo!()` path in `soroban_spec_tools::to_json`
    /// for exotic `ScAddress` variants.
    #[test]
    fn surplus_claimable_balance_arg_returns_arg_count_mismatch_not_panic() {
        use stellar_xdr::{ClaimableBalanceId, Hash, ScAddress, ScVal};
        let entries = make_approve_spec();
        // The spec has 2 params (from: Address, amount: i128).
        // Construct a surplus ScVal::Address(ScAddress::ClaimableBalance(...)) which
        // would trigger a `todo!()` in soroban_spec_tools if it reached `to_json`.
        // The arity check must fire BEFORE any rendering attempt.
        let fake_address = ScVal::Address(ScAddress::ClaimableBalance(
            ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash([0u8; 32])),
        ));
        // Passing 3 args for a 2-param function: any arity mismatch → ArgCountMismatch.
        let from = ScVal::Address(ScAddress::Account(stellar_xdr::AccountId(
            stellar_xdr::PublicKey::PublicKeyTypeEd25519(stellar_xdr::Uint256([0u8; 32])),
        )));
        let amount = ScVal::I128(stellar_xdr::Int128Parts { hi: 0, lo: 100 });
        let args = vec![from, amount, fake_address];
        // Must return ArgCountMismatch, NOT panic with "ClaimableBalance is not supported".
        let result = render_typed_args(&entries, "CTEST...", "approve", &args);
        assert!(
            matches!(
                result,
                Err(Sep48Error::ArgCountMismatch {
                    expected: 2,
                    actual: 3,
                })
            ),
            "3 args for 2-param function must return ArgCountMismatch(expected=2, actual=3), got: {result:?}"
        );
    }

    /// Verifies that passing an I128 ScVal where an Address is expected returns
    /// `UnsupportedArgType` at index 0 via the `Err(_panic)` arm. The arity matches
    /// (2 args for 2-param function), so the render loop is entered.
    ///
    /// `xdr_to_json(ScVal::I128, ScType::Address)` hits the `(v, typed) => todo!()`
    /// catch-all in `soroban_spec_tools::Spec::xdr_to_json` which panics. The
    /// `catch_unwind` boundary converts this to the `Err(_panic)` arm.
    #[test]
    fn i128_for_address_param_returns_unsupported_via_panic_arm() {
        use stellar_xdr::{Int128Parts, ScVal};
        let entries = make_approve_spec();
        // Spec: approve(from: Address, amount: i128).
        // Pass (I128, I128) — xdr_to_json(I128, Address) hits todo!() (panic arm).
        let mismatch_val = ScVal::I128(Int128Parts {
            hi: 0,
            lo: 1_000_000,
        });
        let amount_val = ScVal::I128(Int128Parts {
            hi: 0,
            lo: 1_000_000,
        });
        let args = vec![mismatch_val, amount_val];
        let result = render_typed_args(&entries, "CTEST...", "approve", &args);
        assert!(
            matches!(
                result,
                Err(super::Sep48Error::UnsupportedArgType { arg_index: 0, .. })
            ),
            "I128 for Address param must return UnsupportedArgType at index 0, got: {result:?}"
        );
    }

    /// Verifies that passing a `ScVal::Vec(Some(_))` where an `Address` is expected
    /// returns `UnsupportedArgType` via the `Ok(Err(e))` arm (NOT via panic).
    ///
    /// `xdr_to_json(ScVal::Vec(Some(_)), ScType::Address)` routes through
    /// `sc_object_to_json` which returns `Err(Error::InvalidPair(...))` at the
    /// catch-all arm — no `todo!()` is hit. `catch_unwind` returns `Ok(Err(e))`
    /// which is processed by the `Ok(Err(e))` arm.
    #[test]
    fn vec_for_address_param_returns_unsupported_via_err_arm() {
        use stellar_xdr::{Int128Parts, ScVal, ScVec, VecM};
        let entries = make_approve_spec();
        // Spec: approve(from: Address, amount: i128). Arity = 2.
        // ScVal::Vec(Some(empty)) for the Address param: routes to sc_object_to_json
        // which returns Err(InvalidPair) — no panic.
        let vec_val = ScVal::Vec(Some(ScVec(VecM::default())));
        let amount_val = ScVal::I128(Int128Parts { hi: 0, lo: 500 });
        let args = vec![vec_val, amount_val];
        let result = render_typed_args(&entries, "CTEST...", "approve", &args);
        // The Ok(Err(e)) arm fires, wrapping the InvalidPair error.
        assert!(
            matches!(
                result,
                Err(super::Sep48Error::UnsupportedArgType { arg_index: 0, .. })
            ),
            "ScVal::Vec for Address param must return UnsupportedArgType at index 0 via Ok(Err) arm, got: {result:?}"
        );
    }

    /// Verifies that a zero-param function with zero args renders successfully
    /// and returns an empty args map with the correct contract + function fields.
    ///
    /// Covers the `Ok(TypedPreview { .. })` path where the loop body is never
    /// entered (args_map stays empty).
    #[test]
    fn zero_param_function_renders_successfully() {
        use stellar_xdr::{ScSpecEntry, ScSpecFunctionV0, StringM, VecM};
        let func = ScSpecFunctionV0 {
            doc: StringM::default(),
            name: "ping".try_into().unwrap(),
            inputs: VecM::default(),
            outputs: VecM::default(),
        };
        let entries = vec![ScSpecEntry::FunctionV0(func)];
        let result = render_typed_args(&entries, "CTEST...", "ping", &[]);
        let preview = result.expect("zero-param function with zero args must succeed");
        assert_eq!(preview.function, "ping");
        assert_eq!(preview.contract, "CTEST...");
        assert!(
            preview.args.is_empty(),
            "zero-param function must have empty args map"
        );
        assert!(preview.doc.is_none(), "no doc on this function");
    }

    /// Verifies that a function with a doc string populates `TypedPreview::doc`.
    ///
    /// Covers the `doc_str = Some(s)` branch in `render_typed_args`.
    #[test]
    fn function_with_doc_string_populates_preview_doc() {
        use stellar_xdr::{ScSpecEntry, ScSpecFunctionV0, VecM};
        let func = ScSpecFunctionV0 {
            doc: "Transfers tokens from sender to recipient."
                .try_into()
                .unwrap(),
            name: "transfer".try_into().unwrap(),
            inputs: VecM::default(),
            outputs: VecM::default(),
        };
        let entries = vec![ScSpecEntry::FunctionV0(func)];
        let result = render_typed_args(&entries, "CTEST...", "transfer", &[]);
        let preview = result.expect("function with doc must render successfully");
        assert_eq!(
            preview.doc.as_deref(),
            Some("Transfers tokens from sender to recipient."),
            "doc string must be present in TypedPreview"
        );
    }

    /// Verifies that `render_typed_args` produces the exact typed JSON map for a
    /// valid `approve(from: Address, amount: I128)` call with real ScVal values.
    ///
    /// Covers the `Ok(Ok(v)) => v` arm and the `args_map.insert` call.
    #[test]
    fn render_valid_approve_args_produces_exact_map() {
        use stellar_xdr::{AccountId, Int128Parts, PublicKey, ScAddress, ScVal, Uint256};
        let entries = make_approve_spec();
        let from_val = ScVal::Address(ScAddress::Account(AccountId(
            PublicKey::PublicKeyTypeEd25519(Uint256([0u8; 32])),
        )));
        let amount_val = ScVal::I128(Int128Parts {
            hi: 0,
            lo: 1_000_000,
        });
        let args = vec![from_val, amount_val];
        let result = render_typed_args(&entries, "CTEST...", "approve", &args);
        let preview = result.expect("valid approve call must render successfully");
        assert_eq!(preview.function, "approve");
        assert_eq!(preview.contract, "CTEST...");
        // Amount is an I128 — soroban_spec_tools renders it as a string.
        assert_eq!(
            preview.args.get("amount").and_then(|v| v.as_str()),
            Some("1000000"),
            "amount I128 must render as string '1000000'"
        );
        // From is an Address — rendered as the strkey string.
        assert!(
            preview.args.contains_key("from"),
            "from parameter must be present in args map"
        );
    }
}
