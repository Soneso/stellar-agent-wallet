//! Read-only Soroban simulate primitives shared by DeFi protocol crates.
//!
//! # What this module does
//!
//! Provides:
//! - [`simulate_invoke_returning_scval`] — builds a read-only simulate call
//!   to an arbitrary contract function and returns the raw `ScVal` result.
//! - [`decode_i128_scval`] — decodes `ScVal::I128(Int128Parts {hi, lo})` to
//!   `i128`.
//! - [`scval_variant_name`] — returns a non-sensitive variant name string for
//!   an `ScVal`, used in error messages to avoid logging full values.
//!
//! # Design rationale
//!
//! Both `stellar-agent-defi::reflector` and `stellar-agent-defindex::storage`
//! use identical read-only simulate scaffolds (dummy source account, fee=100,
//! no signatures, no auth, `simulate_transaction_envelope`) and the same i128
//! reconstruction from `Int128Parts`. This module is the single authoritative
//! implementation; both call sites delegate here.
//!
//! The `scval_variant_name` kept here is the complete copy, covering all 22
//! stable `ScVal` variants including `Error`, `Timepoint`, `Duration`, `U256`,
//! `I256`, `Bytes`, `LedgerKeyNonce`, and `ContractInstance`.
//!
//! # ABI provenance
//!
//! `i128` return values encode as `ScVal::I128(Int128Parts { hi: i64, lo: u64 })`
//! per stellar-xdr `generated.rs` at the `Int128Parts` definition;
//! reconstruction matches `int128_helpers::i128_from_pieces`
//! (`scval_conversions.rs:214`).
//!
//! The dummy source account for read-only simulate is the all-zeros G-strkey
//! `GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF`; its 32-byte
//! public key payload is all-zeros.
//!
//! # HTTP scheme
//!
//! `stellar-rpc-client` accepts both `http://` and `https://` URLs natively;
//! no `allow_http` flag or production-code weakening is required.
//! Test servers (wiremock loopback) are reached via `http://`, which is permitted
//! by the upstream client without any opt-in.

use stellar_agent_xdr_limits::untrusted_decode_limits;
use stellar_rpc_client::Client;
use stellar_xdr::{
    ContractId, Hash, HostFunction, InvokeContractArgs, InvokeHostFunctionOp, Memo, MuxedAccount,
    Operation, OperationBody, Preconditions, ReadXdr, ScAddress, ScSymbol, ScVal, SequenceNumber,
    StringM, Transaction, TransactionEnvelope, TransactionExt, TransactionV1Envelope, Uint256,
    VecM,
};

// ─────────────────────────────────────────────────────────────────────────────
// SimulateError
// ─────────────────────────────────────────────────────────────────────────────

/// Error returned by [`simulate_invoke_returning_scval`] and
/// [`decode_i128_scval`].
///
/// No variant carries sensitive data — contract addresses are not echoed, and
/// error messages are bounded diagnostic strings.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SimulateError {
    /// The contract address is not a valid C-strkey.
    #[error("invalid contract address: {reason}")]
    InvalidAddress {
        /// Non-sensitive reason.
        reason: String,
    },
    /// The simulate call could not be built or dispatched.
    #[error("simulate call failed: {reason}")]
    SimulateFailed {
        /// Non-sensitive reason.
        reason: String,
    },
    /// The simulate returned a contract-level error.
    #[error("simulate returned error: {reason}")]
    SimulateError {
        /// Non-sensitive reason.
        reason: String,
    },
    /// The simulate returned no result entry.
    #[error("simulate returned no result value")]
    NoResult,
    /// The result `ScVal` does not match the expected type.
    #[error("ScVal decode failed: {reason}")]
    DecodeFailed {
        /// Non-sensitive reason.
        reason: String,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// simulate_invoke_returning_scval
// ─────────────────────────────────────────────────────────────────────────────

/// Performs a read-only `simulateTransaction` that invokes `fn_name` on
/// `contract_address` with the given positional `args` and returns the raw
/// `ScVal` result.
///
/// This is the shared scaffold used by Reflector `lastprice` queries (in
/// `stellar-agent-defi::reflector`) and DeFindex vault `balance` / `get_assets`
/// queries (in `stellar-agent-defindex::storage`).
///
/// No auth entries and no signing are required; the dummy all-zeros source
/// account is used.  The sequence number is 0 — read-only simulations are
/// stateless with respect to ledger sequence.
///
/// # Arguments
///
/// - `contract_address` — C-strkey of the contract to invoke.
/// - `fn_name` — Function name as a `&str` (max 32 bytes for `ScSymbol`).
/// - `args` — Positional `ScVal` arguments to pass to the function.
/// - `rpc_url` — Soroban RPC URL (`https://` for production; `http://`
///   accepted only on loopback test servers without any production opt-in).
/// - `network_passphrase` — Stellar network passphrase (unused in the XDR
///   envelope itself; the passphrase context is provided by the RPC server).
///
/// # Errors
///
/// Returns [`SimulateError`] on address-parse, construction, dispatch, or
/// result-extraction failure.
pub async fn simulate_invoke_returning_scval(
    contract_address: &str,
    fn_name: &str,
    args: Vec<ScVal>,
    rpc_url: &str,
    _network_passphrase: &str,
) -> Result<ScVal, SimulateError> {
    // Parse contract address.
    let contract_bytes = stellar_strkey::Contract::from_string(contract_address).map_err(|e| {
        SimulateError::InvalidAddress {
            reason: format!("contract address parse failed: {e}"),
        }
    })?;
    let contract_sc_addr = ScAddress::Contract(ContractId(Hash(contract_bytes.0)));

    // Build function symbol — ScSymbol wraps StringM<32>; exceeding 32 bytes is
    // rejected here before any network call.
    let fn_sym: StringM<32> = fn_name
        .try_into()
        .map_err(|_| SimulateError::SimulateFailed {
            reason: format!(
                "function name '{fn_name}' exceeds 32-byte ScSymbol limit (unexpected)"
            ),
        })?;

    // Build args VecM.
    let args_vec: VecM<ScVal> = args.try_into().map_err(|_| SimulateError::SimulateFailed {
        reason: "args VecM conversion failed (unexpected)".to_owned(),
    })?;

    let invoke_args = InvokeContractArgs {
        contract_address: contract_sc_addr,
        function_name: ScSymbol(fn_sym),
        args: args_vec,
    };

    let operation = Operation {
        source_account: None,
        body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
            host_function: HostFunction::InvokeContract(invoke_args),
            auth: VecM::default(),
        }),
    };

    // Dummy source account for read-only simulate.
    // G-strkey GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF decodes
    // to 32 zero bytes; confirmed via stellar-strkey's base32-checksum round-trip.
    let operations: VecM<Operation, 100> =
        vec![operation]
            .try_into()
            .map_err(|_| SimulateError::SimulateFailed {
                reason: "operations VecM conversion failed (unexpected)".to_owned(),
            })?;

    let tx = Transaction {
        source_account: MuxedAccount::Ed25519(Uint256([0u8; 32])),
        fee: 100,
        seq_num: SequenceNumber(0),
        cond: Preconditions::None,
        memo: Memo::None,
        operations,
        ext: TransactionExt::V0,
    };

    let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: VecM::default(),
    });

    // Construct the RPC client.  stellar-rpc-client::Client::new accepts both
    // http:// (loopback test servers) and https:// (production) without any
    // opt-in flag.
    let client = Client::new(rpc_url).map_err(|e| SimulateError::SimulateFailed {
        reason: format!("RPC client construction failed: {e}"),
    })?;

    let simulate_response = client
        .simulate_transaction_envelope(&envelope, None)
        .await
        .map_err(|e| SimulateError::SimulateFailed {
            reason: format!("simulate_transaction_envelope failed: {e}"),
        })?;

    // Check for a contract-level error in the response.
    if let Some(err_msg) = &simulate_response.error {
        return Err(SimulateError::SimulateError {
            reason: err_msg.clone(),
        });
    }

    // Extract the first result entry — NoResult when results is empty.
    let raw_result = simulate_response
        .results
        .into_iter()
        .next()
        .ok_or(SimulateError::NoResult)?;

    // Decode the XDR base64 ScVal from the result's `xdr` field.
    // BOUND with untrusted_decode_limits: the response is from an untrusted
    // RPC endpoint; depth-bombs and oversized length fields must be rejected.
    let xdr_b64 = &raw_result.xdr;
    let limits = untrusted_decode_limits(xdr_b64.len());
    let scval =
        ScVal::from_xdr_base64(xdr_b64, limits).map_err(|e| SimulateError::DecodeFailed {
            reason: format!("ScVal XDR base64 decode failed: {e}"),
        })?;

    Ok(scval)
}

// ─────────────────────────────────────────────────────────────────────────────
// decode_i128_scval
// ─────────────────────────────────────────────────────────────────────────────

/// Decodes `ScVal::I128(Int128Parts {hi, lo})` to `i128`.
///
/// # ABI provenance
///
/// `i128` return values from Soroban contracts encode as `ScVal::I128` with
/// `Int128Parts { hi: i64, lo: u64 }` per the stellar-xdr `Int128Parts`
/// definition; reconstruction matches `int128_helpers::i128_from_pieces`
/// (`scval_conversions.rs:214`).
///
/// # Errors
///
/// Returns [`SimulateError::DecodeFailed`] if the `ScVal` is not `I128`.
pub fn decode_i128_scval(val: &ScVal) -> Result<i128, SimulateError> {
    use stellar_xdr::Int128Parts;

    match val {
        ScVal::I128(Int128Parts { hi, lo }) => Ok(((*hi as i128) << 64) | (*lo as i128)),
        other => Err(SimulateError::DecodeFailed {
            reason: format!("expected ScVal::I128; got {}", scval_variant_name(other)),
        }),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// scval_variant_name
// ─────────────────────────────────────────────────────────────────────────────

/// Returns a non-sensitive discriminant name string for a `ScVal`.
///
/// Used in error messages to avoid logging the full value, which may contain
/// addresses or other sensitive data.  Covers all 22 stable variants.
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
    }
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

    use stellar_xdr::{Int128Parts, ScVal, UInt128Parts};

    use super::*;

    // ── decode_i128_scval ─────────────────────────────────────────────────────

    #[test]
    fn decode_i128_round_trips_positive_value() {
        let expected: i128 = 100_000_000;
        let scval = ScVal::I128(Int128Parts {
            hi: (expected >> 64) as i64,
            lo: expected as u64,
        });
        let got = decode_i128_scval(&scval).unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn decode_i128_round_trips_negative_value() {
        let expected: i128 = -42_000_000;
        let scval = ScVal::I128(Int128Parts {
            hi: (expected >> 64) as i64,
            lo: expected as u64,
        });
        let got = decode_i128_scval(&scval).unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn decode_i128_round_trips_zero() {
        let scval = ScVal::I128(Int128Parts { hi: 0, lo: 0 });
        let got = decode_i128_scval(&scval).unwrap();
        assert_eq!(got, 0i128);
    }

    #[test]
    fn decode_i128_wrong_variant_returns_decode_failed() {
        let result = decode_i128_scval(&ScVal::Void);
        assert!(
            matches!(result, Err(SimulateError::DecodeFailed { .. })),
            "Void must return DecodeFailed"
        );
        let result2 = decode_i128_scval(&ScVal::U64(42));
        assert!(
            matches!(result2, Err(SimulateError::DecodeFailed { .. })),
            "U64 must return DecodeFailed"
        );
    }

    // ── scval_variant_name ───────────────────────────────────────────────────

    /// Asserts the exact discriminant name string for ALL 22 stable `ScVal`
    /// variants.  A constant-returning implementation would be caught because
    /// at most one variant can return any single string.
    #[test]
    fn scval_variant_name_exact_name_for_all_22_variants() {
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
        // Error — ScError is an enum; use the Value(ScErrorCode) variant.
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
        // Address — use an all-zero Ed25519 public key (account address).
        assert_eq!(
            scval_variant_name(&ScVal::Address(ScAddress::Account(stellar_xdr::AccountId(
                stellar_xdr::PublicKey::PublicKeyTypeEd25519(Uint256([0u8; 32],))
            )))),
            "Address"
        );
        // LedgerKeyContractInstance (unit variant — no inner value).
        assert_eq!(
            scval_variant_name(&ScVal::LedgerKeyContractInstance),
            "LedgerKeyContractInstance"
        );
        // LedgerKeyNonce — ScVal::LedgerKeyNonce(ScNonceKey { nonce: i64 }).
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
    }

    // ── simulate_invoke_returning_scval: address validation ──────────────────

    #[tokio::test]
    async fn simulate_fn_name_too_long_returns_simulate_failed() {
        // Function names > 32 bytes are rejected by ScSymbol.
        let long_name = "a_very_long_function_name_that_exceeds_thirty_two_bytes";
        assert!(long_name.len() > 32, "sanity: name must be > 32 chars");
        let result = simulate_invoke_returning_scval(
            TEST_CONTRACT,
            long_name,
            vec![],
            "https://soroban-testnet.stellar.org",
            TEST_PASSPHRASE,
        )
        .await;
        assert!(
            matches!(result, Err(SimulateError::SimulateFailed { .. })),
            "fn name > 32 bytes must return SimulateFailed: {result:?}"
        );
    }

    #[tokio::test]
    async fn simulate_invalid_contract_address_returns_invalid_address() {
        let result = simulate_invoke_returning_scval(
            "not-a-strkey",
            "balance",
            vec![],
            "https://soroban-testnet.stellar.org",
            "Test SDF Network ; September 2015",
        )
        .await;
        assert!(
            matches!(result, Err(SimulateError::InvalidAddress { .. })),
            "invalid C-strkey must return InvalidAddress: {result:?}"
        );
    }

    // ── simulate_invoke_returning_scval: wiremock RPC paths ──────────────────

    // A valid C-strkey for test fixtures.
    const TEST_CONTRACT: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";
    const TEST_PASSPHRASE: &str = "Test SDF Network ; September 2015";

    // XDR-base64 for ScVal::Void (SCV_VOID discriminant 1 in xdr-27; Bool=0, Void=1).
    const SCVAL_VOID_B64: &str = "AAAAAQ==";

    // XDR-base64 for ScVal::I128(hi=0, lo=100_000_000).
    const SCVAL_I128_B64: &str = "AAAACgAAAAAAAAAAAAAAAAX14QA=";

    fn simulate_error_response_json(error_msg: &str) -> serde_json::Value {
        serde_json::json!({
            "latestLedger": 100,
            "error": error_msg
        })
    }

    fn simulate_no_results_response_json() -> serde_json::Value {
        serde_json::json!({
            "latestLedger": 100,
            "minResourceFee": "100"
        })
    }

    fn simulate_success_response_json(xdr_b64: &str) -> serde_json::Value {
        serde_json::json!({
            "latestLedger": 100,
            "minResourceFee": "100",
            "results": [{"auth": [], "xdr": xdr_b64}]
        })
    }

    /// Starts a wiremock server that responds to `simulateTransaction` JSON-RPC
    /// requests with `result`.  Uses [`stellar_agent_test_support::EchoIdResponder`]
    /// so `jsonrpsee-http-client` accepts the response (request-ID parity).
    async fn mock_simulate_server(result: serde_json::Value) -> (wiremock::MockServer, String) {
        use stellar_agent_test_support::EchoIdResponder;
        use wiremock::matchers::{body_partial_json, method, path};
        use wiremock::{Mock, MockServer};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_partial_json(
                serde_json::json!({"method": "simulateTransaction"}),
            ))
            .respond_with(EchoIdResponder::new(result))
            .mount(&server)
            .await;
        let url = server.uri();
        (server, url)
    }

    #[tokio::test]
    async fn simulate_rpc_error_field_returns_simulate_error() {
        let (_server, url) =
            mock_simulate_server(simulate_error_response_json("contract error: balance")).await;
        let result = simulate_invoke_returning_scval(
            TEST_CONTRACT,
            "balance",
            vec![],
            &url,
            TEST_PASSPHRASE,
        )
        .await;
        assert!(
            matches!(result, Err(SimulateError::SimulateError { ref reason }) if reason.contains("contract error")),
            "error field must return SimulateError with the error message: {result:?}"
        );
    }

    #[tokio::test]
    async fn simulate_no_results_returns_no_result() {
        let (_server, url) = mock_simulate_server(simulate_no_results_response_json()).await;
        let result = simulate_invoke_returning_scval(
            TEST_CONTRACT,
            "balance",
            vec![],
            &url,
            TEST_PASSPHRASE,
        )
        .await;
        assert!(
            matches!(result, Err(SimulateError::NoResult)),
            "missing results must return NoResult: {result:?}"
        );
    }

    #[tokio::test]
    async fn simulate_success_returns_void_scval() {
        let (_server, url) =
            mock_simulate_server(simulate_success_response_json(SCVAL_VOID_B64)).await;
        let result = simulate_invoke_returning_scval(
            TEST_CONTRACT,
            "balance",
            vec![],
            &url,
            TEST_PASSPHRASE,
        )
        .await;
        assert!(
            matches!(result, Ok(ScVal::Void)),
            "success must return ScVal::Void: {result:?}"
        );
    }

    #[tokio::test]
    async fn simulate_success_returns_i128_scval_with_correct_value() {
        let (_server, url) =
            mock_simulate_server(simulate_success_response_json(SCVAL_I128_B64)).await;
        let result = simulate_invoke_returning_scval(
            TEST_CONTRACT,
            "balance",
            vec![],
            &url,
            TEST_PASSPHRASE,
        )
        .await
        .expect("expected Ok");
        let value = decode_i128_scval(&result).expect("expected I128");
        assert_eq!(
            value, 100_000_000i128,
            "I128 decode must return 100_000_000"
        );
    }

    /// Structurally truncated XDR in the simulate result `xdr` field returns
    /// `DecodeFailed`.
    ///
    /// `"AAAA"` base64-decodes to three bytes, which is fewer than the four
    /// bytes needed for the XDR discriminant — so any decoder, bounded or not,
    /// must reject it.  This is a valid test for the truncated-XDR error path;
    /// it does NOT exercise the depth bound at line 224.
    #[tokio::test]
    async fn simulate_truncated_xdr_in_result_returns_decode_failed() {
        // "AAAA" decodes to three zero bytes — not a valid ScVal XDR encoding.
        let bad_xdr = "AAAA";
        let (_server, url) = mock_simulate_server(simulate_success_response_json(bad_xdr)).await;
        let result = simulate_invoke_returning_scval(
            TEST_CONTRACT,
            "balance",
            vec![],
            &url,
            TEST_PASSPHRASE,
        )
        .await;
        assert!(
            matches!(result, Err(SimulateError::DecodeFailed { .. })),
            "truncated XDR must return DecodeFailed: {result:?}"
        );
    }

    /// Encodes a deeply-nested `ScVal::Vec` chain (501 levels — above the 500
    /// level depth bound) with `Limits::none()` on the write side, then feeds
    /// it through a wiremock simulate response.  The bounded decode in
    /// `simulate_invoke_returning_scval` (line 224, `untrusted_decode_limits`)
    /// must reject it with `DecodeFailed`.
    ///
    /// This test is DISCRIMINATING: if line 224's bound were reverted to
    /// `Limits::none()`, the decode would succeed and the test would fail.
    /// The fixture is never decoded without bounds in the test itself; only the
    /// production function under test attempts to decode it.
    #[tokio::test]
    async fn simulate_depth_bomb_above_500_levels_returns_decode_failed() {
        use stellar_xdr::{Limits, ScVec, WriteXdr};

        // Build a 501-level nested ScVal::Vec iteratively (no recursion).
        // Each iteration wraps the current value in a single-element Vec.
        let mut current = ScVal::Void;
        for _ in 0..501 {
            let inner: stellar_xdr::VecM<ScVal> = vec![current]
                .try_into()
                .expect("single-element VecM must succeed");
            current = ScVal::Vec(Some(ScVec(inner)));
        }

        // Encode with Limits::none() on the write side — the structure is valid
        // XDR, just deeply nested beyond the 500-level read limit.
        let depth_bomb_xdr = current
            .to_xdr_base64(Limits::none())
            .expect("write with no limits must succeed");

        // Feed it as the simulate result xdr via wiremock.
        let (_server, url) =
            mock_simulate_server(simulate_success_response_json(&depth_bomb_xdr)).await;
        let result = simulate_invoke_returning_scval(
            TEST_CONTRACT,
            "balance",
            vec![],
            &url,
            TEST_PASSPHRASE,
        )
        .await;

        // The depth-bounded decode at line 224 must reject this as DecodeFailed.
        assert!(
            matches!(result, Err(SimulateError::DecodeFailed { .. })),
            "depth-bomb (501 levels) must be rejected by untrusted_decode_limits as \
             DecodeFailed; a reversion to Limits::none() would cause this test to fail \
             (Ok result instead): {result:?}"
        );
    }

    // ── Live testnet smoke test ──────────────────────────────────────────────

    /// Live testnet smoke test: calls `decimals()` on the testnet USDC SAC
    /// (`CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA`) and
    /// asserts the result is `ScVal::U32(7)`.
    ///
    /// This test closes the wire-contract loop that wiremock mocks cannot cover:
    /// if `stellar-rpc-client`'s serde contract drifts, the live call will fail
    /// before reaching the `ScVal` decode.
    ///
    /// Skips gracefully when the testnet RPC is unreachable (logs and returns;
    /// does not fail the task).  Run with `cargo test -- --ignored`.
    #[tokio::test]
    #[ignore = "live testnet — run with --ignored"]
    async fn live_testnet_usdc_sac_decimals_returns_u32_7() {
        const TESTNET_RPC: &str = "https://soroban-testnet.stellar.org";
        const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";
        // Testnet USDC SAC — token interface; `decimals()` returns U32(7).
        const USDC_SAC: &str = "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA";

        let result = simulate_invoke_returning_scval(
            USDC_SAC,
            "decimals",
            vec![],
            TESTNET_RPC,
            TESTNET_PASSPHRASE,
        )
        .await;

        match result {
            Ok(ScVal::U32(7)) => {
                // Expected result — wire-contract confirmed.
            }
            Ok(other) => {
                panic!("live testnet USDC SAC decimals: expected ScVal::U32(7), got {other:?}");
            }
            Err(SimulateError::SimulateFailed { ref reason })
                if reason.contains("connection")
                    || reason.contains("dns")
                    || reason.contains("connect") =>
            {
                // RPC unreachable — skip gracefully.
                tracing::info!("live testnet unreachable ({reason}); skipping live smoke test");
            }
            Err(e) => {
                panic!("live testnet USDC SAC decimals returned unexpected error: {e}");
            }
        }
    }
}
