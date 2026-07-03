//! SEP-48-owned `InvokeHostFunction` decode.
//!
//! # Design
//!
//! `stellar-agent-sep48` owns its own `InvokeHostFunction` decode. It does NOT
//! call or extend `stellar_agent_core::envelope_decode::decode_authoritative_args`
//! (that function covers classic-op-only paths and has a two-tool allowlist that
//! must not be broadened). Both this module and `envelope_decode` use the same
//! `stellar-xdr` version, so `ScVal` / `ScSpecEntry` types interoperate with no
//! conversion shim.
//!
//! # Scope
//!
//! Given a base64-encoded `TransactionEnvelope`, this module extracts the
//! `(contract_id, function_name, args: Vec<ScVal>)` triple from the first
//! `InvokeHostFunction` operation it finds. Multi-operation transactions are
//! supported: only the first `InvokeHostFunction` with an `InvokeContract`
//! sub-function is decoded.
//!
//! # XDR byte-layout
//!
//! - `TransactionEnvelope` variants: `Tx(TransactionV1Envelope)`,
//!   `TxV0(TransactionV0Envelope)`, `TxFeeBump(FeeBumpTransactionEnvelope)`.
//! - `InvokeHostFunctionOp::host_function`:
//!   `HostFunction::InvokeContract(InvokeContractArgs)`.
//! - `InvokeContractArgs`: `contract_address: ScAddress`, `function_name: ScSymbol`,
//!   `args: VecM<ScVal>`.

use stellar_xdr::{
    ContractId, FeeBumpTransactionInnerTx, Hash, HostFunction, InvokeContractArgs, OperationBody,
    ReadXdr, TransactionEnvelope, TransactionV1Envelope,
};

use stellar_agent_xdr_limits::untrusted_decode_limits;

use crate::error::Sep48Error;

/// The decoded parts of an `InvokeHostFunction` / `InvokeContract` operation.
#[derive(Debug, Clone)]
pub struct DecodedInvocation {
    /// The C-strkey of the invoked contract.
    pub contract_strkey: String,
    /// The name of the invoked function (from `ScSymbol`).
    pub function_name: String,
    /// The positional arguments passed to the function.
    pub args: Vec<stellar_xdr::ScVal>,
}

/// Decodes the first `InvokeHostFunction` / `InvokeContract` operation from a
/// base64-encoded `TransactionEnvelope`.
///
/// # Arguments
///
/// * `tx_xdr_base64` — base64-encoded XDR of a `TransactionEnvelope`.
///
/// # Returns
///
/// The `(contract_id_strkey, function_name, args)` triple extracted from the
/// first `InvokeHostFunction` operation whose `host_function` is
/// `HostFunction::InvokeContract(InvokeContractArgs { .. })`.
///
/// # Errors
///
/// - [`Sep48Error::InvokeDecodeFailed`] — XDR parse failed or the transaction
///   contains no `InvokeHostFunction`/`InvokeContract` operation.
pub fn decode_invoke_host_function(tx_xdr_base64: &str) -> Result<DecodedInvocation, Sep48Error> {
    // `tx_xdr_base64` is caller-supplied (attacker-influenced) input; bounded
    // depth + len limits guard against stack exhaustion and oversized allocations.
    // Passing the base64 string length is safe: the decoded byte count is
    // strictly smaller, so valid input is never rejected.
    let limits = untrusted_decode_limits(tx_xdr_base64.len());
    let envelope = TransactionEnvelope::from_xdr_base64(tx_xdr_base64, limits).map_err(|e| {
        Sep48Error::InvokeDecodeFailed {
            reason: format!("TransactionEnvelope XDR decode failed: {e}"),
        }
    })?;

    let operations = match envelope {
        TransactionEnvelope::Tx(TransactionV1Envelope { tx, .. }) => tx.operations,
        TransactionEnvelope::TxV0(v0) => v0.tx.operations,
        TransactionEnvelope::TxFeeBump(fb) => {
            // Fee-bump wraps an inner TransactionV1; extract operations.
            match fb.tx.inner_tx {
                FeeBumpTransactionInnerTx::Tx(inner) => inner.tx.operations,
            }
        }
    };

    for op in operations.iter() {
        if let OperationBody::InvokeHostFunction(ihf) = &op.body
            && let HostFunction::InvokeContract(InvokeContractArgs {
                contract_address,
                function_name,
                args,
            }) = &ihf.host_function
        {
            let contract_strkey = sc_address_to_contract_strkey(contract_address)?;
            let fn_name = std::str::from_utf8(function_name.0.as_slice())
                .map_err(|e| Sep48Error::InvokeDecodeFailed {
                    reason: format!("function_name UTF-8 decode failed: {e}"),
                })?
                .to_owned();
            let arg_vec = args.to_vec();
            return Ok(DecodedInvocation {
                contract_strkey,
                function_name: fn_name,
                args: arg_vec,
            });
        }
    }

    Err(Sep48Error::InvokeDecodeFailed {
        reason: "no InvokeHostFunction/InvokeContract operation found in transaction".to_owned(),
    })
}

/// Converts an `ScAddress` to its C-strkey string representation.
///
/// Only `ScAddress::Contract` is supported; `ScAddress::Account` returns an
/// error because an account address cannot be the target of `InvokeContract`.
///
/// # Errors
///
/// Returns [`Sep48Error::InvokeDecodeFailed`] for non-contract address variants.
fn sc_address_to_contract_strkey(addr: &stellar_xdr::ScAddress) -> Result<String, Sep48Error> {
    use stellar_xdr::ScAddress;
    match addr {
        ScAddress::Contract(ContractId(Hash(bytes))) => {
            // stellar_strkey::Contract.to_string() returns heapless::String<56>;
            // use .as_str() to convert to &str then build a std::String.
            let hs = stellar_strkey::Contract(*bytes).to_string();
            Ok(hs.as_str().to_owned())
        }
        ScAddress::Account(_) => Err(Sep48Error::InvokeDecodeFailed {
            reason: "InvokeContract target is an Account address, expected Contract".to_owned(),
        }),
        _ => Err(Sep48Error::InvokeDecodeFailed {
            reason: "InvokeContract target has an unsupported ScAddress variant".to_owned(),
        }),
    }
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
    use stellar_xdr::{
        FeeBumpTransaction, FeeBumpTransactionEnvelope, FeeBumpTransactionExt,
        FeeBumpTransactionInnerTx, Hash, HostFunction, Int128Parts, InvokeContractArgs,
        InvokeHostFunctionOp, Limits, MuxedAccount, Operation, OperationBody, Preconditions,
        ScAddress, ScSymbol, ScVal, SequenceNumber, SorobanResources, SorobanTransactionData,
        SorobanTransactionDataExt, Transaction, TransactionEnvelope, TransactionExt,
        TransactionV1Envelope, Uint256, VecM, WriteXdr,
    };

    fn make_invoke_tx(
        contract_bytes: [u8; 32],
        fn_name: &str,
        args: Vec<ScVal>,
    ) -> TransactionEnvelope {
        use stellar_xdr::{ContractId, LedgerFootprint};

        let args_vec: VecM<ScVal> = args.try_into().unwrap();
        let ihf = InvokeHostFunctionOp {
            host_function: HostFunction::InvokeContract(InvokeContractArgs {
                contract_address: ScAddress::Contract(ContractId(Hash(contract_bytes))),
                function_name: ScSymbol(fn_name.as_bytes().try_into().unwrap()),
                args: args_vec,
            }),
            auth: VecM::default(),
        };
        let op = Operation {
            source_account: None,
            body: OperationBody::InvokeHostFunction(ihf),
        };
        let source = MuxedAccount::Ed25519(Uint256([0u8; 32]));
        let soroban_data = SorobanTransactionData {
            ext: SorobanTransactionDataExt::V0,
            resources: SorobanResources {
                footprint: LedgerFootprint {
                    read_only: VecM::default(),
                    read_write: VecM::default(),
                },
                instructions: 0,
                disk_read_bytes: 0,
                write_bytes: 0,
            },
            resource_fee: 0,
        };
        let tx = Transaction {
            source_account: source,
            fee: 100,
            seq_num: SequenceNumber(1),
            cond: Preconditions::None,
            memo: stellar_xdr::Memo::None,
            operations: vec![op].try_into().unwrap(),
            ext: TransactionExt::V1(soroban_data),
        };
        TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: VecM::default(),
        })
    }

    fn encode_tx(env: &TransactionEnvelope) -> String {
        env.to_xdr_base64(Limits::none()).unwrap()
    }

    #[test]
    fn decode_invalid_xdr_returns_error() {
        let result = decode_invoke_host_function("not-valid-base64");
        assert!(
            matches!(result, Err(Sep48Error::InvokeDecodeFailed { .. })),
            "invalid XDR must return InvokeDecodeFailed"
        );
    }

    #[test]
    fn decode_empty_xdr_returns_error() {
        let result = decode_invoke_host_function("");
        assert!(
            matches!(result, Err(Sep48Error::InvokeDecodeFailed { .. })),
            "empty XDR must return InvokeDecodeFailed"
        );
    }

    #[test]
    fn decode_valid_invoke_contract_tx() {
        let contract_bytes = [1u8; 32];
        let amount_arg = ScVal::I128(Int128Parts { hi: 0, lo: 500 });
        let tx_env = make_invoke_tx(contract_bytes, "transfer", vec![amount_arg]);
        let b64 = encode_tx(&tx_env);
        let result = decode_invoke_host_function(&b64).unwrap();
        assert_eq!(result.function_name, "transfer");
        assert_eq!(result.args.len(), 1);
        assert!(
            result.contract_strkey.starts_with('C'),
            "contract strkey must start with C"
        );
    }

    #[test]
    fn decode_tx_with_no_invoke_host_function_returns_error() {
        // Build a transaction with a payment op (no InvokeHostFunction).
        use stellar_xdr::{Asset, PaymentOp, SequenceNumber};
        let payment = PaymentOp {
            destination: MuxedAccount::Ed25519(Uint256([0u8; 32])),
            asset: Asset::Native,
            amount: 100,
        };
        let op = Operation {
            source_account: None,
            body: OperationBody::Payment(payment),
        };
        let source = MuxedAccount::Ed25519(Uint256([0u8; 32]));
        let tx = Transaction {
            source_account: source,
            fee: 100,
            seq_num: SequenceNumber(1),
            cond: Preconditions::None,
            memo: stellar_xdr::Memo::None,
            operations: vec![op].try_into().unwrap(),
            ext: TransactionExt::V0,
        };
        let env = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: VecM::default(),
        });
        let b64 = encode_tx(&env);
        let result = decode_invoke_host_function(&b64);
        assert!(
            matches!(result, Err(Sep48Error::InvokeDecodeFailed { .. })),
            "payment-only tx must return InvokeDecodeFailed"
        );
    }

    /// Verifies the `TxV0` envelope arm: a `TransactionV0Envelope` wrapping an
    /// `InvokeHostFunction` / `InvokeContract` operation decodes to the correct
    /// `DecodedInvocation`.
    ///
    /// `TransactionV0` shares the same `Operation`/`OperationBody` types as
    /// `Transaction` (V1), so a TxV0 envelope CAN carry an `InvokeHostFunction`
    /// op with an `InvokeContract` host function.  The `source_account_ed25519`
    /// field is a bare `Uint256` (no mux tag) and the ext union is `V0`-only.
    #[test]
    fn decode_txv0_invoke_contract_tx() {
        use stellar_xdr::{
            ContractId, InvokeContractArgs, ScAddress, ScSymbol, TimeBounds, TransactionV0,
            TransactionV0Envelope, TransactionV0Ext,
        };

        let contract_bytes = [3u8; 32];
        let amount_arg = ScVal::I128(stellar_xdr::Int128Parts { hi: 0, lo: 999 });

        let ihf = InvokeHostFunctionOp {
            host_function: HostFunction::InvokeContract(InvokeContractArgs {
                contract_address: ScAddress::Contract(ContractId(Hash(contract_bytes))),
                function_name: ScSymbol("do_work".as_bytes().try_into().unwrap()),
                args: vec![amount_arg.clone()].try_into().unwrap(),
            }),
            auth: VecM::default(),
        };
        let op = Operation {
            source_account: None,
            body: OperationBody::InvokeHostFunction(ihf),
        };
        let txv0 = TransactionV0 {
            source_account_ed25519: Uint256([0u8; 32]),
            fee: 100,
            seq_num: SequenceNumber(1),
            time_bounds: None::<TimeBounds>,
            memo: stellar_xdr::Memo::None,
            operations: vec![op].try_into().unwrap(),
            ext: TransactionV0Ext::V0,
        };
        let env = TransactionEnvelope::TxV0(TransactionV0Envelope {
            tx: txv0,
            signatures: VecM::default(),
        });
        let b64 = encode_tx(&env);

        let result = decode_invoke_host_function(&b64).unwrap();

        assert_eq!(
            result.function_name, "do_work",
            "TxV0 envelope must decode function_name correctly"
        );
        assert_eq!(
            result.args.len(),
            1,
            "TxV0 envelope must decode exactly 1 arg"
        );
        assert_eq!(
            result.args[0], amount_arg,
            "TxV0 envelope must decode the arg value correctly"
        );
        assert!(
            result.contract_strkey.starts_with('C'),
            "TxV0 contract strkey must start with C, got: {}",
            result.contract_strkey
        );
        // Verify the exact contract strkey round-trips correctly.
        let expected_strkey = stellar_strkey::Contract(contract_bytes).to_string();
        assert_eq!(
            result.contract_strkey,
            expected_strkey.as_str(),
            "TxV0 contract strkey must match the encoded contract_bytes"
        );
    }

    #[test]
    fn decode_fee_bump_invoke_contract_tx() {
        let contract_bytes = [2u8; 32];
        let inner_env = make_invoke_tx(contract_bytes, "mint", vec![]);
        let inner_v1 = match inner_env {
            TransactionEnvelope::Tx(v1) => v1,
            _ => panic!("expected Tx variant"),
        };
        let fee_bump_tx = FeeBumpTransaction {
            fee_source: MuxedAccount::Ed25519(Uint256([0u8; 32])),
            fee: 200,
            inner_tx: FeeBumpTransactionInnerTx::Tx(inner_v1),
            ext: FeeBumpTransactionExt::V0,
        };
        let fb_env = TransactionEnvelope::TxFeeBump(FeeBumpTransactionEnvelope {
            tx: fee_bump_tx,
            signatures: VecM::default(),
        });
        let b64 = encode_tx(&fb_env);
        let result = decode_invoke_host_function(&b64).unwrap();
        assert_eq!(result.function_name, "mint");
    }

    /// Regression: a 600-deep `SorobanAuthorizedInvocation.sub_invocations`
    /// chain encoded with `Limits::none()` (write side) must be REJECTED by the
    /// bounded decode, not cause a stack overflow or panic.
    ///
    /// The depth-500 limit (matching `soroban-env-host DEFAULT_XDR_RW_LIMITS.depth`)
    /// is tighter than the 600-deep fixture, so the decode returns the typed
    /// `InvokeDecodeFailed` error before attempting the full recursive parse.
    ///
    /// NOTE: `TransactionEnvelope::from_xdr_base64` hits the depth limit at the
    /// nesting level of its own structure before it could recurse into the
    /// `SorobanAuthorizedInvocation` tree, so this test validates the depth
    /// guard via an overly-nested `TransactionEnvelope` structure wrapping a
    /// deeply nested auth tree inside the invocation.
    #[test]
    fn depth_bomb_nested_invocation_rejected_not_panics() {
        use stellar_xdr::{
            ContractId, InvokeContractArgs, ScAddress, ScSymbol, SorobanAuthorizedFunction,
            SorobanAuthorizedInvocation,
        };

        // Build a 600-deep SorobanAuthorizedInvocation tree iteratively.
        let leaf = SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                contract_address: ScAddress::Contract(ContractId(Hash([0u8; 32]))),
                function_name: ScSymbol("f".as_bytes().try_into().unwrap()),
                args: VecM::default(),
            }),
            sub_invocations: VecM::default(),
        };

        let mut chain = leaf;
        for _ in 0..600 {
            chain = SorobanAuthorizedInvocation {
                function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                    contract_address: ScAddress::Contract(ContractId(Hash([0u8; 32]))),
                    function_name: ScSymbol("g".as_bytes().try_into().unwrap()),
                    args: VecM::default(),
                }),
                sub_invocations: vec![chain].try_into().unwrap(),
            };
        }

        // Wrap inside an InvokeHostFunctionOp auth entry.
        let ihf = InvokeHostFunctionOp {
            host_function: HostFunction::InvokeContract(InvokeContractArgs {
                contract_address: ScAddress::Contract(ContractId(Hash([1u8; 32]))),
                function_name: ScSymbol("top".as_bytes().try_into().unwrap()),
                args: VecM::default(),
            }),
            auth: vec![stellar_xdr::SorobanAuthorizationEntry {
                credentials: stellar_xdr::SorobanCredentials::SourceAccount,
                root_invocation: chain,
            }]
            .try_into()
            .unwrap(),
        };

        let op = Operation {
            source_account: None,
            body: OperationBody::InvokeHostFunction(ihf),
        };
        use stellar_xdr::{LedgerFootprint, SorobanResources, SorobanTransactionData};
        let soroban_data = SorobanTransactionData {
            ext: SorobanTransactionDataExt::V0,
            resources: SorobanResources {
                footprint: LedgerFootprint {
                    read_only: VecM::default(),
                    read_write: VecM::default(),
                },
                instructions: 0,
                disk_read_bytes: 0,
                write_bytes: 0,
            },
            resource_fee: 0,
        };
        let tx = Transaction {
            source_account: MuxedAccount::Ed25519(Uint256([0u8; 32])),
            fee: 100,
            seq_num: SequenceNumber(1),
            cond: Preconditions::None,
            memo: stellar_xdr::Memo::None,
            operations: vec![op].try_into().unwrap(),
            ext: TransactionExt::V1(soroban_data),
        };
        let env = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: VecM::default(),
        });

        // Encode with no limits (write side — not a security concern for the writer).
        let b64 = env.to_xdr_base64(Limits::none()).unwrap();

        // The bounded decode (depth 500) MUST reject this, returning the typed
        // error rather than panicking or stack-overflowing.
        let result = decode_invoke_host_function(&b64);
        assert!(
            matches!(result, Err(Sep48Error::InvokeDecodeFailed { .. })),
            "depth-600 nested invocation must return InvokeDecodeFailed (depth limit), got: {result:?}"
        );
    }
}
