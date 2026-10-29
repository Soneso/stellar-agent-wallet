//! The swap adapter's submission signs the router call with the transfer of
//! the input token under it, bounded by `amount_in`, and refuses a simulated
//! transfer above that bound before anything is signed.
//!
//! The mocked endpoint answers the whole adapter flow: the router WASM pin
//! read, the quote simulation, the auth-entry count simulation, the wallet's
//! authorized simulation, the signed re-simulation and the send.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "mock fixture construction and assertions"
)]

use std::any::Any;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use stellar_agent_defi::adapter::{DefiAdapter, DefiAdapterCtx, DefiAdapterError};
use stellar_agent_defi::dispatch::{GateOutcome, dispatch_gate};
use stellar_agent_defi::pins::DefiContractPin;
use stellar_agent_dex::abi::TradeArgs;
use stellar_agent_dex::adapter::DexSwapAdapter;
use stellar_agent_dex::pins::{SOROSWAP_ROUTER_ADDRESS_TESTNET, SOROSWAP_ROUTER_WASM_HASH_TESTNET};
use stellar_agent_network::StellarRpcClient;
use stellar_agent_network::signing::test_doubles::CountingSigner;
use stellar_agent_test_support::auth_tree_rpc::{AuthTreeEndpoint, AuthTreeRpc};
use stellar_agent_test_support::signed_envelope::{TESTNET_PASSPHRASE, account_id_for_seed};
use stellar_xdr::{
    ContractExecutable, ContractId, Hash, HostFunction, Int128Parts, InvokeContractArgs,
    OperationBody, ScAddress, ScContractInstance, ScSymbol, ScVal, ScVec,
    SorobanAuthorizedFunction, SorobanAuthorizedInvocation, SorobanCredentials,
    TransactionEnvelope,
};

const SEED: [u8; 32] = [0x61; 32];
const AMOUNT_IN: i128 = 1_000_000;
const AMOUNT_OUT: i128 = 990_000;

fn contract(byte: u8) -> ScAddress {
    ScAddress::Contract(ContractId(Hash([byte; 32])))
}

fn strkey(address: &ScAddress) -> String {
    let ScAddress::Contract(ContractId(Hash(bytes))) = address else {
        panic!("a contract address")
    };
    stellar_strkey::Contract(*bytes).to_string().to_string()
}

/// The smart account that swaps.
fn wallet() -> ScAddress {
    contract(0x57)
}

/// The input token, `path[0]`.
fn token_in() -> ScAddress {
    contract(0x70)
}

/// The output token.
fn token_out() -> ScAddress {
    contract(0x71)
}

/// The pair the router sends the input token to.
fn pair() -> ScAddress {
    contract(0x73)
}

fn router() -> ScAddress {
    let bytes = stellar_strkey::Contract::from_string(SOROSWAP_ROUTER_ADDRESS_TESTNET)
        .unwrap()
        .0;
    ScAddress::Contract(ContractId(Hash(bytes)))
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "i128 -> Int128Parts split: hi = high 64 bits, lo = low 64 bits"
)]
fn i128_val(amount: i128) -> ScVal {
    ScVal::I128(Int128Parts {
        hi: (amount >> 64) as i64,
        lo: amount as u64,
    })
}

/// `token.transfer(from, to, amount)` as a leaf of the authorized tree.
fn transfer(token: ScAddress, to: ScAddress, amount: i128) -> SorobanAuthorizedInvocation {
    SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
            contract_address: token,
            function_name: ScSymbol("transfer".try_into().unwrap()),
            args: vec![
                ScVal::Address(wallet()),
                ScVal::Address(to),
                i128_val(amount),
            ]
            .try_into()
            .unwrap(),
        }),
        sub_invocations: Default::default(),
    }
}

/// The router call with `transfer` under it.
fn swap_tree(
    invoke: &InvokeContractArgs,
    transfer: SorobanAuthorizedInvocation,
) -> SorobanAuthorizedInvocation {
    SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(invoke.clone()),
        sub_invocations: vec![transfer].try_into().unwrap(),
    }
}

fn is_swap(invoke: &InvokeContractArgs) -> bool {
    invoke.function_name.0.as_slice() == b"swap_exact_tokens_for_tokens"
}

/// What one adapter submission did.
struct Outcome {
    result: Result<(), DefiAdapterError>,
    signs: usize,
    endpoint: AuthTreeEndpoint,
}

impl Outcome {
    /// The router call and the wallet's signed tree in the one sent envelope.
    fn sent_call_and_tree(&self) -> (InvokeContractArgs, SorobanAuthorizedInvocation) {
        let sent = self.endpoint.sent();
        assert_eq!(sent.len(), 1, "one envelope is sent");
        let TransactionEnvelope::Tx(tx) = &sent[0] else {
            panic!("v1 envelope")
        };
        let OperationBody::InvokeHostFunction(op) = &tx.tx.operations[0].body else {
            panic!("invoke operation")
        };
        let HostFunction::InvokeContract(invoke) = &op.host_function else {
            panic!("contract function")
        };
        let entry = op
            .auth
            .iter()
            .find(|entry| {
                matches!(&entry.credentials,
                    SorobanCredentials::Address(creds) if creds.address == wallet())
            })
            .expect("the wallet's entry is in the envelope");
        (invoke.clone(), entry.root_invocation.clone())
    }
}

/// Runs the swap adapter's submit against an endpoint whose authorized
/// simulation of the router call carries `transfer` under it.
async fn swap(
    transfer: impl Fn() -> SorobanAuthorizedInvocation + Send + Sync + 'static,
) -> Outcome {
    let endpoint = AuthTreeRpc::new(TESTNET_PASSPHRASE, wallet())
        .account(&account_id_for_seed(SEED))
        .instance(
            router(),
            ScContractInstance {
                executable: ContractExecutable::Wasm(Hash(SOROSWAP_ROUTER_WASM_HASH_TESTNET)),
                storage: None,
            },
        )
        .tree(move |invoke| is_swap(invoke).then(|| swap_tree(invoke, transfer())))
        .returns(|invoke| {
            if invoke.function_name.0.as_slice() == b"router_get_amounts_out" {
                ScVal::Vec(Some(ScVec(
                    vec![i128_val(AMOUNT_IN), i128_val(AMOUNT_OUT)]
                        .try_into()
                        .unwrap(),
                )))
            } else {
                ScVal::Void
            }
        })
        .start()
        .await;

    let rpc = StellarRpcClient::new(&endpoint.uri()).unwrap();
    let pin = DefiContractPin::new(
        "soroswap",
        "router-direct",
        "default",
        "stellar:testnet",
        SOROSWAP_ROUTER_ADDRESS_TESTNET,
        SOROSWAP_ROUTER_WASM_HASH_TESTNET,
        "soroswap-core",
    );
    let signer = CountingSigner::new(SEED);
    let ctx = DefiAdapterCtx::new_with_submit_ctx(
        "default",
        &pin,
        &rpc,
        Some(&signer),
        Some(TESTNET_PASSPHRASE),
        Some("stellar:testnet"),
        None,
        Some(Duration::from_secs(5)),
    );
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let args = TradeArgs {
        from_address: strkey(&wallet()),
        amount_in: AMOUNT_IN,
        amount_out_min: AMOUNT_OUT,
        path: vec![strkey(&token_in()), strkey(&token_out())],
        deadline: Some(now + 300),
    };
    let adapter = DexSwapAdapter;
    let Ok(GateOutcome::Allow(witness)) = dispatch_gate(adapter.verb(), "swap-signed-tree") else {
        panic!("the trade verb is registered")
    };
    let result = adapter
        .submit(&args as &(dyn Any + Send + Sync), &ctx, witness)
        .await;
    Outcome {
        result,
        signs: signer.sign_calls(),
        endpoint,
    }
}

#[tokio::test]
async fn an_honest_swap_signs_the_simulated_tree() {
    let outcome = swap(|| transfer(token_in(), pair(), AMOUNT_IN)).await;

    assert!(outcome.result.is_ok(), "{:?}", outcome.result);
    assert!(outcome.signs > 0, "the wallet signs");
    assert_eq!(
        outcome.endpoint.signed_simulations(),
        1,
        "one signed re-simulation"
    );
    let (invoke, signed) = outcome.sent_call_and_tree();
    assert_eq!(invoke.contract_address, router(), "the router is invoked");
    assert_eq!(
        signed,
        swap_tree(&invoke, transfer(token_in(), pair(), AMOUNT_IN)),
        "the signed tree is the simulated one"
    );
}

#[tokio::test]
async fn a_transfer_above_amount_in_is_refused_before_signing() {
    let outcome = swap(|| transfer(token_in(), pair(), AMOUNT_IN + 1)).await;

    assert_eq!(outcome.signs, 0, "nothing is signed: {:?}", outcome.result);
    assert_eq!(outcome.endpoint.signed_simulations(), 0, "no re-simulation");
    assert!(outcome.endpoint.sent().is_empty(), "nothing is sent");
    match &outcome.result {
        Err(DefiAdapterError::Network { reason }) => {
            assert!(reason.contains("AuthContexts"), "{reason}");
            assert!(reason.contains("exceed the declared bound"), "{reason}");
        }
        other => panic!("expected the signed-tree refusal, got {other:?}"),
    }
}
