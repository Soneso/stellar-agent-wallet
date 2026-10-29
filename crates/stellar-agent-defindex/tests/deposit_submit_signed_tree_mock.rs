//! The vault adapter's deposit submission signs the deposit call with the
//! transfers of the vault assets to the vault under it, each bounded by its
//! desired amount, and refuses a simulated transfer above that bound or to
//! another recipient before anything is signed.
//!
//! The mocked endpoint answers the whole adapter flow: the vault WASM pin
//! read, the upgradable-flag, role and asset reads from the vault instance,
//! the wallet's authorized simulation, the signed re-simulation and the send.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "mock fixture construction and assertions"
)]

use std::any::Any;
use std::time::Duration;

use stellar_agent_defi::adapter::{DefiAdapter, DefiAdapterCtx, DefiAdapterError};
use stellar_agent_defi::dispatch::{GateOutcome, dispatch_gate};
use stellar_agent_defi::pins::DefiContractPin;
use stellar_agent_defindex::abi::VaultDepositArgs;
use stellar_agent_defindex::adapter::DefindexVaultAdapter;
use stellar_agent_defindex::pins::DEFINDEX_VAULT_WASM_HASH;
use stellar_agent_network::StellarRpcClient;
use stellar_agent_network::signing::test_doubles::CountingSigner;
use stellar_agent_test_support::auth_tree_rpc::{AuthTreeEndpoint, AuthTreeRpc};
use stellar_agent_test_support::signed_envelope::{TESTNET_PASSPHRASE, account_id_for_seed};
use stellar_xdr::{
    ContractExecutable, ContractId, Hash, HostFunction, Int128Parts, InvokeContractArgs,
    OperationBody, ScAddress, ScContractInstance, ScMap, ScMapEntry, ScSymbol, ScVal, ScVec,
    SorobanAuthorizedFunction, SorobanAuthorizedInvocation, SorobanCredentials,
    TransactionEnvelope,
};

const SEED: [u8; 32] = [0x61; 32];
const DESIRED: i128 = 1_000_000;

fn contract(byte: u8) -> ScAddress {
    ScAddress::Contract(ContractId(Hash([byte; 32])))
}

fn strkey(address: &ScAddress) -> String {
    let ScAddress::Contract(ContractId(Hash(bytes))) = address else {
        panic!("a contract address")
    };
    stellar_strkey::Contract(*bytes).to_string().to_string()
}

/// The smart account that deposits.
fn wallet() -> ScAddress {
    contract(0x57)
}

/// The vault deposited into.
fn vault() -> ScAddress {
    contract(0x5A)
}

/// The vault's one asset.
fn asset() -> ScAddress {
    contract(0x70)
}

/// A recipient the deposit never pays.
fn attacker() -> ScAddress {
    contract(0xAA)
}

fn symbol(name: &str) -> ScVal {
    ScVal::Symbol(ScSymbol(name.try_into().unwrap()))
}

fn vec_val(items: Vec<ScVal>) -> ScVal {
    ScVal::Vec(Some(ScVec(items.try_into().unwrap())))
}

fn map_entry(key: ScVal, val: ScVal) -> ScMapEntry {
    ScMapEntry { key, val }
}

/// The vault instance: the pinned WASM, not upgradable, one asset with no
/// strategies.
fn vault_instance() -> ScContractInstance {
    let asset_strategy_set = ScVal::Map(Some(ScMap(
        vec![
            map_entry(symbol("address"), ScVal::Address(asset())),
            map_entry(symbol("strategies"), vec_val(vec![])),
        ]
        .try_into()
        .unwrap(),
    )));
    ScContractInstance {
        executable: ContractExecutable::Wasm(Hash(DEFINDEX_VAULT_WASM_HASH)),
        storage: Some(ScMap(
            vec![
                map_entry(vec_val(vec![symbol("Upgradable")]), ScVal::Bool(false)),
                map_entry(vec_val(vec![symbol("TotalAssets")]), ScVal::U32(1)),
                map_entry(
                    vec_val(vec![symbol("AssetStrategySet"), ScVal::U32(0)]),
                    asset_strategy_set,
                ),
            ]
            .try_into()
            .unwrap(),
        )),
    }
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

/// `asset.transfer(wallet, to, amount)` as a leaf of the authorized tree.
fn transfer(to: ScAddress, amount: i128) -> SorobanAuthorizedInvocation {
    SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
            contract_address: asset(),
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

/// The deposit call with `transfer` under it.
fn deposit_tree(
    invoke: &InvokeContractArgs,
    transfer: SorobanAuthorizedInvocation,
) -> SorobanAuthorizedInvocation {
    SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(invoke.clone()),
        sub_invocations: vec![transfer].try_into().unwrap(),
    }
}

/// What one adapter submission did.
struct Outcome {
    result: Result<(), DefiAdapterError>,
    signs: usize,
    endpoint: AuthTreeEndpoint,
}

impl Outcome {
    /// The vault call and the wallet's signed tree in the one sent envelope.
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

    /// Asserts the submission was refused with the signed-tree divergence
    /// before any signing primitive ran and before a re-simulation, and
    /// returns the refusal's text.
    fn refused_before_signing(&self) -> String {
        assert_eq!(self.signs, 0, "nothing is signed: {:?}", self.result);
        assert_eq!(self.endpoint.signed_simulations(), 0, "no re-simulation");
        assert!(self.endpoint.sent().is_empty(), "nothing is sent");
        match &self.result {
            Err(DefiAdapterError::Network { reason }) => {
                assert!(reason.contains("AuthContexts"), "{reason}");
                reason.clone()
            }
            other => panic!("expected the signed-tree refusal, got {other:?}"),
        }
    }
}

/// Runs the vault adapter's deposit submit against an endpoint whose
/// authorized simulation of the deposit carries `transfer` under it.
async fn deposit(
    transfer: impl Fn() -> SorobanAuthorizedInvocation + Send + Sync + 'static,
) -> Outcome {
    let endpoint = AuthTreeRpc::new(TESTNET_PASSPHRASE, wallet())
        .account(&account_id_for_seed(SEED))
        .instance(vault(), vault_instance())
        .tree(move |invoke| {
            (invoke.function_name.0.as_slice() == b"deposit")
                .then(|| deposit_tree(invoke, transfer()))
        })
        .start()
        .await;

    let rpc = StellarRpcClient::new(&endpoint.uri()).unwrap();
    let pin = DefiContractPin::new(
        "defindex",
        "vault",
        "default",
        "stellar:testnet",
        strkey(&vault()),
        DEFINDEX_VAULT_WASM_HASH,
        "defindex",
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
    let args = VaultDepositArgs {
        vault_address: strkey(&vault()),
        amounts_desired: vec![DESIRED],
        amounts_min: vec![DESIRED - 1_000],
        from_address: strkey(&wallet()),
        invest: false,
        override_upgradable: false,
    };
    let adapter = DefindexVaultAdapter::new();
    let Ok(GateOutcome::Allow(witness)) = dispatch_gate(adapter.verb(), "deposit-signed-tree")
    else {
        panic!("the vault verb is registered")
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
async fn an_honest_deposit_signs_the_simulated_tree() {
    let outcome = deposit(|| transfer(vault(), DESIRED)).await;

    assert!(outcome.result.is_ok(), "{:?}", outcome.result);
    assert!(outcome.signs > 0, "the wallet signs");
    assert_eq!(
        outcome.endpoint.signed_simulations(),
        1,
        "one signed re-simulation"
    );
    let (invoke, signed) = outcome.sent_call_and_tree();
    assert_eq!(invoke.contract_address, vault(), "the vault is invoked");
    assert_eq!(
        signed,
        deposit_tree(&invoke, transfer(vault(), DESIRED)),
        "the signed tree is the simulated one"
    );
}

#[tokio::test]
async fn a_transfer_above_the_desired_amount_is_refused_before_signing() {
    let outcome = deposit(|| transfer(vault(), DESIRED + 1)).await;

    let reason = outcome.refused_before_signing();
    assert!(reason.contains("exceed the declared bound"), "{reason}");
}

#[tokio::test]
async fn a_transfer_to_another_recipient_is_refused_before_signing() {
    let outcome = deposit(|| transfer(attacker(), DESIRED)).await;

    let reason = outcome.refused_before_signing();
    assert!(reason.contains("to an undeclared recipient"), "{reason}");
}
