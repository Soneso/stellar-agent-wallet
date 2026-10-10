extern crate std;

use super::*;
use soroban_sdk::{
    symbol_short,
    testutils::{
        storage::Instance as _, Address as _, AuthorizedFunction, AuthorizedInvocation, Ledger as _,
    },
    vec,
    xdr::{
        ContractEventBody, ContractId, ScAddress, ScError, ScErrorCode, ScErrorType, ScSymbol,
        ScVal,
    },
    Error, IntoVal,
};

#[contract]
struct Counter;

#[contractimpl]
impl Counter {
    pub fn add(e: Env, amount: u32) -> u32 {
        let value = Self::get(e.clone()) + amount;
        e.storage().instance().set(&symbol_short!("value"), &value);
        value
    }

    pub fn mul(e: Env, factor: u32) -> u32 {
        let value = Self::get(e.clone()) * factor;
        e.storage().instance().set(&symbol_short!("value"), &value);
        value
    }

    pub fn get(e: Env) -> u32 {
        e.storage()
            .instance()
            .get(&symbol_short!("value"))
            .unwrap_or(0)
    }
}

#[contract]
struct Adder;

#[contractimpl]
impl Adder {
    pub fn add(a: u32, b: u32) -> u32 {
        a + b
    }

    pub fn fail() {
        panic!("inner invocation fails");
    }
}

/// The contract id of the contract address `address`.
fn contract_id(address: &Address) -> ContractId {
    match ScAddress::from(address) {
        ScAddress::Contract(id) => id,
        other => panic!("expected a contract address, got {other:?}"),
    }
}

/// The instance TTL of `router`, in ledgers after the current one.
fn instance_ttl(env: &Env, router: &Address) -> u32 {
    env.as_contract(router, || env.storage().instance().get_ttl())
}

#[test]
fn execution_and_results_follow_input_order() {
    let env = Env::default();
    env.mock_all_auths();
    let router = env.register(MulticallRouter, ());
    let counter = env.register(Counter, ());
    let adder = env.register(Adder, ());
    let caller = Address::generate(&env);
    let invocations = vec![
        &env,
        (
            counter.clone(),
            symbol_short!("add"),
            (2_u32,).into_val(&env),
        ),
        (adder, symbol_short!("add"), (2_u32, 3_u32).into_val(&env)),
        (
            counter.clone(),
            symbol_short!("mul"),
            (10_u32,).into_val(&env),
        ),
    ];

    let results = MulticallRouterClient::new(&env, &router).exec(&caller, &invocations);
    assert_eq!(
        env.auths(),
        std::vec![(
            caller.clone(),
            AuthorizedInvocation {
                function: AuthorizedFunction::Contract((
                    router,
                    symbol_short!("exec"),
                    (caller, invocations).into_val(&env),
                )),
                sub_invocations: std::vec![],
            },
        )]
    );
    assert_eq!(
        results,
        vec![
            &env,
            2_u32.into_val(&env),
            5_u32.into_val(&env),
            20_u32.into_val(&env)
        ]
    );
    assert_eq!(CounterClient::new(&env, &counter).get(), 20);
}

#[test]
fn failing_inner_call_aborts_and_rolls_back_bundle() {
    let env = Env::default();
    env.mock_all_auths();
    let router = env.register(MulticallRouter, ());
    let counter = env.register(Counter, ());
    let adder = env.register(Adder, ());
    let invocations = vec![
        &env,
        (
            counter.clone(),
            symbol_short!("add"),
            (5_u32,).into_val(&env),
        ),
        (adder.clone(), symbol_short!("fail"), vec![&env]),
    ];
    let result =
        MulticallRouterClient::new(&env, &router).try_exec(&Address::generate(&env), &invocations);
    assert_eq!(
        result,
        Err(Ok(Error::from_type_and_code(
            ScErrorType::Context,
            ScErrorCode::InvalidAction
        )))
    );
    // try_call exposes a generic host error. The diagnostics show the
    // counter's add returning 5 inside the failed call before the adder's
    // panic raises the error, so the stored 0 below is a rollback.
    let diagnostics = env.host().get_diagnostic_events().unwrap();
    let counter_id = contract_id(&counter);
    let adder_id = contract_id(&adder);
    let fn_return = ScVal::Symbol(ScSymbol::try_from("fn_return").unwrap());
    let add = ScVal::Symbol(ScSymbol::try_from("add").unwrap());
    let add_returned = diagnostics
        .0
        .iter()
        .position(|event| {
            let ContractEventBody::V0(body) = &event.event.body;
            event.failed_call
                && event.event.contract_id.as_ref() == Some(&counter_id)
                && body.topics.as_slice() == [fn_return.clone(), add.clone()]
                && body.data == ScVal::U32(5)
        })
        .expect("the counter's add returned 5 inside the failed call");
    let fail_raised = diagnostics
        .0
        .iter()
        .position(|event| {
            let ContractEventBody::V0(body) = &event.event.body;
            event.event.contract_id.as_ref() == Some(&adder_id)
                && body
                    .topics
                    .contains(&ScVal::Error(ScError::WasmVm(ScErrorCode::InvalidAction)))
        })
        .expect("the adder's fail raised the error");
    assert!(add_returned < fail_raised);
    assert_eq!(CounterClient::new(&env, &counter).get(), 0);
}

#[test]
fn missing_authorization_fails_with_host_auth_error() {
    let env = Env::default();
    let router = env.register(MulticallRouter, ());
    let result =
        MulticallRouterClient::new(&env, &router).try_exec(&Address::generate(&env), &vec![&env]);
    assert_eq!(
        result,
        Err(Ok(Error::from_type_and_code(
            ScErrorType::Context,
            ScErrorCode::InvalidAction
        )))
    );
    // try_call exposes a generic host error; diagnostics retain the auth code.
    let diagnostics = env.host().get_diagnostic_events().unwrap();
    assert!(diagnostics.0.iter().any(|event| {
        let ContractEventBody::V0(body) = &event.event.body;
        body.topics
            .contains(&ScVal::Error(ScError::Auth(ScErrorCode::InvalidAction)))
    }));
}

#[test]
fn exec_extends_instance_ttl_to_30_days() {
    let env = Env::default();
    env.mock_all_auths();
    let router = env.register(MulticallRouter, ());
    MulticallRouterClient::new(&env, &router).exec(&Address::generate(&env), &vec![&env]);
    assert_eq!(instance_ttl(&env, &router), 30 * 17_280);
}

#[test]
fn exec_extends_instance_ttl_only_when_fewer_than_23_days_remain() {
    let env = Env::default();
    env.mock_all_auths();
    let router = env.register(MulticallRouter, ());
    let client = MulticallRouterClient::new(&env, &router);
    let caller = Address::generate(&env);
    client.exec(&caller, &vec![&env]);
    let live_until = env.ledger().sequence() + instance_ttl(&env, &router);

    // Six days later 24 days remain, so exec leaves the live-until ledger.
    env.ledger()
        .with_mut(|ledger| ledger.sequence_number += 6 * 17_280);
    client.exec(&caller, &vec![&env]);
    assert_eq!(
        env.ledger().sequence() + instance_ttl(&env, &router),
        live_until
    );
    assert_eq!(instance_ttl(&env, &router), 24 * 17_280);

    // Two days later 22 days remain, so exec extends the TTL to 30 days.
    env.ledger()
        .with_mut(|ledger| ledger.sequence_number += 2 * 17_280);
    client.exec(&caller, &vec![&env]);
    assert_eq!(instance_ttl(&env, &router), 30 * 17_280);
}

#[test]
fn empty_bundle_returns_empty_results() {
    let env = Env::default();
    env.mock_all_auths();
    let router = env.register(MulticallRouter, ());
    assert_eq!(
        MulticallRouterClient::new(&env, &router).exec(&Address::generate(&env), &vec![&env]),
        vec![&env]
    );
}
