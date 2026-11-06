//! Canonical envelope fixtures for checked admission tests.
#![allow(clippy::unwrap_used, clippy::panic, reason = "test fixture invariants")]
use stellar_agent_core::policy::v1::criteria::state_store::{StateKey, WindowEntry};
use stellar_agent_core::profile::caip2::Caip2;
/// Freezes explicit checked fixture entries into a test plan.
#[must_use]
pub fn with_legs(
    plan: &crate::SignedIntentPlan,
    entries: &[WindowEntry],
) -> crate::SignedIntentPlan {
    plan.with_legs(entries)
}

/// Builds an empty authorization fixture with amount and count legs.
#[must_use]
///
/// # Panics
/// Panics if the fixed fixture cannot encode its authorization.
pub fn intent_fixture_plan(
    sequence: i64,
    amount: i128,
) -> (crate::SignedIntentPlan, stellar_xdr::TransactionEnvelope) {
    use stellar_agent_core::policy::v1::criteria::WindowLimit;
    use stellar_xdr::*;
    let host = HostFunction::InvokeContract(InvokeContractArgs {
        contract_address: ScAddress::Contract(ContractId(Hash([1; 32]))),
        function_name: ScSymbol::try_from("call").unwrap(),
        args: Default::default(),
    });
    let source = stellar_strkey::ed25519::PublicKey([0; 32])
        .to_string()
        .as_str()
        .to_owned();
    let plan = crate::SignedIntentPlan::new(
        Caip2::Testnet.network_passphrase(),
        &source,
        &source,
        sequence,
        crate::intent_xdr_hash(&host).unwrap(),
        Vec::new(),
        None,
    )
    .unwrap();
    let plan = plan.with_legs(&[
        WindowEntry::new(
            StateKey::new("intent", 1, "native", 60),
            1000,
            amount,
            WindowLimit::Amount {
                asset: "native".into(),
                window: "1m".into(),
                max_stroops: amount,
            },
        ),
        WindowEntry::new(
            StateKey::new("intent", 1, "rate_limit", 60),
            1000,
            1,
            WindowLimit::Count {
                window: "1m".into(),
                max_calls: 1,
            },
        ),
    ]);
    let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx: Transaction {
            source_account: MuxedAccount::Ed25519(Uint256([0; 32])),
            fee: 100,
            seq_num: SequenceNumber(sequence),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: vec![Operation {
                source_account: None,
                body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                    host_function: host,
                    auth: Default::default(),
                }),
            }]
            .try_into()
            .unwrap(),
            ext: TransactionExt::V0,
        },
        signatures: Default::default(),
    });
    (plan, envelope)
}

/// Builds source or smart account authorization for the fixture invocation.
///
/// # Panics
/// Panics if the fixed fixture cannot encode its authorization.
#[must_use]
pub fn fixture_entry(source: bool) -> stellar_xdr::SorobanAuthorizationEntry {
    use stellar_xdr::*;
    let (_, envelope) = intent_fixture_plan(1, 60);
    let TransactionEnvelope::Tx(envelope) = envelope else {
        panic!("V1");
    };
    let OperationBody::InvokeHostFunction(op) = &envelope.tx.operations[0].body else {
        panic!("invoke");
    };
    let HostFunction::InvokeContract(call) = &op.host_function else {
        panic!("call");
    };
    let root_invocation = SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(call.clone()),
        sub_invocations: Default::default(),
    };
    if source {
        return SorobanAuthorizationEntry {
            credentials: SorobanCredentials::SourceAccount,
            root_invocation,
        };
    }
    let symbol = |name: &str| ScVal::Symbol(ScSymbol::try_from(name).unwrap());
    let bytes = |value: u8| ScVal::Bytes(ScBytes(vec![value; 32].try_into().unwrap()));
    let mut signers = vec![
        ScMapEntry {
            key: ScVal::Vec(Some(
                vec![
                    symbol("Delegated"),
                    ScVal::Address(ScAddress::Account(AccountId(
                        PublicKey::PublicKeyTypeEd25519(Uint256([2; 32])),
                    ))),
                ]
                .try_into()
                .unwrap(),
            )),
            val: bytes(0),
        },
        ScMapEntry {
            key: ScVal::Vec(Some(
                vec![
                    symbol("External"),
                    ScVal::Address(ScAddress::Contract(ContractId(Hash([3; 32])))),
                    bytes(4),
                ]
                .try_into()
                .unwrap(),
            )),
            val: bytes(0),
        },
    ];
    signers.sort_by(|a, b| a.key.cmp(&b.key));
    let signature = ScVal::Map(Some(
        vec![
            ScMapEntry {
                key: symbol("context_rule_ids"),
                val: ScVal::Vec(Some(vec![ScVal::U32(3)].try_into().unwrap())),
            },
            ScMapEntry {
                key: symbol("signers"),
                val: ScVal::Map(Some(signers.try_into().unwrap())),
            },
        ]
        .try_into()
        .unwrap(),
    ));
    SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: ScAddress::Contract(ContractId(Hash([1; 32]))),
            nonce: 7,
            signature_expiration_ledger: 100,
            signature,
        }),
        root_invocation,
    }
}

/// Builds an empty, source, or smart-account fixture by kind.
#[must_use]
///
/// # Panics
/// Panics if the fixed fixture cannot encode its authorization.
pub fn intent_fixture_kind(
    kind: u8,
) -> (crate::SignedIntentPlan, stellar_xdr::TransactionEnvelope) {
    use stellar_xdr::*;
    let (base, mut envelope) = intent_fixture_plan(1, 60);
    if kind != 0 {
        let TransactionEnvelope::Tx(tx) = &mut envelope else {
            panic!("V1");
        };
        let mut operations = tx.tx.operations.to_vec();
        let OperationBody::InvokeHostFunction(op) = &mut operations[0].body else {
            panic!("invoke");
        };
        op.auth = vec![fixture_entry(kind == 1)].try_into().unwrap();
        tx.tx.operations = operations.try_into().unwrap();
    }
    let TransactionEnvelope::Tx(tx) = &envelope else {
        panic!("V1");
    };
    let OperationBody::InvokeHostFunction(op) = &tx.tx.operations[0].body else {
        panic!("invoke");
    };
    let subjects = op
        .auth
        .iter()
        .map(|entry| crate::IntentSubject::of_entry(entry, &base.facts.envelope_source).unwrap())
        .collect::<Vec<_>>();
    let expiration = subjects
        .iter()
        .filter_map(crate::IntentSubject::expiration)
        .max();
    let plan = crate::SignedIntentPlan::new(
        Caip2::Testnet.network_passphrase(),
        &base.facts.auth_address,
        &base.facts.envelope_source,
        1,
        base.facts.host_invocation_sha256,
        subjects,
        expiration,
    )
    .unwrap()
    .with_legs(base.legs());
    (plan, envelope)
}

/// Seeds one exposed and one bound intent for read-only view assertions.
///
/// # Errors
/// Returns a durable store refusal.
///
/// # Panics
/// Panics if the fixed fixture cannot encode its authorization.
pub fn seed_two_intents(
    profile: &stellar_agent_core::profile::schema::Profile,
    store: &crate::policy_state::PersistedWindowStore,
) -> Result<(), crate::policy_state::WindowStoreError> {
    use stellar_agent_core::policy::v1::criteria::WindowLimit;
    for sequence in [1, 2] {
        let (plan, envelope) = intent_fixture_plan(sequence, 60);
        let legs = vec![
            WindowEntry::new(
                StateKey::new("intent", 1, "native", 60),
                1000,
                60,
                WindowLimit::Amount {
                    asset: "native".into(),
                    window: "1m".into(),
                    max_stroops: 120,
                },
            ),
            WindowEntry::new(
                StateKey::new("intent", 1, "rate_limit", 60),
                1000,
                1,
                WindowLimit::Count {
                    window: "1m".into(),
                    max_calls: 2,
                },
            ),
        ];
        let plan = plan.with_legs(&legs);
        let exposed = store.admit_signed_intent(profile, &plan)?.expose();
        if sequence == 2 {
            let facts =
                crate::BindFacts::from_envelope(&envelope, Caip2::Testnet.network_passphrase())
                    .unwrap();
            store.bind_signed_intent(profile, exposed.intent_id().unwrap(), &facts, &legs)?;
        }
    }
    Ok(())
}
