#![allow(clippy::unwrap_used, clippy::panic, reason = "test assertions")]

use std::path::Path;

use stellar_agent_core::policy::v1::criteria::state_store::{PolicyStateStore, StateKey};
use stellar_agent_core::policy::{
    McpToolRegistration, NoopPolicyEngine, PolicyEngine, ToolDescriptor, ToolValueKind,
};
use stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE;
use stellar_agent_core::profile::schema::{KeyringEntryRef, Profile, generation_account};
use stellar_xdr::{
    AccountId, ContractId, HostFunction, Int128Parts, InvokeContractArgs, PublicKey, ScBytes,
    ScSymbol, ScVal, SorobanAuthorizedFunction, Uint256,
};

use super::*;
use crate::policy_state::PersistedWindowStore;
use crate::signing::LedgerWitnessCapability;

const SOURCE: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
const PRIMARY: &str = "https://primary.example/rpc";
const SECONDARY: &str = "https://secondary.example/rpc";

fn account(value: u8) -> ScAddress {
    ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
        [value; 32],
    ))))
}

fn contract(value: u8) -> ScAddress {
    ScAddress::Contract(ContractId(Hash([value; 32])))
}

fn bytes(value: u8) -> ScVal {
    ScVal::Bytes(ScBytes(vec![value; 32].try_into().unwrap()))
}

fn call(name: &str, approval: bool, expiration: bool) -> InvokeContractArgs {
    let mut args = vec![ScVal::Address(account(0)), ScVal::Address(account(2))];
    if name == "approve_for_all" {
        args.push(ScVal::Bool(approval));
        if expiration {
            args.push(ScVal::U32(100));
        }
    } else {
        args.push(ScVal::I128(Int128Parts { hi: 0, lo: 1 }));
        if matches!(name, "approve" | "increase_allowance") {
            args.push(ScVal::U32(100));
        }
    }
    InvokeContractArgs {
        contract_address: contract(3),
        function_name: ScSymbol::try_from(name).unwrap(),
        args: args.try_into().unwrap(),
    }
}

fn schedule_call() -> InvokeContractArgs {
    InvokeContractArgs {
        contract_address: contract(9),
        function_name: ScSymbol::try_from("schedule").unwrap(),
        args: vec![
            ScVal::Address(contract(3)),
            ScVal::Symbol(ScSymbol::try_from("transfer").unwrap()),
            ScVal::Vec(Some(
                call("transfer", false, false)
                    .args
                    .to_vec()
                    .try_into()
                    .unwrap(),
            )),
            bytes(0),
            bytes(4),
            ScVal::U32(10),
            ScVal::Address(account(0)),
        ]
        .try_into()
        .unwrap(),
    }
}

fn tree(
    call: InvokeContractArgs,
    children: Vec<SorobanAuthorizedInvocation>,
) -> SorobanAuthorizedInvocation {
    SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(call),
        sub_invocations: children.try_into().unwrap(),
    }
}

fn plan(
    host: &HostFunction,
    roots: Vec<SorobanAuthorizedInvocation>,
    sequence: i64,
) -> SignedIntentPlan {
    let subjects: Vec<_> = roots
        .into_iter()
        .enumerate()
        .map(|(index, root)| {
            IntentSubject::account_key(&account(0), 7 + i64::try_from(index).unwrap(), 100, &root)
                .unwrap()
        })
        .collect();
    let expiration = (!subjects.is_empty()).then_some(100);
    SignedIntentPlan::new(
        TESTNET_PASSPHRASE,
        SOURCE,
        SOURCE,
        sequence,
        intent_xdr_hash(host).unwrap(),
        subjects,
        expiration,
    )
    .unwrap()
    .with_envelope_max_ledger(100)
    .unwrap()
}

#[test]
fn purpose_veto_visits_every_validated_function() {
    let normal = call("transfer", false, false);
    let generic = HostFunction::InvokeContract(InvokeContractArgs {
        contract_address: contract(4),
        function_name: ScSymbol::try_from("execute").unwrap(),
        args: vec![
            ScVal::Address(contract(3)),
            ScVal::Symbol(ScSymbol::try_from("transfer").unwrap()),
            ScVal::Vec(Some(normal.args.to_vec().try_into().unwrap())),
        ]
        .try_into()
        .unwrap(),
    });
    let normal_host = HostFunction::InvokeContract(normal.clone());
    let positive = plan(&normal_host, vec![tree(normal.clone(), Vec::new())], 1)
        .classify_purpose(&normal_host, None)
        .unwrap();
    assert_eq!(positive.purpose(), Some(&IntentPurpose::Invoke));
    assert_eq!(
        plan(&generic, vec![tree(normal.clone(), Vec::new())], 1)
            .classify_purpose(&generic, None)
            .unwrap()
            .purpose(),
        Some(&IntentPurpose::Invoke),
    );

    for name in [
        "schedule",
        "approve",
        "increase_allowance",
        "approve_for_all",
    ] {
        for approval in [false, true] {
            for expiration in [false, true] {
                let veto = if name == "schedule" {
                    schedule_call()
                } else {
                    call(name, approval, expiration)
                };
                if name == "approve_for_all" {
                    assert_eq!(veto.args[0], ScVal::Address(account(0)));
                    assert_eq!(veto.args[1], ScVal::Address(account(2)));
                    assert_eq!(veto.args[2], ScVal::Bool(approval));
                    assert_eq!(veto.args.len(), if expiration { 4 } else { 3 });
                    if expiration {
                        assert_eq!(veto.args[3], ScVal::U32(100));
                    }
                }
                let veto_host = HostFunction::InvokeContract(veto.clone());
                for roots in [Vec::new(), vec![tree(veto.clone(), Vec::new())]] {
                    assert_eq!(
                        plan(&veto_host, roots, 1)
                            .classify_purpose(&veto_host, None)
                            .unwrap()
                            .purpose(),
                        None,
                        "host and root veto: {name}, approval={approval}, expiration={expiration}",
                    );
                }
                let veto_root = tree(veto.clone(), Vec::new());
                let cases = [
                    vec![veto_root.clone()],
                    vec![tree(normal.clone(), vec![veto_root.clone()])],
                    vec![tree(normal.clone(), Vec::new()), veto_root.clone()],
                    vec![tree(
                        normal.clone(),
                        vec![tree(normal.clone(), vec![veto_root])],
                    )],
                ];
                for (index, roots) in cases.into_iter().enumerate() {
                    assert_eq!(
                        plan(&generic, roots, 1)
                            .classify_purpose(&generic, None)
                            .unwrap()
                            .purpose(),
                        None,
                        "generic invocation case {index}: {name}, approval={approval}, expiration={expiration}",
                    );
                }
            }
        }
    }

    let schedule = schedule_call();
    let host = HostFunction::InvokeContract(schedule.clone());
    let timelock = stellar_strkey::Contract([9; 32])
        .to_string()
        .as_str()
        .to_owned();
    let expected = IntentPurpose::TimelockSchedule {
        timelock: timelock.clone(),
        operation_id: [8; 32],
    };
    assert_eq!(
        plan(&host, vec![tree(schedule.clone(), Vec::new())], 1)
            .classify_purpose(&host, Some((&timelock, [8; 32])))
            .unwrap()
            .purpose(),
        Some(&expected),
    );
    for name in ["approve", "increase_allowance", "approve_for_all"] {
        for approval in [false, true] {
            let allowance = tree(call(name, approval, true), Vec::new());
            for roots in [
                vec![tree(schedule.clone(), vec![allowance.clone()])],
                vec![tree(schedule.clone(), Vec::new()), allowance],
            ] {
                assert_eq!(
                    plan(&host, roots, 1)
                        .classify_purpose(&host, Some((&timelock, [8; 32])))
                        .unwrap()
                        .purpose(),
                    None,
                    "allowance veto overrides schedule identity: {name}, approval={approval}",
                );
            }
        }
    }
    assert_eq!(
        plan(
            &host,
            vec![tree(schedule.clone(), vec![tree(schedule, Vec::new())])],
            1
        )
        .classify_purpose(&host, Some((&timelock, [8; 32])))
        .unwrap()
        .purpose(),
        None,
        "a nested schedule does not inherit the host exception",
    );
}

fn read_key(entry: &KeyringEntryRef) -> Option<String> {
    keyring_core::Entry::new(&entry.service, &entry.account)
        .unwrap()
        .get_password()
        .ok()
}

fn snapshot(path: &Path) -> serde_json::Value {
    let bytes = std::fs::read(path).unwrap();
    serde_json::from_slice(&bytes[32..]).unwrap()
}

fn witness(arrival: u64) -> LedgerWitnessCapability {
    let now = tokio::time::Instant::now();
    LedgerWitnessCapability::for_test(
        ChainScope::from_passphrase(TESTNET_PASSPHRASE).unwrap(),
        [PRIMARY, SECONDARY],
        [101, 102],
        [now, now],
        [arrival - 1, arrival],
        now + std::time::Duration::from_secs(10),
    )
    .unwrap()
}

#[tokio::test]
#[serial_test::serial]
async fn entryless_admission_commits_progress() {
    stellar_agent_test_support::keyring_mock::install().unwrap();
    let scratch = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/tmp");
    std::fs::create_dir_all(&scratch).unwrap();
    let dir = tempfile::Builder::new()
        .prefix("entryless-intent-")
        .tempdir_in(scratch)
        .unwrap();
    let profile = Profile::builder_testnet_named(
        "intent",
        "entryless-owner",
        "account",
        "entryless-nonce",
        "account",
    )
    .build();
    let generation = KeyringEntryRef::new(
        profile.policy_window_state_key_id.service.clone(),
        generation_account(&profile.policy_window_state_key_id.account),
    );
    std::fs::write(dir.path().join("intent.toml"), format!(
        "chain_id = \"stellar:testnet\"\nrpc_url = \"{PRIMARY}\"\nsecondary_rpc_url = \"{SECONDARY}\"\n",
    )).unwrap();
    let store = PersistedWindowStore::at_path(dir.path().join("intent.window"))
        .with_profile_directory("intent", dir.path().to_owned());
    let mut tool = ToolDescriptor::from_registration(&McpToolRegistration {
        name: "stellar_smart_account_timelock_cancel",
        destructive_hint: true,
        read_only_hint: false,
        chain_id_required: true,
        value_kind: ToolValueKind::MovesValue,
    });
    tool.chain_id = "stellar:testnet".into();
    let sizing = NoopPolicyEngine
        .size_no_value(&tool, &profile, 1000)
        .unwrap();
    assert!(sizing.entries().is_empty());
    let admission = NoValueAdmission::with_store(profile.clone(), store.clone(), sizing).unwrap();
    let host = HostFunction::InvokeContract(call("transfer", false, false));
    let candidate = plan(&host, Vec::new(), 2)
        .classify_purpose(&host, None)
        .unwrap();
    let clock = crate::mainnet::clock::set_now_ms_for_test(1000);
    let proof = admission.admit(&candidate).await.unwrap();
    assert!(proof.intent_id.is_none());
    assert!(!store.path().exists());
    assert!(read_key(&profile.policy_window_state_key_id).is_none());
    assert!(read_key(&generation).is_none());

    let (fixture, _) = super::test_helpers::intent_fixture_plan(1, 60);
    let charged = plan(&host, Vec::new(), 1)
        .classify_purpose(&host, None)
        .unwrap()
        .with_legs(fixture.legs());
    let exposed = store
        .admit_signed_intent(&profile, &charged)
        .unwrap()
        .expose();
    let intent_id = exposed.intent_id().unwrap().to_owned();
    let before = std::fs::read(store.path()).unwrap();
    let before_generation = read_key(&generation);
    clock.set(2000);
    let proof = admission
        .admit(&candidate.clone().with_capability(witness(2000)))
        .await
        .unwrap();
    assert!(proof.intent_id.is_none());
    assert_ne!(std::fs::read(store.path()).unwrap(), before);
    assert_ne!(read_key(&generation), before_generation);
    let views = store.signed_intents("intent", &profile).unwrap();
    assert_eq!(views.len(), 1);
    assert_eq!(views[0].intent_id, intent_id);
    let closed = snapshot(store.path());
    assert_eq!(closed["signed_intents"].as_array().unwrap().len(), 1);
    assert_eq!(closed["signed_intents"][0]["expiry_observed_at_ms"], 2000);
    assert_eq!(closed["signed_intents"][0]["accounting_until_ms"], 62_000);

    let closed_bytes = std::fs::read(store.path()).unwrap();
    let closed_generation = read_key(&generation);
    clock.set(3000);
    let _proof = admission
        .admit(&candidate.clone().with_capability(witness(3000)))
        .await
        .unwrap();
    assert_eq!(std::fs::read(store.path()).unwrap(), closed_bytes);
    assert_eq!(read_key(&generation), closed_generation);
    let retention =
        stellar_agent_core::policy::v1::criteria::per_period_cap::MAX_SUPPORTED_WINDOW_SECS * 1000;
    clock.set(2000 + retention);
    let _proof = admission.admit(&candidate).await.unwrap();
    assert_eq!(std::fs::read(store.path()).unwrap(), closed_bytes);
    assert_eq!(read_key(&generation), closed_generation);
    clock.set(2001 + retention);
    let _proof = admission.admit(&candidate).await.unwrap();
    assert!(store.signed_intents("intent", &profile).unwrap().is_empty());
    let loaded = PolicyStateStore::new();
    store.load_into("intent", &profile, &loaded).unwrap();
    assert_eq!(
        loaded
            .query_window(&StateKey::new("intent", 1, "native", 60), 2001 + retention)
            .unwrap(),
        (0, 0)
    );
    assert_eq!(
        loaded
            .query_window(
                &StateKey::new("intent", 1, "rate_limit", 60),
                2001 + retention
            )
            .unwrap(),
        (0, 0)
    );

    let committed_key = read_key(&profile.policy_window_state_key_id);
    let committed_generation = read_key(&generation);
    assert!(committed_generation.is_some());
    std::fs::rename(store.path(), dir.path().join("committed.window")).unwrap();
    let refusal = match admission.admit(&candidate).await {
        Ok(_) => panic!("deletion of committed history admits no proof"),
        Err(error) => error,
    };
    assert_eq!(refusal.code(), "submission.intent_record_unavailable");
    assert!(matches!(
        refusal,
        WalletError::Submission(SubmissionError::IntentRecordUnavailable {
            class: "window_unavailable"
        })
    ));
    assert!(!store.path().exists());
    assert_eq!(read_key(&profile.policy_window_state_key_id), committed_key);
    assert_eq!(read_key(&generation), committed_generation);
}

#[test]
#[serial_test::serial]
fn envelope_bound_mismatch_keeps_admitted_charge() {
    use stellar_xdr::{LedgerBounds, Preconditions, PreconditionsV2, VecM};

    let set_bound = |envelope: &mut TransactionEnvelope, maximum: Option<u32>| {
        let TransactionEnvelope::Tx(tx) = envelope else {
            panic!("V1 envelope")
        };
        tx.tx.cond = Preconditions::V2(PreconditionsV2 {
            time_bounds: None,
            ledger_bounds: maximum.map(|max_ledger| LedgerBounds {
                min_ledger: 0,
                max_ledger,
            }),
            min_seq_num: None,
            min_seq_age: stellar_xdr::Duration(0),
            min_seq_ledger_gap: 0,
            extra_signers: VecM::default(),
        });
    };
    stellar_agent_test_support::keyring_mock::install().unwrap();
    let scratch = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/tmp");
    std::fs::create_dir_all(&scratch).unwrap();
    let dir = tempfile::Builder::new()
        .prefix("bound-intent-")
        .tempdir_in(scratch)
        .unwrap();
    let profile = Profile::builder_testnet_named(
        "intent",
        "bound-owner",
        "account",
        "bound-nonce",
        "account",
    )
    .build();
    let generation = KeyringEntryRef::new(
        profile.policy_window_state_key_id.service.clone(),
        generation_account(&profile.policy_window_state_key_id.account),
    );
    let store = PersistedWindowStore::at_path(dir.path().join("intent.window"));
    let (fixture, mut envelope) = super::test_helpers::intent_fixture_plan(1, 60);
    let entry = super::test_helpers::fixture_entry(false);
    let subject = IntentSubject::of_entry(&entry, SOURCE).unwrap();
    let TransactionEnvelope::Tx(tx) = &mut envelope else {
        panic!("V1 envelope")
    };
    let mut operations = tx.tx.operations.to_vec();
    let OperationBody::InvokeHostFunction(op) = &mut operations[0].body else {
        panic!("invoke")
    };
    op.auth = vec![entry].try_into().unwrap();
    let host = op.host_function.clone();
    tx.tx.operations = operations.try_into().unwrap();
    let plan = SignedIntentPlan::new(
        TESTNET_PASSPHRASE,
        SOURCE,
        SOURCE,
        1,
        intent_xdr_hash(&host).unwrap(),
        vec![subject],
        Some(100),
    )
    .unwrap()
    .classify_purpose(&host, None)
    .unwrap()
    .with_envelope_max_ledger(50)
    .unwrap()
    .with_legs(fixture.legs());
    assert_eq!(plan.facts.greatest_expiration_ledger, Some(100));
    set_bound(&mut envelope, Some(50));
    assert_eq!(plan.check_envelope(&envelope), Ok(()));
    let _clock = crate::mainnet::clock::set_now_ms_for_test(1000);
    let exposure = store.admit_signed_intent(&profile, &plan).unwrap().expose();
    let intent_id = exposure.intent_id().unwrap();
    let before = std::fs::read(store.path()).unwrap();
    let before_generation = read_key(&generation);
    for maximum in [None, Some(0), Some(49), Some(51)] {
        let mut changed = envelope.clone();
        set_bound(&mut changed, maximum);
        assert_eq!(
            plan.check_envelope(&changed),
            Err("expiration"),
            "{maximum:?}"
        );
        match BindFacts::from_envelope(&changed, TESTNET_PASSPHRASE) {
            Ok(facts) => {
                assert_eq!(facts.facts.greatest_expiration_ledger, Some(100));
                assert!(matches!(
                    store.bind_signed_intent(&profile, intent_id, &facts, exposure.plan().legs()),
                    Err(
                        crate::policy_state::WindowStoreError::IntentBindingMismatch {
                            field: "expiration"
                        }
                    )
                ));
            }
            Err(field) => {
                assert_eq!(maximum, Some(0));
                assert_eq!(field, "expiration");
            }
        }
        assert_eq!(std::fs::read(store.path()).unwrap(), before);
        assert_eq!(read_key(&generation), before_generation);
        let loaded = PolicyStateStore::new();
        store.load_into("intent", &profile, &loaded).unwrap();
        assert_eq!(
            loaded
                .query_window(&StateKey::new("intent", 1, "native", 60), 1000)
                .unwrap(),
            (60, 1)
        );
        assert_eq!(
            loaded
                .query_window(&StateKey::new("intent", 1, "rate_limit", 60), 1000)
                .unwrap(),
            (1, 1)
        );
    }
    let facts = BindFacts::from_envelope(&envelope, TESTNET_PASSPHRASE).unwrap();
    store
        .bind_signed_intent(&profile, intent_id, &facts, exposure.plan().legs())
        .unwrap();
    assert_ne!(std::fs::read(store.path()).unwrap(), before);
}
