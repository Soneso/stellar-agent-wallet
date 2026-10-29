//! The invocation tree `submit_signed_invoke` signs is the wallet's own: its
//! host function as the root, with only the sub-invocations the caller
//! declared under it.
//!
//! The mock RPC answers the first simulation with an authorization entry for
//! the wallet whose tree a test chooses from the request, echoes the signed
//! entries on the re-simulation, and records every simulation and every sent
//! envelope. The signer counts every signing primitive.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "mock fixture construction and assertions"
)]

use serde_json::{Value, json};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;
use stellar_agent_core::smart_account::rule_id::ContextRuleId;
use stellar_agent_network::Signer;
use stellar_agent_network::signing::test_doubles::CountingSigner;
use stellar_agent_smart_account::error::SimulationDivergenceSubCode;
use stellar_agent_smart_account::{
    SaError,
    managers::authorization::{AuthorizationInfo, Combinator, SignerGroup},
    submit::{
        DeclaredSubInvocations, DeclaredTransfer, SubmitInvokeArgs, SubmitInvokeResult,
        submit_signed_invoke,
    },
};
use stellar_agent_test_support::signed_envelope::{
    account_id_for_seed, get_network_result, public_key_for_seed, send_transaction_hash_hex,
};
use stellar_xdr::{
    ContractId, Hash, HostFunction, Int128Parts, InvokeContractArgs, Limits, OperationBody,
    ReadXdr, ScAddress, ScSymbol, ScVal, SorobanAddressCredentials, SorobanAuthorizationEntry,
    SorobanAuthorizedFunction, SorobanAuthorizedInvocation, SorobanCredentials,
    TransactionEnvelope, WriteXdr,
};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate, matchers::method};

use crate::rpc_mock_helpers as rpc_helpers;

const PASSPHRASE: &str = "Test SDF Network ; September 2015";
const SEED: [u8; 32] = [0x61; 32];
/// The qualifying signer of the quorum-path submissions.
const QUORUM_SEED: [u8; 32] = [0x62; 32];

/// The smart account whose credentials sign.
fn wallet() -> ScAddress {
    contract(0x57)
}

/// A contract the wallet never calls.
fn attacker() -> ScAddress {
    contract(0xAA)
}

/// The token whose transfer a declaration names.
fn token() -> ScAddress {
    contract(0x70)
}

/// The external router a swap-shaped submission invokes.
fn router() -> ScAddress {
    contract(0x72)
}

/// The recipient a router chooses for the input token.
fn pair() -> ScAddress {
    contract(0x73)
}

fn contract(byte: u8) -> ScAddress {
    ScAddress::Contract(ContractId(Hash([byte; 32])))
}

fn strkey(address: &ScAddress) -> String {
    let ScAddress::Contract(ContractId(Hash(bytes))) = address else {
        panic!("a contract address")
    };
    stellar_strkey::Contract(*bytes).to_string().to_string()
}

fn call(target: ScAddress, function: &str, args: Vec<ScVal>) -> InvokeContractArgs {
    InvokeContractArgs {
        contract_address: target,
        function_name: ScSymbol(function.try_into().unwrap()),
        args: args.try_into().unwrap(),
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

/// `token.transfer(from, to, amount)`.
fn transfer(token: ScAddress, from: ScAddress, to: ScAddress, amount: i128) -> InvokeContractArgs {
    call(
        token,
        "transfer",
        vec![ScVal::Address(from), ScVal::Address(to), i128_val(amount)],
    )
}

fn leaf(call: InvokeContractArgs) -> SorobanAuthorizedInvocation {
    node(call, vec![])
}

fn node(
    call: InvokeContractArgs,
    sub_invocations: Vec<SorobanAuthorizedInvocation>,
) -> SorobanAuthorizedInvocation {
    SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(call),
        sub_invocations: sub_invocations.try_into().unwrap(),
    }
}

/// The wallet entrypoint the self-call tests invoke.
fn entrypoint() -> InvokeContractArgs {
    call(wallet(), "set_limit", vec![ScVal::U32(5)])
}

/// The swap-shaped external call: the router call with the wallet as `to`.
fn swap() -> InvokeContractArgs {
    call(
        router(),
        "swap_exact_tokens_for_tokens",
        vec![
            i128_val(100),
            i128_val(90),
            ScVal::Address(wallet()),
            ScVal::U64(1_700_000_000),
        ],
    )
}

/// Builds the simulated root invocation from the host function the request
/// carries.
type TreeFn = dyn Fn(&InvokeContractArgs) -> SorobanAuthorizedInvocation + Send + Sync;

struct Rpc {
    tree: Arc<TreeFn>,
    simulations: Arc<AtomicUsize>,
    sent: Arc<Mutex<Vec<String>>>,
}

impl Respond for Rpc {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        let result = match body["method"].as_str().unwrap() {
            "getNetwork" => get_network_result(PASSPHRASE),
            "getLatestLedger" => {
                json!({"id": "ab".repeat(32), "sequence": 1000, "protocolVersion": 27})
            }
            "getLedgerEntries" => {
                rpc_helpers::build_ledger_entries_account(&account_id_for_seed(SEED))
            }
            "simulateTransaction" => {
                self.simulations.fetch_add(1, Ordering::SeqCst);
                let TransactionEnvelope::Tx(tx) = TransactionEnvelope::from_xdr_base64(
                    body["params"]["transaction"].as_str().unwrap(),
                    Limits::none(),
                )
                .unwrap() else {
                    panic!("v1 envelope")
                };
                let OperationBody::InvokeHostFunction(op) = &tx.tx.operations[0].body else {
                    panic!("invoke operation")
                };
                let HostFunction::InvokeContract(invoke) = &op.host_function else {
                    panic!("contract function")
                };
                let mut result = rpc_helpers::build_simulate_response(
                    &ScVal::Void.to_xdr_base64(Limits::none()).unwrap(),
                );
                let auth = if op.auth.is_empty() {
                    vec![SorobanAuthorizationEntry {
                        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                            address: wallet(),
                            nonce: 7,
                            signature_expiration_ledger: 0,
                            signature: ScVal::Void,
                        }),
                        root_invocation: (self.tree)(invoke),
                    }]
                } else {
                    op.auth.to_vec()
                };
                result["results"][0]["auth"] = json!(
                    auth.iter()
                        .map(|entry| entry.to_xdr_base64(Limits::none()).unwrap())
                        .collect::<Vec<_>>()
                );
                result
            }
            "sendTransaction" => {
                self.sent
                    .lock()
                    .unwrap()
                    .push(body["params"]["transaction"].as_str().unwrap().to_owned());
                json!({"status": "PENDING", "hash": send_transaction_hash_hex(&body, PASSPHRASE), "latestLedger": 1000, "latestLedgerCloseTime": "1234567890"})
            }
            "getTransaction" => {
                json!({"status": "SUCCESS", "ledger": 1001, "latestLedger": 1001, "oldestLedger": 1})
            }
            other => panic!("unexpected RPC method: {other}"),
        };
        ResponseTemplate::new(200)
            .set_body_json(json!({"jsonrpc": "2.0", "id": body["id"], "result": result}))
    }
}

/// What one submission did.
struct Outcome {
    result: Result<SubmitInvokeResult, SaError>,
    signs: usize,
    simulations: usize,
    sent: Vec<String>,
}

impl Outcome {
    /// The root invocation of the wallet's entry in the one sent envelope.
    fn signed_root(&self) -> SorobanAuthorizedInvocation {
        assert_eq!(self.sent.len(), 1, "one envelope is sent");
        let TransactionEnvelope::Tx(tx) =
            TransactionEnvelope::from_xdr_base64(&self.sent[0], Limits::none()).unwrap()
        else {
            panic!("v1 envelope")
        };
        let OperationBody::InvokeHostFunction(op) = &tx.tx.operations[0].body else {
            panic!("invoke operation")
        };
        op.auth
            .iter()
            .find(|entry| {
                matches!(&entry.credentials,
                    SorobanCredentials::Address(creds) if creds.address == wallet())
            })
            .expect("the wallet's entry is in the envelope")
            .root_invocation
            .clone()
    }

    /// Asserts the submission was refused with the signed-tree divergence
    /// before any signing primitive ran and before a second simulation, and
    /// returns the refusal's reason.
    fn refused_before_signing(&self) -> String {
        assert_eq!(self.signs, 0, "nothing is signed: {:?}", self.result);
        assert_eq!(self.simulations, 1, "no re-simulation: {:?}", self.result);
        assert!(self.sent.is_empty(), "nothing is sent");
        match &self.result {
            Err(
                err @ SaError::SimulationDivergence {
                    sub_code: SimulationDivergenceSubCode::AuthContexts,
                    redacted_reason,
                },
            ) => {
                assert_eq!(err.wire_code(), "simulation.divergence.auth_contexts");
                redacted_reason.clone()
            }
            other => panic!("expected the auth-contexts divergence, got {other:?}"),
        }
    }

    /// Asserts the submission signed and reached the send.
    fn signed_and_sent(&self) {
        assert!(self.result.is_ok(), "{:?}", self.result);
        assert!(self.signs > 0, "the wallet signs");
        assert_eq!(self.sent.len(), 1, "one envelope is sent");
    }
}

/// The signing path a submission takes.
#[derive(Clone, Copy)]
enum SigningPath {
    /// The envelope signer's delegated G-key signs the wallet's entry.
    SingleSigner,
    /// A one-of-one quorum whose qualifying signer is a second key.
    Quorum,
}

/// Submits `host_function` from the wallet under rule 0 with `declared`,
/// against an RPC whose first simulation returns `tree(host_function)`.
async fn submit(
    host_function: InvokeContractArgs,
    declared: DeclaredSubInvocations<'_>,
    tree: impl Fn(&InvokeContractArgs) -> SorobanAuthorizedInvocation + Send + Sync + 'static,
) -> Outcome {
    submit_on(SigningPath::SingleSigner, host_function, declared, tree).await
}

/// [`submit`] on `path`. `Outcome::signs` counts the signing primitives of
/// every signer the submission holds.
async fn submit_on(
    path: SigningPath,
    host_function: InvokeContractArgs,
    declared: DeclaredSubInvocations<'_>,
    tree: impl Fn(&InvokeContractArgs) -> SorobanAuthorizedInvocation + Send + Sync + 'static,
) -> Outcome {
    let mock = MockServer::start().await;
    let simulations = Arc::new(AtomicUsize::new(0));
    let sent = Arc::new(Mutex::new(Vec::new()));
    Mock::given(method("POST"))
        .respond_with(Rpc {
            tree: Arc::new(tree),
            simulations: Arc::clone(&simulations),
            sent: Arc::clone(&sent),
        })
        .mount(&mock)
        .await;
    let target = strkey(&host_function.contract_address);
    let auth_address = strkey(&wallet());
    let signer = CountingSigner::new(SEED);
    let quorum_signer = CountingSigner::new(QUORUM_SEED);
    let quorum_signers: [&(dyn Signer + Send + Sync); 1] = [&quorum_signer];
    let authorization = match path {
        SigningPath::SingleSigner => None,
        SigningPath::Quorum => Some(AuthorizationInfo::new(
            vec![
                SignerGroup::new("ops".to_owned(), vec![public_key_for_seed(QUORUM_SEED)], 1)
                    .unwrap(),
            ],
            Combinator::Or,
        )),
    };
    let result = submit_signed_invoke(
        SubmitInvokeArgs::builder()
            .target_contract(&target)
            .auth_address(&auth_address)
            .auth_rule_ids(&[ContextRuleId::new(0)])
            .host_function(HostFunction::InvokeContract(host_function))
            .sub_invocations(declared)
            .signer(&signer)
            .maybe_authorization(authorization.as_ref())
            .signers(match path {
                SigningPath::SingleSigner => &[],
                SigningPath::Quorum => &quorum_signers,
            })
            .primary_rpc_url(&mock.uri())
            .network_passphrase(PASSPHRASE)
            .chain_id("stellar:testnet")
            .timeout(Duration::from_secs(5))
            .op_label("signed_tree_mock")
            .build(),
    )
    .await;
    let sent = sent.lock().unwrap().clone();
    Outcome {
        result,
        signs: signer.sign_calls() + quorum_signer.sign_calls(),
        simulations: simulations.load(Ordering::SeqCst),
        sent,
    }
}

/// The honest tree of `invoke`: the call itself with `subs` under it.
fn honest_with(
    subs: Vec<SorobanAuthorizedInvocation>,
) -> impl Fn(&InvokeContractArgs) -> SorobanAuthorizedInvocation + Send + Sync + 'static {
    move |invoke| node(invoke.clone(), subs.clone())
}

// ── Root binding ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_root_on_another_contract_is_refused_before_signing() {
    let outcome = submit(entrypoint(), DeclaredSubInvocations::None, |invoke| {
        let mut root = invoke.clone();
        root.contract_address = attacker();
        leaf(root)
    })
    .await;
    let reason = outcome.refused_before_signing();
    assert!(reason.contains("in its contract"), "{reason}");
}

#[tokio::test]
async fn a_root_with_another_function_is_refused_before_signing() {
    let outcome = submit(entrypoint(), DeclaredSubInvocations::None, |invoke| {
        let mut root = invoke.clone();
        root.function_name = ScSymbol("upgrade".try_into().unwrap());
        leaf(root)
    })
    .await;
    let reason = outcome.refused_before_signing();
    assert!(reason.contains("in its function"), "{reason}");
}

#[tokio::test]
async fn a_root_with_another_argument_is_refused_before_signing() {
    let outcome = submit(entrypoint(), DeclaredSubInvocations::None, |invoke| {
        let mut root = invoke.clone();
        root.args = vec![ScVal::U32(u32::MAX)].try_into().unwrap();
        leaf(root)
    })
    .await;
    let reason = outcome.refused_before_signing();
    assert!(reason.contains("in argument 0"), "{reason}");
    assert!(
        !reason.contains(&u32::MAX.to_string()),
        "the reason names no value: {reason}"
    );
}

#[tokio::test]
async fn an_honest_entrypoint_root_signs() {
    let outcome = submit(
        entrypoint(),
        DeclaredSubInvocations::None,
        honest_with(vec![]),
    )
    .await;
    outcome.signed_and_sent();
    assert_eq!(outcome.signed_root(), leaf(entrypoint()));
}

// ── Declared sub-invocations: none ───────────────────────────────────────────

#[tokio::test]
async fn an_undeclared_sub_invocation_is_refused_before_signing() {
    let outcome = submit(
        entrypoint(),
        DeclaredSubInvocations::None,
        honest_with(vec![leaf(transfer(token(), wallet(), attacker(), 1_000))]),
    )
    .await;
    let reason = outcome.refused_before_signing();
    assert!(reason.contains("1 undeclared sub-invocations"), "{reason}");
}

// ── Declared sub-invocations: token transfers ────────────────────────────────

const BOUND: i128 = 100;

fn bounded_to_any() -> [DeclaredTransfer; 1] {
    [DeclaredTransfer {
        token: token(),
        to: None,
        max_amount: BOUND,
    }]
}

#[tokio::test]
async fn a_declared_transfer_within_its_bound_signs() {
    let declared = bounded_to_any();
    let drawn = leaf(transfer(token(), wallet(), pair(), BOUND));
    let outcome = submit(
        swap(),
        DeclaredSubInvocations::TokenTransfers(&declared),
        honest_with(vec![drawn.clone()]),
    )
    .await;
    outcome.signed_and_sent();
    assert_eq!(outcome.signed_root(), node(swap(), vec![drawn]));
}

#[tokio::test]
async fn a_transfer_above_its_bound_is_refused() {
    let declared = bounded_to_any();
    let outcome = submit(
        swap(),
        DeclaredSubInvocations::TokenTransfers(&declared),
        honest_with(vec![leaf(transfer(token(), wallet(), pair(), BOUND + 1))]),
    )
    .await;
    let reason = outcome.refused_before_signing();
    assert!(reason.contains("exceed the declared bound"), "{reason}");
}

#[tokio::test]
async fn a_transfer_on_another_token_is_refused() {
    let declared = bounded_to_any();
    let outcome = submit(
        swap(),
        DeclaredSubInvocations::TokenTransfers(&declared),
        honest_with(vec![leaf(transfer(attacker(), wallet(), pair(), 1))]),
    )
    .await;
    let reason = outcome.refused_before_signing();
    assert!(reason.contains("on an undeclared token"), "{reason}");
}

#[tokio::test]
async fn a_transfer_from_another_address_is_refused() {
    let declared = bounded_to_any();
    let outcome = submit(
        swap(),
        DeclaredSubInvocations::TokenTransfers(&declared),
        honest_with(vec![leaf(transfer(token(), attacker(), pair(), 1))]),
    )
    .await;
    let reason = outcome.refused_before_signing();
    assert!(
        reason.contains("from an address other than the authorizing one"),
        "{reason}"
    );
}

#[tokio::test]
async fn two_transfers_above_the_bound_together_are_refused() {
    let declared = bounded_to_any();
    let half_and_one = BOUND / 2 + 1;
    let outcome = submit(
        swap(),
        DeclaredSubInvocations::TokenTransfers(&declared),
        honest_with(vec![
            leaf(transfer(token(), wallet(), pair(), half_and_one)),
            leaf(transfer(token(), wallet(), pair(), half_and_one)),
        ]),
    )
    .await;
    let reason = outcome.refused_before_signing();
    assert!(
        reason.contains("through sub-invocation 1 exceed the declared bound"),
        "{reason}"
    );
}

#[tokio::test]
async fn a_nested_node_under_a_transfer_is_refused() {
    let declared = bounded_to_any();
    let outcome = submit(
        swap(),
        DeclaredSubInvocations::TokenTransfers(&declared),
        honest_with(vec![node(
            transfer(token(), wallet(), pair(), 1),
            vec![leaf(transfer(token(), wallet(), attacker(), 1_000))],
        )]),
    )
    .await;
    let reason = outcome.refused_before_signing();
    assert!(
        reason.contains("sub-invocation 0 carries nested sub-invocations"),
        "{reason}"
    );
}

#[tokio::test]
async fn a_declared_transfer_to_another_recipient_is_refused() {
    let declared = [DeclaredTransfer {
        token: token(),
        to: Some(pair()),
        max_amount: BOUND,
    }];
    let outcome = submit(
        swap(),
        DeclaredSubInvocations::TokenTransfers(&declared),
        honest_with(vec![leaf(transfer(token(), wallet(), attacker(), 1))]),
    )
    .await;
    let reason = outcome.refused_before_signing();
    assert!(reason.contains("to an undeclared recipient"), "{reason}");
}

// ── Declared sub-invocations: calls ──────────────────────────────────────────

fn first_call() -> InvokeContractArgs {
    call(contract(0x81), "deposit", vec![ScVal::U32(1)])
}

fn second_call() -> InvokeContractArgs {
    call(contract(0x82), "stake", vec![ScVal::U32(2)])
}

#[tokio::test]
async fn declared_calls_in_order_sign() {
    let declared = [first_call(), second_call()];
    let subs = vec![leaf(first_call()), leaf(second_call())];
    let outcome = submit(
        entrypoint(),
        DeclaredSubInvocations::Calls(&declared),
        honest_with(subs.clone()),
    )
    .await;
    outcome.signed_and_sent();
    assert_eq!(outcome.signed_root(), node(entrypoint(), subs));
}

#[tokio::test]
async fn an_extra_or_reordered_call_is_refused() {
    let declared = [first_call(), second_call()];

    let reordered = submit(
        entrypoint(),
        DeclaredSubInvocations::Calls(&declared),
        honest_with(vec![leaf(second_call()), leaf(first_call())]),
    )
    .await;
    let reason = reordered.refused_before_signing();
    assert!(
        reason.contains("sub-invocation 1 is not a declared call in declared order"),
        "{reason}"
    );

    let repeated = submit(
        entrypoint(),
        DeclaredSubInvocations::Calls(&declared),
        honest_with(vec![
            leaf(first_call()),
            leaf(second_call()),
            leaf(second_call()),
        ]),
    )
    .await;
    let reason = repeated.refused_before_signing();
    assert!(
        reason.contains("sub-invocation 2 is not a declared call in declared order"),
        "{reason}"
    );

    let extra = submit(
        entrypoint(),
        DeclaredSubInvocations::Calls(&declared),
        honest_with(vec![
            leaf(first_call()),
            leaf(transfer(token(), wallet(), attacker(), 1_000)),
        ]),
    )
    .await;
    let reason = extra.refused_before_signing();
    assert!(
        reason.contains("sub-invocation 1 is not a declared call in declared order"),
        "{reason}"
    );
}

// ── A swap whose simulation substitutes the root and drains the wallet ───────

/// The hostile answer to a swap: an attacker contract with the router's
/// function and arguments as the root, and a transfer of the wallet's whole
/// balance to the attacker under it. A signature over that tree would be an
/// authorization the RPC could submit on its own.
#[tokio::test]
async fn a_swap_tree_with_a_substituted_root_and_a_drain_is_refused_before_signing() {
    let declared = bounded_to_any();
    let outcome = submit(
        swap(),
        DeclaredSubInvocations::TokenTransfers(&declared),
        |invoke| {
            let mut root = invoke.clone();
            root.contract_address = attacker();
            node(
                root,
                vec![leaf(transfer(token(), wallet(), attacker(), i128::MAX))],
            )
        },
    )
    .await;
    let reason = outcome.refused_before_signing();
    assert!(reason.contains("in its contract"), "{reason}");
}

/// The swap's honest tree with only the drain substituted is refused by the
/// declaration, so neither half of the hostile tree is signed alone.
#[tokio::test]
async fn a_swap_tree_with_the_honest_root_and_a_drain_is_refused_before_signing() {
    let declared = bounded_to_any();
    let outcome = submit(
        swap(),
        DeclaredSubInvocations::TokenTransfers(&declared),
        honest_with(vec![leaf(transfer(
            token(),
            wallet(),
            attacker(),
            i128::MAX,
        ))]),
    )
    .await;
    let reason = outcome.refused_before_signing();
    assert!(reason.contains("exceed the declared bound"), "{reason}");
}

/// The refusal's reason carries the fingerprint of the simulated tree for
/// attribution, never the amounts or addresses it holds.
#[tokio::test]
async fn the_refusal_names_the_simulated_tree_by_fingerprint_only() {
    let outcome = submit(
        entrypoint(),
        DeclaredSubInvocations::None,
        honest_with(vec![leaf(transfer(
            token(),
            wallet(),
            attacker(),
            987_654_321,
        ))]),
    )
    .await;
    let reason = outcome.refused_before_signing();
    assert!(
        reason.starts_with("signed_tree_mock: simulated tree invoke:"),
        "{reason}"
    );
    assert!(!reason.contains("987654321"), "{reason}");
    assert!(!reason.contains(&strkey(&attacker())), "{reason}");
}

// ── Quorum path ──────────────────────────────────────────────────────────────

/// The quorum collector signs the wallet's root with no sub-invocations, so a
/// subtree the declaration accepts is still refused on that path, before any
/// key signs and before a re-simulation.
#[tokio::test]
async fn the_quorum_path_refuses_an_accepted_subtree_before_signing() {
    let declared = bounded_to_any();
    let outcome = submit_on(
        SigningPath::Quorum,
        entrypoint(),
        DeclaredSubInvocations::TokenTransfers(&declared),
        honest_with(vec![leaf(transfer(token(), wallet(), pair(), BOUND))]),
    )
    .await;
    assert_eq!(outcome.signs, 0, "nothing is signed: {:?}", outcome.result);
    assert_eq!(
        outcome.simulations, 1,
        "no re-simulation: {:?}",
        outcome.result
    );
    assert!(outcome.sent.is_empty(), "nothing is sent");
    match &outcome.result {
        Err(SaError::AuthEntryConstructionFailed {
            stage,
            redacted_reason,
        }) => {
            assert_eq!(*stage, "quorum_external_contract_guard");
            assert!(
                redacted_reason.contains("the simulated tree carries sub-invocations"),
                "{redacted_reason}"
            );
        }
        other => panic!("expected the quorum guard refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn the_quorum_path_signs_an_entrypoint_with_an_empty_subtree() {
    let outcome = submit_on(
        SigningPath::Quorum,
        entrypoint(),
        DeclaredSubInvocations::None,
        honest_with(vec![]),
    )
    .await;
    outcome.signed_and_sent();
    assert_eq!(outcome.signed_root(), leaf(entrypoint()));
}

/// A submission that declares nothing accepts no sub-invocations.
#[test]
fn the_default_declaration_is_none() {
    assert_eq!(
        DeclaredSubInvocations::default(),
        DeclaredSubInvocations::None
    );
}
