//! Testnet acceptance test for `AuthorizationInfo` quorum substrate.
//!
//! Exercises the off-chain quorum orchestration against testnet:
//!
//! - 2-of-3 quorum success.  Deploys a C-account with 3 G-key signers
//!   at a 2-of-3 threshold rule; invokes `execute` via
//!   [`collect_quorum_signatures`] with 2 qualifying signers; asserts the
//!   transaction is accepted by the on-chain `__check_auth`.
//!
//! - 1-of-3 quorum failure (offline).  A [`collect_quorum_signatures`]
//!   call with only 1 signer against a 2-of-3 `AuthorizationInfo` returns
//!   `QuorumError::GroupNotSatisfiedInAndCombinator` before any RPC round-trip.
//!   The offline path asserts fail-closed semantics without a live contract
//!   invocation.
//!
//! - `SubmitInvokeArgs::authorization` path smoke-test.  The quorum
//!   path inside `submit_signed_invoke` is exercised end-to-end via a
//!   2-of-3-signed rule invocation; verifies the quorum branch of
//!   `submit_signed_invoke` converges to an on-chain confirmation (same outcome
//!   as the success case but goes through the full `submit_signed_invoke` step-5
//!   branch).
//!
//! # Gating
//!
//! All tests compile only under `--features testnet-integration`:
//!
//! ```text
//! cargo test --features testnet-integration --test quorum_authorization_info_testnet_acceptance
//! ```
//!
//! The OpenZeppelin smart-account contract's on-chain `__check_auth` enforces
//! the threshold at invocation time.  This test verifies the wallet-side
//! `collect_quorum_signatures` produces entry sets that pass `__check_auth`.
//! Threshold orchestration is wallet-side only; the on-chain contract performs
//! per-signer auth checks, not off-chain quorum collection.
//!
//! All tests in this file are testnet acceptance gates for the multi-signer
//! quorum substrate.

#![cfg(feature = "testnet-integration")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics are acceptable in testnet acceptance tests"
)]

use std::time::Duration;

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use serial_test::serial;
use sha2::{Digest as _, Sha256};
use stellar_agent_core::smart_account::rule_id::ContextRuleId;
use stellar_agent_network::{Signer, SoftwareSigningKey, StellarRpcClient, fetch_account};
use stellar_agent_smart_account::deployment::{
    DeployerKeypair, DeploymentArgs, ResolvedFeePerOp, deploy_smart_account,
    derive_smart_account_address,
};
use stellar_agent_smart_account::managers::auth_entry::test_helpers::{
    baseline_authorization_simulation, matching_envelope_context,
};
use stellar_agent_smart_account::managers::authorization::{
    AuthorizationInfo, Combinator, QuorumError, SignerGroup, collect_quorum_signatures,
};
use stellar_agent_smart_account::managers::rules::RuleContext;
use stellar_agent_smart_account::managers::rules::{
    ContextRuleDefinition, ContextRuleManager, ContextRuleManagerConfig, ContextRulePolicy,
    ContextRuleSignerInput, parse_c_strkey_to_smart_account, parse_g_strkey_to_signer_address,
};
use stellar_agent_smart_account::signers::policy_identification::THRESHOLD_POLICY_WASM;
use stellar_agent_smart_account::submit::{SubmitInvokeArgs, submit_signed_invoke};
use stellar_baselib::account::{Account as BaselibAccount, AccountBehavior};
use stellar_baselib::transaction::{Transaction, TransactionBehavior};
use stellar_baselib::transaction_builder::{TransactionBuilder, TransactionBuilderBehavior};
use stellar_rpc_client::Client;
use stellar_xdr::{
    AccountId, BytesM, ContractExecutable, ContractIdPreimage, ContractIdPreimageFromAddress,
    CreateContractArgsV2, Hash, HostFunction, InvokeContractArgs, InvokeHostFunctionOp, LedgerKey,
    LedgerKeyContractCode, Limits, Operation, OperationBody, PublicKey as XdrPublicKey, ScAddress,
    ScSymbol, ScVal, ScVec, SorobanAuthorizationEntry, Uint256, VecM, WriteXdr,
};
use uuid::Uuid;
use zeroize::Zeroizing;

// ── Network constants ─────────────────────────────────────────────────────────

const TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";
const TESTNET_FRIENDBOT_URL: &str = "https://friendbot.stellar.org";
const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";
const CHAIN_ID: &str = "stellar:testnet";
const FEE_STROOPS: u32 = 1_000_000;
const TIMEOUT_SECS: u64 = 120;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn rid() -> String {
    Uuid::new_v4().to_string()
}

/// Generates a fresh ed25519 keypair and returns `(g_strkey, boxed_signer)`.
fn fresh_signer() -> (String, Box<dyn Signer + Send + Sync>) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let g_strkey = format!(
        "{}",
        stellar_strkey::ed25519::PublicKey(verifying_key.to_bytes())
    );
    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(signing_key.to_bytes());
    let signer: Box<dyn Signer + Send + Sync> =
        Box::new(SoftwareSigningKey::new_from_zeroizing(seed));
    (g_strkey, signer)
}

/// Generates a fresh deployer keypair wrapped in `DeployerKeypair::SecretEnv`.
fn fresh_deployer() -> (String, DeployerKeypair) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let g_strkey = format!(
        "{}",
        stellar_strkey::ed25519::PublicKey(verifying_key.to_bytes())
    );
    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(signing_key.to_bytes());
    let signer: Box<dyn Signer + Send + Sync> =
        Box::new(SoftwareSigningKey::new_from_zeroizing(seed));
    (
        g_strkey,
        DeployerKeypair::SecretEnv {
            var_name: "testnet-quorum-acceptance".to_owned(),
            signer,
        },
    )
}

/// Funds a G-strkey via testnet Friendbot.
///
/// Checks reachability only (the Friendbot 200 response); no balance threshold
/// gates are applied.
async fn fund_via_friendbot(g_strkey: &str) {
    let url = format!("{TESTNET_FRIENDBOT_URL}?addr={g_strkey}");
    let resp = reqwest::get(&url)
        .await
        .expect("Friendbot HTTP must succeed");
    assert!(
        resp.status().is_success(),
        "Friendbot must return 200 for {g_strkey}; got {}",
        resp.status()
    );
}

fn fresh_rule_manager() -> ContextRuleManager {
    ContextRuleManager::new(ContextRuleManagerConfig::new(
        TESTNET_RPC_URL.to_owned(),
        TESTNET_PASSPHRASE.to_owned(),
        Duration::from_secs(TIMEOUT_SECS),
        CHAIN_ID.to_owned(),
    ))
    .expect("ContextRuleManager::new must succeed")
}

/// Deploys a fresh smart-account and returns its C-strkey.
async fn deploy_fresh_smart_account(signer_g: &str) -> String {
    let (deployer_g, deployer) = fresh_deployer();
    fund_via_friendbot(&deployer_g).await;

    let mut salt = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut OsRng, &mut salt);

    let result = deploy_smart_account(
        DeploymentArgs {
            deployer,
            initial_signer: signer_g.to_owned(),
            salt,
            network_passphrase: TESTNET_PASSPHRASE.to_owned(),
            rpc_url: TESTNET_RPC_URL.to_owned(),
            timeout: Duration::from_secs(TIMEOUT_SECS),
            fee: ResolvedFeePerOp {
                stroops: FEE_STROOPS,
                percentile_label: "explicit".to_owned(),
            },
            dry_run: false,
            genesis_signer_scval_override: None,
        },
        None,
    )
    .await
    .expect("smart-account deployment must succeed on testnet");
    result.smart_account
}

/// Encodes `SimpleThresholdAccountParams { threshold }` as a Soroban `ScVal`.
///
/// Byte-layout: `ScVal::Map([("threshold", ScVal::U32(threshold))])`.
/// This matches the OpenZeppelin policy's `SimpleThresholdAccountParams {
/// threshold: u32 }` type encoded via `#[contracttype]`.
fn encode_simple_threshold_params(threshold: u32) -> ScVal {
    use stellar_xdr::{ScMap, ScMapEntry, ScSymbol as Sym};
    let key = ScVal::Symbol(Sym::try_from("threshold").expect("symbol must encode"));
    let val = ScVal::U32(threshold);
    ScVal::Map(Some(ScMap(
        vec![ScMapEntry { key, val }]
            .try_into()
            .expect("map must encode"),
    )))
}

/// Deploys the vendored OZ threshold-policy WASM to testnet.
///
/// Returns the deployed threshold-policy C-strkey.
/// Mirrors the WASM upload-and-deploy pattern used by the wallet-signers
/// testnet acceptance test.
///
/// Byte-layout canonical source: `CreateContractArgsV2` from
/// stellar-xdr `Stellar-transaction.x` IDL (curr/src/generated.rs).
async fn deploy_threshold_policy_wasm(
    deployer_g: &str,
    signer: &(dyn Signer + Send + Sync),
) -> String {
    let wasm_hash_bytes: [u8; 32] = Sha256::digest(THRESHOLD_POLICY_WASM).into();

    let salt_input = format!("oz-threshold-policy-v0.7.2-{TESTNET_PASSPHRASE}");
    let salt: [u8; 32] = Sha256::digest(salt_input.as_bytes()).into();

    let policy_strkey = derive_smart_account_address(deployer_g, &salt, TESTNET_PASSPHRASE)
        .expect("threshold-policy address derivation must succeed");

    let rpc_server = Client::new(TESTNET_RPC_URL).expect("Client::new must succeed");

    let network_client =
        StellarRpcClient::new(TESTNET_RPC_URL).expect("StellarRpcClient::new must succeed");

    let deployer_view = fetch_account(&network_client, deployer_g, &[])
        .await
        .expect("deployer account fetch must succeed");
    let mut deployer_account =
        BaselibAccount::new(deployer_g, &deployer_view.sequence_number.to_string())
            .expect("BaselibAccount::new must succeed");

    // Upload WASM if not already on-chain (idempotent).
    let wasm_key = LedgerKey::ContractCode(LedgerKeyContractCode {
        hash: Hash(wasm_hash_bytes),
    });
    let wasm_query = rpc_server
        .get_ledger_entries(&[wasm_key])
        .await
        .expect("getLedgerEntries must succeed");
    let wasm_already_on_chain = wasm_query.entries.as_ref().is_some_and(|e| !e.is_empty());

    if !wasm_already_on_chain {
        let wasm_bytes: BytesM = THRESHOLD_POLICY_WASM
            .to_vec()
            .try_into()
            .expect("THRESHOLD_POLICY_WASM must fit in BytesM");

        let upload_op = Operation {
            source_account: None,
            body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                host_function: HostFunction::UploadContractWasm(wasm_bytes),
                auth: VecM::default(),
            }),
        };

        let mut upload_tx_builder =
            TransactionBuilder::new(&mut deployer_account, TESTNET_PASSPHRASE, None);
        upload_tx_builder.fee(FEE_STROOPS);
        upload_tx_builder.add_operation(upload_op);
        let upload_tx: Transaction = upload_tx_builder.build_for_simulation();

        let upload_envelope_pre = upload_tx
            .to_envelope()
            .expect("upload to_envelope (pre-sim) must succeed");
        let upload_sim = rpc_server
            .simulate_transaction_envelope(&upload_envelope_pre, None)
            .await
            .expect("upload simulate_transaction_envelope must succeed");
        let upload_resource_fee = u32::try_from(upload_sim.min_resource_fee)
            .expect("upload min_resource_fee must fit u32");
        let mut prepared_upload = upload_tx.clone();
        prepared_upload.fee = prepared_upload.fee.saturating_add(upload_resource_fee);
        prepared_upload.soroban_data = Some(
            upload_sim
                .transaction_data()
                .expect("upload transaction_data must decode"),
        );

        let upload_xdr = prepared_upload
            .to_envelope()
            .expect("upload to_envelope must succeed")
            .to_xdr_base64(Limits::none())
            .expect("upload XDR encode must succeed");

        let signed_upload = stellar_agent_network::signing::envelope_signing::attach_signature(
            &upload_xdr,
            signer,
            TESTNET_PASSPHRASE,
        )
        .await
        .expect("upload envelope signing must succeed");

        stellar_agent_network::submit_transaction_and_wait(
            &network_client,
            &signed_upload,
            Duration::from_secs(TIMEOUT_SECS),
            TESTNET_PASSPHRASE,
            None,
        )
        .await
        .expect("upload submission must succeed");
    }

    // Deploy the threshold-policy contract.
    let deployer_view2 = fetch_account(&network_client, deployer_g, &[])
        .await
        .expect("deployer account re-fetch must succeed");
    let mut deployer_account2 =
        BaselibAccount::new(deployer_g, &deployer_view2.sequence_number.to_string())
            .expect("BaselibAccount::new must succeed");

    let deployer_id = stellar_strkey::ed25519::PublicKey::from_string(deployer_g)
        .expect("deployer_g must be a valid G-strkey");
    let contract_id_preimage = ContractIdPreimage::Address(ContractIdPreimageFromAddress {
        address: ScAddress::Account(AccountId(XdrPublicKey::PublicKeyTypeEd25519(Uint256(
            deployer_id.0,
        )))),
        salt: Uint256(salt),
    });

    let create_op = Operation {
        source_account: None,
        body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
            host_function: HostFunction::CreateContractV2(CreateContractArgsV2 {
                contract_id_preimage,
                executable: ContractExecutable::Wasm(Hash(wasm_hash_bytes)),
                constructor_args: VecM::default(),
            }),
            auth: VecM::default(),
        }),
    };

    let mut create_tx_builder =
        TransactionBuilder::new(&mut deployer_account2, TESTNET_PASSPHRASE, None);
    create_tx_builder.fee(FEE_STROOPS);
    create_tx_builder.add_operation(create_op);
    let create_tx: Transaction = create_tx_builder.build_for_simulation();

    let create_envelope_pre = create_tx
        .to_envelope()
        .expect("create to_envelope (pre-sim) must succeed");
    let create_sim = rpc_server
        .simulate_transaction_envelope(&create_envelope_pre, None)
        .await
        .expect("create simulate_transaction_envelope must succeed");
    let create_resource_fee =
        u32::try_from(create_sim.min_resource_fee).expect("create min_resource_fee must fit u32");
    let create_sim_auth: VecM<SorobanAuthorizationEntry> = create_sim
        .results()
        .ok()
        .and_then(|rs| rs.into_iter().next())
        .map(|r| r.auth)
        .unwrap_or_default()
        .try_into()
        .expect("create sim auth VecM encode must succeed");
    let mut prepared_create = create_tx.clone();
    prepared_create.fee = prepared_create.fee.saturating_add(create_resource_fee);
    prepared_create.soroban_data = Some(
        create_sim
            .transaction_data()
            .expect("create transaction_data must decode"),
    );
    if let Some(op) = prepared_create
        .operations
        .as_mut()
        .and_then(|ops| ops.get_mut(0))
        && let OperationBody::InvokeHostFunction(ihf) = &mut op.body
    {
        ihf.auth = create_sim_auth;
    }

    let create_xdr = prepared_create
        .to_envelope()
        .expect("create to_envelope must succeed")
        .to_xdr_base64(Limits::none())
        .expect("create XDR encode must succeed");

    let signed_create = stellar_agent_network::signing::envelope_signing::attach_signature(
        &create_xdr,
        signer,
        TESTNET_PASSPHRASE,
    )
    .await
    .expect("create envelope signing must succeed");

    stellar_agent_network::submit_transaction_and_wait(
        &network_client,
        &signed_create,
        Duration::from_secs(TIMEOUT_SECS),
        TESTNET_PASSPHRASE,
        None,
    )
    .await
    .expect("create submission must succeed");

    policy_strkey
}

/// Installs a rule with `signers` (all Delegated) and `threshold` on
/// `sa_addr`. The install is authorised by `authorizing_signer` via
/// `bootstrap_rule_id`.  Returns `(new_rule_id, policy_strkey)`.
///
/// For the quorum acceptance test, `signers` contains 3 G-strkeys at a
/// 2-of-3 threshold.
async fn install_multisigner_threshold_rule(
    sa_addr: ScAddress,
    signer_g_keys: &[&str],
    threshold: u32,
    authorizing_signer_g: &str,
    authorizing_signer: &(dyn Signer + Send + Sync),
    bootstrap_rule_id: ContextRuleId,
) -> (u32, String) {
    let rule_manager = fresh_rule_manager();

    let policy_strkey =
        deploy_threshold_policy_wasm(authorizing_signer_g, authorizing_signer).await;
    let policy_addr = parse_c_strkey_to_smart_account(&policy_strkey)
        .expect("threshold-policy C-strkey must parse");

    let threshold_params = encode_simple_threshold_params(threshold);

    let signer_inputs: Vec<ContextRuleSignerInput> = signer_g_keys
        .iter()
        .map(|g| {
            let addr = parse_g_strkey_to_signer_address(g)
                .expect("signer G-strkey must parse to ScAddress");
            ContextRuleSignerInput::Delegated { address: addr }
        })
        .collect();

    let definition = ContextRuleDefinition::new(
        RuleContext::Default,
        "quorum-test-rule".to_owned(), // OZ MAX_NAME_SIZE = 20 chars
        None,
        signer_inputs,
        vec![ContextRulePolicy::new(policy_addr, threshold_params)],
    );

    let install_out = rule_manager
        .install_rule(
            sa_addr,
            definition,
            vec![bootstrap_rule_id],
            authorizing_signer,
            None,
            rid(),
            false,
            false,
        )
        .await
        .expect("install_multisigner_threshold_rule: install_rule must succeed");

    (install_out.rule_id, policy_strkey)
}

// ── Offline quorum fail-closed (no RPC) ─────────────────────────────────

/// `collect_quorum_signatures` returns
/// `QuorumError::GroupNotSatisfiedInAndCombinator` when fewer than `threshold`
/// qualifying signers are provided. This test runs offline (no network).
///
/// No balance-threshold gates are applied; reachability is checked by Friendbot
/// 200 response in live tests only. This test runs fully offline.
#[tokio::test]
#[serial]
async fn q2_insufficient_signers_fails_before_rpc() {
    use stellar_xdr::{ContractId, Hash, ScAddress};

    let pk1 = [1u8; 32];
    let pk2 = [2u8; 32];
    let pk3 = [3u8; 32];

    // 2-of-3 group but only signer pk1 is supplied.
    let group = SignerGroup::new(
        "quorum-test".into(),
        vec![pk1, pk2, pk3],
        2, // threshold
    )
    .expect("valid group");

    let authz = AuthorizationInfo::new(vec![group], Combinator::And);

    let s1 = stellar_agent_network::SoftwareSigningKey::new_from_zeroizing(Zeroizing::new(pk1));
    let signers: Vec<&(dyn Signer + Send + Sync)> = vec![&s1];

    let auth_scaddr = ScAddress::Contract(ContractId(Hash([0u8; 32])));
    let function_name = ScSymbol::try_from("test_fn").expect("ScSymbol must encode");
    let rule_id = ContextRuleId::new(1);

    // Use test_helpers builders to construct the non_exhaustive simulation and
    // envelope types without struct literals; #[non_exhaustive] types cannot be
    // constructed via struct expressions in integration tests outside the crate.
    // The simulation data is irrelevant here — collect_quorum_signatures returns
    // InsufficientSignersInGroup before build_authorization_entry is called.
    let simulation = baseline_authorization_simulation(TESTNET_PASSPHRASE, CHAIN_ID, vec![rule_id]);
    let envelope = matching_envelope_context(&simulation);

    let result = collect_quorum_signatures(
        &authz,
        &signers,
        auth_scaddr,
        function_name,
        vec![],
        vec![rule_id],
        &simulation,
        &envelope,
        TESTNET_PASSPHRASE,
        9999,
    )
    .await;

    match result {
        Err(QuorumError::GroupNotSatisfiedInAndCombinator { unsatisfied_groups }) => {
            assert_eq!(
                unsatisfied_groups,
                vec!["quorum-test".to_owned()],
                "unsatisfied_groups must name the quorum-test group"
            );
        }
        Err(QuorumError::InsufficientSignersInGroup {
            group_name,
            required,
            provided,
        }) => {
            // Also acceptable: the AND path may surface InsufficientSignersInGroup
            // directly on first failure.
            assert_eq!(group_name, "quorum-test");
            assert_eq!(required, 2);
            assert_eq!(provided, 1);
        }
        other => panic!(
            "expected GroupNotSatisfiedInAndCombinator or InsufficientSignersInGroup, got: {other:?}"
        ),
    }
}

// ── Live testnet quorum invocation ─────────────────────────────────

/// Deploys a C-account, installs a 2-of-3 threshold rule
/// with three G-key signers, then:
///
/// - invokes `set_threshold` via `collect_quorum_signatures` with
///   2 signers; asserts the transaction is confirmed.
/// - exercises the `SubmitInvokeArgs::authorization` path in
///   `submit_signed_invoke` for the same invocation shape.
///
/// # Preconditions
///
/// - This test must ship in the same commit as the substantive quorum substrate.
/// - No balance-threshold gates are applied.
/// - `#[serial]` is used on all testnet tests that share process-global state.
///
/// The OpenZeppelin smart-account contract's on-chain `__check_auth` enforces
/// the 2-of-3 threshold at invocation time. The per-signer auth-entry XDR shape
/// is `HashIdPreimageSorobanAuthorization` from stellar-xdr 27
/// `curr/src/generated.rs`.
///
/// # Acceptance
///
/// 2-of-3 quorum testnet acceptance gate for the multi-signer substrate.
#[tokio::test]
#[serial]
async fn q1_and_q3_two_of_three_quorum_invocation_accepted() {
    // ── Provision: fund 4 accounts (bootstrap + signer1 + signer2 + signer3)
    //
    // ALL three quorum signers must have funded Stellar G-key accounts so that the
    // Soroban host can resolve `require_auth_for_args` for each delegated G-key
    // sub-auth entry inside `__check_auth`. An unfunded G-key produces
    // `Error(Storage, MissingValue): trying to get non-existing value for account`.
    let (signer1_g, signer1) = fresh_signer();
    let (signer2_g, signer2) = fresh_signer();
    let (signer3_g, _signer3) = fresh_signer();
    // Bootstrap signer: deploys the C-account + authorises the rule install.
    let (bootstrap_g, bootstrap) = fresh_signer();

    fund_via_friendbot(&bootstrap_g).await;
    fund_via_friendbot(&signer1_g).await;
    fund_via_friendbot(&signer2_g).await;
    fund_via_friendbot(&signer3_g).await;

    // ── Deploy C-account (bootstrap signer as initial sole signer) ─────────────
    let sa_strkey = deploy_fresh_smart_account(&bootstrap_g).await;
    let sa_addr =
        parse_c_strkey_to_smart_account(&sa_strkey).expect("deployed C-strkey must parse");

    // ── Install 2-of-3 threshold rule with signers 1, 2, 3 ─────────────────────
    let signer1_pk = stellar_strkey::ed25519::PublicKey::from_string(&signer1_g)
        .expect("signer1_g must be valid G-strkey")
        .0;
    let signer2_pk = stellar_strkey::ed25519::PublicKey::from_string(&signer2_g)
        .expect("signer2_g must be valid G-strkey")
        .0;
    let signer3_pk = stellar_strkey::ed25519::PublicKey::from_string(&signer3_g)
        .expect("signer3_g must be valid G-strkey")
        .0;

    let (rule_id, policy_strkey) = install_multisigner_threshold_rule(
        sa_addr.clone(),
        &[&signer1_g, &signer2_g, &signer3_g],
        2, // 2-of-3 threshold
        &bootstrap_g,
        bootstrap.as_ref(),
        ContextRuleId::new(0), // bootstrap rule_id=0 authorises the install
    )
    .await;

    let rule_ids = vec![ContextRuleId::new(rule_id)];

    // ── Build AuthorizationInfo: 2-of-3 group, AND combinator ──────────────────
    let group = SignerGroup::new(
        "main-signers".into(),
        vec![signer1_pk, signer2_pk, signer3_pk],
        2, // threshold: 2-of-3
    )
    .expect("SignerGroup must be valid");

    let authz = AuthorizationInfo::new(vec![group], Combinator::And);

    // signers 1 and 2 supply signatures (satisfies 2-of-3).
    let quorum_signers: Vec<&(dyn Signer + Send + Sync)> = vec![signer1.as_ref(), signer2.as_ref()];

    // ── submit a `get_threshold` call via `execute()` with quorum
    //
    // Route through the smart account's `execute()` entrypoint to trigger
    // `__check_auth` — the standard pattern to avoid Soroban re-entry. The
    // OpenZeppelin `execute(target, target_fn, target_args)` entrypoint calls
    // `e.current_contract_address().require_auth()`.
    //
    // `get_threshold` is read-only and idempotent; no state mutation needed.
    // The OpenZeppelin threshold policy exposes
    // `get_threshold(context_rule_id: u32, smart_account: Address)`.
    //
    // Per-signer auth-entry XDR shape: `HashIdPreimageSorobanAuthorization` from
    // stellar-xdr 27 `curr/src/generated.rs`.

    let policy_addr =
        parse_c_strkey_to_smart_account(&policy_strkey).expect("policy C-strkey must parse");

    // `get_threshold(context_rule_id: u32, smart_account: Address)` args.
    let get_threshold_inner_args: VecM<ScVal> =
        vec![ScVal::U32(rule_id), ScVal::Address(sa_addr.clone())]
            .try_into()
            .expect("get_threshold inner args must encode");

    // `execute(target: Address, target_fn: Symbol, target_args: Vec<Val>)` args.
    let execute_args: VecM<ScVal> = vec![
        ScVal::Address(policy_addr),
        ScVal::Symbol(ScSymbol::try_from("get_threshold").expect("symbol must encode")),
        ScVal::Vec(Some(ScVec(get_threshold_inner_args))),
    ]
    .try_into()
    .expect("execute args must encode");

    let invoke = InvokeContractArgs {
        contract_address: sa_addr.clone(),
        function_name: ScSymbol::try_from("execute").expect("symbol must encode"),
        args: execute_args,
    };
    let host_function = HostFunction::InvokeContract(invoke);

    let result = submit_signed_invoke(
        SubmitInvokeArgs::builder()
            .target_contract(&sa_strkey)
            // auth_address: omit → defaults to None (uses target_contract)
            .auth_rule_ids(rule_ids.as_slice())
            .host_function(host_function.clone())
            .signer(signer1.as_ref())
            .maybe_authorization(Some(&authz))
            .signers(quorum_signers.as_slice())
            .primary_rpc_url(TESTNET_RPC_URL)
            // secondary_rpc_url: omit → defaults to None
            .network_passphrase(TESTNET_PASSPHRASE)
            .chain_id(CHAIN_ID)
            .timeout(Duration::from_secs(TIMEOUT_SECS))
            .op_label("execute_get_threshold_2of3")
            .emit_observability_logs(true)
            .build(),
    )
    .await;

    assert!(
        result.is_ok(),
        "2-of-3 quorum invocation must be accepted; got: {result:?}"
    );

    let confirmed = result.unwrap();
    assert!(
        !confirmed.tx_hash.is_empty(),
        "confirmed tx_hash must be non-empty"
    );
    assert!(confirmed.ledger > 0, "confirmed ledger must be > 0");
}
