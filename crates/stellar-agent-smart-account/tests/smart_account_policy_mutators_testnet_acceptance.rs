//! Testnet acceptance tests for `add_policy` / `remove_policy`.
//!
//! # Coverage
//!
//! | Fixture | Description |
//! |---------|-------------|
//! | [`h3_add_policy_increments_count_and_emits_audit_row`] | Deploy SA + policyless rule, attach the simple-threshold policy with `manager.add_policy`, assert `policy_count == 1`, the `SaThresholdChangedV2` row before the `SaPolicyAdded` row, then a refused second simple-threshold attach |
//! | [`h4_remove_policy_decrements_count_and_emits_audit_row`] | Deploy SA + policyless rule, attach the simple-threshold policy, call `manager.remove_policy`, assert `policy_count == 0`, the `SaThresholdChangedV2` row before the `SaPolicyRemoved` row |
//! | [`h5_add_policy_type_mismatched_install_param_no_success_audit`] | Deploy SA + rule, call `manager.add_policy` for a simple-threshold policy with a `ScVal::Bool(true)` install-param (base64-decodable but type-mismatches `SimpleThresholdAccountParams`), assert the `sa.simple_threshold_install_refused` refusal before submission, no `SaPolicyAdded` row, exactly one `SaRawInvocation(PreSubmissionRefused)` row |
//!
//! Every rule is installed through a rule manager and a signers manager over
//! one audit log, as production wires them: the install records the rule's
//! signer-set baseline, which the simple-threshold attach and detach compare
//! with the chain before submission.
//!
//! # Gating
//!
//! Feature flags: `testnet-integration` + `deploy-cli`. Run with:
//!
//! ```text
//! cargo build --release -p stellar-agent-cli
//! cargo test --features "testnet-integration,deploy-cli" --test smart_account_policy_mutators_testnet_acceptance
//! ```
//!
//! `deploy-cli` is required to access `THRESHOLD_POLICY_WASM` (used by the
//! test setup to deploy the threshold-policy contract on testnet).
//!
//! Tests require live testnet access and Friendbot funding. They are excluded
//! from default `cargo test` runs.
//!
//! # Reference cross-check
//!
//! - OpenZeppelin smart-account contract:
//!   `fn add_policy(e, context_rule_id: u32, policy: Address, install_param: Val) -> u32`.
//! - OpenZeppelin smart-account contract:
//!   `fn remove_policy(e, context_rule_id: u32, policy_id: u32)`.
//! - OpenZeppelin smart-account contract: `ContextRuleEntry.policy_ids: Vec<u32>`.

#![cfg(feature = "testnet-integration")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::use_debug,
    clippy::print_stderr,
    reason = "test-only; panics and diagnostic output are acceptable in testnet acceptance tests"
)]

use std::io::{BufRead as _, BufReader};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use sha2::{Digest as _, Sha256};
use stellar_agent_core::audit_log::entry::AuditEntry;
use stellar_agent_core::audit_log::schema::EventKind;
use stellar_agent_core::audit_log::signer_set::ThresholdObservation;
use stellar_agent_core::smart_account::rule_id::ContextRuleId;
use stellar_agent_network::signing::envelope_signing::attach_signature;
use stellar_agent_network::{
    Signer, SoftwareSigningKey, StellarRpcClient, fetch_account, submit_transaction_and_wait,
};
use stellar_agent_smart_account::SaError;
use stellar_agent_smart_account::deployment::{
    DeployerKeypair, DeploymentArgs, ResolvedFeePerOp, deploy_smart_account,
    derive_smart_account_address,
};
use stellar_agent_smart_account::managers::rules::RuleContext;
use stellar_agent_smart_account::managers::rules::{
    ContextRuleDefinition, ContextRuleManager, ContextRulePolicy, ContextRuleSignerInput,
    decode_policy_count_from_scval, parse_c_strkey_to_smart_account,
    parse_g_strkey_to_signer_address,
};
use stellar_agent_smart_account::managers::signers::{PreviousBaseline, SignersManager};
use stellar_agent_smart_account::signers::policy_identification::THRESHOLD_POLICY_WASM;
use stellar_agent_smart_account::test_helpers::managers_for_tests;
use stellar_baselib::account::{Account as BaselibAccount, AccountBehavior};
use stellar_baselib::transaction::{Transaction, TransactionBehavior};
use stellar_baselib::transaction_builder::{TransactionBuilder, TransactionBuilderBehavior};
use stellar_rpc_client::Client;
use stellar_xdr::{
    AccountId, BytesM, ContractExecutable, ContractId, ContractIdPreimage,
    ContractIdPreimageFromAddress, CreateContractArgsV2, Hash, HostFunction, InvokeHostFunctionOp,
    LedgerKey, LedgerKeyContractCode, Limits, Operation, OperationBody, PublicKey as XdrPublicKey,
    ScAddress, ScMap, ScMapEntry, ScSymbol, ScVal, SorobanAuthorizationEntry, Uint256, VecM,
    WriteXdr,
};
use tempfile::TempDir;
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
            var_name: "testnet-policy-mutators-acceptance".to_owned(),
            signer,
        },
    )
}

async fn fund_via_friendbot(g_strkey: &str) {
    let url = format!("{TESTNET_FRIENDBOT_URL}?addr={g_strkey}");
    let resp = stellar_agent_test_support::testnet_helpers::friendbot_funding_request(&url)
        .await
        .expect("Friendbot HTTP must succeed");
    assert!(
        resp.status().is_success(),
        "Friendbot must return 200 for {g_strkey}; got {}",
        resp.status()
    );
}

fn read_audit_entries(log_path: &std::path::Path) -> Vec<AuditEntry> {
    let file = std::fs::File::open(log_path).expect("audit log file must be readable");
    let reader = BufReader::new(file);
    let mut entries = Vec::new();
    for line in reader.lines() {
        let Ok(line) = line else { continue };
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(entry) = serde_json::from_str::<AuditEntry>(&line) {
            entries.push(entry);
        }
    }
    entries
}

/// The audit rows written under `request_id`, in log order.
fn rows_for_request(log_path: &std::path::Path, request_id: &str) -> Vec<AuditEntry> {
    read_audit_entries(log_path)
        .into_iter()
        .filter(|entry| entry.request_id == request_id)
        .collect()
}

/// The 32-byte id of a contract address.
fn contract_id(address: &ScAddress) -> [u8; 32] {
    match address {
        ScAddress::Contract(ContractId(Hash(id))) => *id,
        other => panic!("not a contract address: {other:?}"),
    }
}

/// A testnet rule manager and its signers manager over one temporary audit
/// log, as production wires them, with the log's path and the `TempDir`
/// that holds it. The caller holds the `TempDir` for the test's duration.
fn fresh_managers() -> (ContextRuleManager, Arc<SignersManager>, PathBuf, TempDir) {
    managers_for_tests(
        TESTNET_RPC_URL,
        TESTNET_RPC_URL,
        Duration::from_secs(TIMEOUT_SECS),
    )
}

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

/// Encodes `SimpleThresholdAccountParams { threshold: N }` as a Soroban ScVal.
///
/// `#[contracttype]` struct encoding: `ScVal::Map(ScMap([("threshold", U32(N))]))`.
///
/// # Byte-layout
///
/// The OpenZeppelin threshold policy defines
/// `SimpleThresholdAccountParams { threshold: u32 }` with `#[contracttype]`.
fn encode_threshold_params(threshold: u32) -> ScVal {
    let entry = ScMapEntry {
        key: ScVal::Symbol(ScSymbol::try_from("threshold").expect("'threshold' fits ScSymbol")),
        val: ScVal::U32(threshold),
    };
    let map: VecM<ScMapEntry> = vec![entry].try_into().expect("single-entry VecM");
    ScVal::Map(Some(ScMap(map)))
}

/// Deploys the OZ v0.7.2 threshold-policy WASM to testnet and returns the
/// resulting contract C-strkey.
///
/// The deployed contract address is deterministic:
/// `sha256("oz-threshold-policy-v0.7.2-{salt_suffix}")` combined with the
/// deployer's G-strkey. Callers MUST pass distinct `salt_suffix` values when
/// they need distinct contract addresses, because:
///
/// - The OpenZeppelin `add_context_rule` takes
///   `policies: &Map<Address, Val>` — Soroban Map, unique Address keys.
/// - The wallet encodes policies as `ScVal::Map`; the Soroban host validates
///   strict ascending key order with no duplicates. Duplicate `Address` keys
///   fail at simulate.
/// - The OpenZeppelin `add_policy` panics with
///   `DuplicatePolicy` when the address already exists in the rule. Calling
///   `add_policy(same_addr)` on a rule that already contains that address
///   unconditionally fails on-chain regardless of the wallet layer.
///
/// WASM upload is gated by an on-chain existence check (idempotent).  Contract
/// creation is idempotent: `AlreadyExists` / `ContractAlreadyExists` is treated
/// as success and the deterministic address is returned.
async fn deploy_threshold_policy_with_salt(
    deployer_g: &str,
    signer: &(dyn Signer + Send + Sync),
    salt_suffix: &str,
) -> String {
    let wasm_hash_bytes: [u8; 32] = Sha256::digest(THRESHOLD_POLICY_WASM).into();

    let salt_input = format!("oz-threshold-policy-v0.7.2-{salt_suffix}");
    let salt: [u8; 32] = Sha256::digest(salt_input.as_bytes()).into();

    let policy_strkey = derive_smart_account_address(deployer_g, &salt, TESTNET_PASSPHRASE)
        .expect("threshold-policy address derivation must succeed");

    let rpc_server = Client::new(TESTNET_RPC_URL).expect("Server::new must succeed");

    let network_client =
        StellarRpcClient::new(TESTNET_RPC_URL).expect("StellarRpcClient::new must succeed");

    let deployer_view = fetch_account(&network_client, deployer_g, &[])
        .await
        .expect("deployer account fetch must succeed");
    let mut deployer_account =
        BaselibAccount::new(deployer_g, &deployer_view.sequence_number.to_string())
            .expect("BaselibAccount::new must succeed");

    // Upload WASM if not already on-chain.
    let wasm_key = LedgerKey::ContractCode(LedgerKeyContractCode {
        hash: Hash(wasm_hash_bytes),
    });
    let wasm_query = rpc_server
        .get_ledger_entries(&[wasm_key])
        .await
        .expect("getLedgerEntries (wasm pre-flight) must succeed");
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

        let upload_tx_envelope_pre = upload_tx
            .to_envelope()
            .expect("upload to_envelope (pre-sim) must succeed");
        let upload_tx_sim = rpc_server
            .simulate_transaction_envelope(&upload_tx_envelope_pre, None)
            .await
            .expect("upload simulate_transaction_envelope must succeed");
        let upload_tx_resource_fee = u32::try_from(upload_tx_sim.min_resource_fee)
            .expect("upload min_resource_fee must fit u32");
        let mut prepared_upload = upload_tx.clone();
        prepared_upload.fee = prepared_upload.fee.saturating_add(upload_tx_resource_fee);
        prepared_upload.soroban_data = Some(
            upload_tx_sim
                .transaction_data()
                .expect("upload transaction_data must decode"),
        );

        let upload_xdr = prepared_upload
            .to_envelope()
            .expect("upload to_envelope must succeed")
            .to_xdr_base64(Limits::none())
            .expect("upload XDR encode must succeed");

        let signed_upload_xdr = attach_signature(&upload_xdr, signer, TESTNET_PASSPHRASE)
            .await
            .expect("upload signing must succeed");

        submit_transaction_and_wait(
            &network_client,
            &signed_upload_xdr,
            Duration::from_secs(TIMEOUT_SECS),
            TESTNET_PASSPHRASE,
            None,
            None,
        )
        .await
        .expect("upload submit must succeed");

        let updated_view = fetch_account(&network_client, deployer_g, &[])
            .await
            .expect("deployer re-fetch after upload must succeed");
        deployer_account =
            BaselibAccount::new(deployer_g, &updated_view.sequence_number.to_string())
                .expect("BaselibAccount::new after upload must succeed");
    }

    // Deploy contract via CreateContractV2.
    let deployer_pk = stellar_strkey::ed25519::PublicKey::from_string(deployer_g)
        .expect("deployer G-strkey parse must succeed");
    let deployer_sc_address = ScAddress::Account(AccountId(XdrPublicKey::PublicKeyTypeEd25519(
        Uint256(deployer_pk.0),
    )));

    let deploy_args = CreateContractArgsV2 {
        contract_id_preimage: ContractIdPreimage::Address(ContractIdPreimageFromAddress {
            address: deployer_sc_address,
            salt: Uint256(salt),
        }),
        executable: ContractExecutable::Wasm(Hash(wasm_hash_bytes)),
        constructor_args: VecM::default(),
    };

    let deploy_op = Operation {
        source_account: None,
        body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
            host_function: HostFunction::CreateContractV2(deploy_args),
            auth: VecM::default(),
        }),
    };

    let mut deploy_tx_builder =
        TransactionBuilder::new(&mut deployer_account, TESTNET_PASSPHRASE, None);
    deploy_tx_builder.fee(FEE_STROOPS);
    deploy_tx_builder.add_operation(deploy_op);
    let deploy_tx: Transaction = deploy_tx_builder.build_for_simulation();

    let deploy_tx_envelope_pre = deploy_tx
        .to_envelope()
        .expect("deploy to_envelope (pre-sim) must succeed");
    let deploy_tx_sim = rpc_server
        .simulate_transaction_envelope(&deploy_tx_envelope_pre, None)
        .await
        .expect("deploy simulate_transaction_envelope must succeed");
    let deploy_tx_resource_fee = u32::try_from(deploy_tx_sim.min_resource_fee)
        .expect("deploy min_resource_fee must fit u32");
    let deploy_sim_auth: VecM<SorobanAuthorizationEntry> = deploy_tx_sim
        .results()
        .ok()
        .and_then(|rs| rs.into_iter().next())
        .map(|r| r.auth)
        .unwrap_or_default()
        .try_into()
        .expect("deploy sim auth VecM encode must succeed");
    let mut prepared_deploy = deploy_tx.clone();
    prepared_deploy.fee = prepared_deploy.fee.saturating_add(deploy_tx_resource_fee);
    prepared_deploy.soroban_data = Some(
        deploy_tx_sim
            .transaction_data()
            .expect("deploy transaction_data must decode"),
    );
    if let Some(op) = prepared_deploy
        .operations
        .as_mut()
        .and_then(|ops| ops.get_mut(0))
        && let OperationBody::InvokeHostFunction(ihf) = &mut op.body
    {
        ihf.auth = deploy_sim_auth;
    }

    let deploy_xdr = prepared_deploy
        .to_envelope()
        .expect("deploy to_envelope must succeed")
        .to_xdr_base64(Limits::none())
        .expect("deploy XDR encode must succeed");

    let signed_deploy_xdr = attach_signature(&deploy_xdr, signer, TESTNET_PASSPHRASE)
        .await
        .expect("deploy signing must succeed");

    let deploy_result = submit_transaction_and_wait(
        &network_client,
        &signed_deploy_xdr,
        Duration::from_secs(TIMEOUT_SECS),
        TESTNET_PASSPHRASE,
        None,
        None,
    )
    .await;

    match deploy_result {
        Ok(_) => {}
        Err(e) => {
            let msg = format!("{e}");
            if !msg.contains("AlreadyExists") && !msg.contains("ContractAlreadyExists") {
                panic!("deploy threshold-policy tx failed: {e}");
            }
        }
    }

    policy_strkey
}

// ── h3_add_policy_increments_count_and_emits_audit_row ───────────────────────

/// Deploy a fresh smart account, install a rule with no policy, call
/// `manager.add_policy` with the simple-threshold policy `policy_addr_A`,
/// assert `policy_count == 1` and the audit rows of the attach, then attach a
/// second simple-threshold policy `policy_addr_B` and assert the refusal.
///
/// # Why the rule holds one simple-threshold policy
///
/// The wallet records a rule's simple-threshold value in its signer-set
/// state, so an attach of the simple-threshold policy runs through the
/// signers manager: the rule's version-2 baseline (which the install recorded)
/// must match the chain, and the rule must have no simple-threshold policy
/// yet. The attach of `policy_addr_A` records a `SaThresholdChangedV2` row
/// (no previous threshold, the resulting threshold 1 on `policy_addr_A`)
/// before the `SaPolicyAdded` row. The attach of the distinct
/// `policy_addr_B` then refuses before submission with
/// `ThresholdPolicyIdentificationFailed`, and the policy count stays 1.
///
/// # Steps
///
/// 1. Generate and fund the operator signer.
/// 2. Deploy a fresh smart account.
/// 3. Deploy two DISTINCT threshold-policy contracts (salts `h3-policy-a`, `h3-policy-b`).
/// 4. Install a rule with no policy through a rule manager and signers
///    manager over one audit log.
/// 5. Fetch the installed rule; assert `decode_policy_count_from_scval == 0`
///    (precondition guard).
/// 6. Call `manager.add_policy` with `policy_addr_A` and threshold 1.
/// 7. Fetch the rule again; assert `decode_policy_count_from_scval == 1`.
/// 8. Assert the attach's rows: `SaThresholdChangedV2`, then `SaPolicyAdded`
///    with the correct `rule_id` and `chain_id`, then one
///    `SaRawInvocation(Success)`.
/// 9. Call `manager.add_policy` with `policy_addr_B`; assert the refusal, no
///    `SaPolicyAdded` row for it, and `policy_count == 1`.
///
/// # Reference cross-check
///
/// - The OpenZeppelin `add_policy` returns `u32` (policy_id).
/// - The OpenZeppelin `add_policy` implementation panics with
///   `DuplicatePolicy` when the address already exists in the rule.
/// - The OpenZeppelin `add_context_rule` takes
///   `policies: &Map<Address, Val>` — Soroban Map, unique Address keys.
#[tokio::test]
async fn h3_add_policy_increments_count_and_emits_audit_row() {
    // ── Step 1: Generate and fund the operator signer ────────────────────────
    let (signer_g, signer_box) = fresh_signer();
    fund_via_friendbot(&signer_g).await;

    // ── Step 2: Deploy a fresh smart account ─────────────────────────────────
    let sa_strkey = deploy_fresh_smart_account(&signer_g).await;
    let sa_addr = parse_c_strkey_to_smart_account(&sa_strkey)
        .expect("[h3] SA C-strkey must parse to ScAddress");

    eprintln!("[h3] smart_account = {sa_strkey}");

    // ── Step 3: Deploy two DISTINCT threshold-policy contracts ───────────────
    // policy_addr_a is attached to the policyless rule; policy_addr_b is the
    // second simple-threshold policy whose attach the wallet refuses.
    let policy_a_strkey =
        deploy_threshold_policy_with_salt(&signer_g, signer_box.as_ref(), "h3-policy-a").await;
    let policy_addr_a = parse_c_strkey_to_smart_account(&policy_a_strkey)
        .expect("[h3] policy_a C-strkey must parse");
    eprintln!("[h3] threshold-policy A = {policy_a_strkey}");

    let policy_b_strkey =
        deploy_threshold_policy_with_salt(&signer_g, signer_box.as_ref(), "h3-policy-b").await;
    let policy_addr_b = parse_c_strkey_to_smart_account(&policy_b_strkey)
        .expect("[h3] policy_b C-strkey must parse");
    eprintln!("[h3] threshold-policy B = {policy_b_strkey}");

    assert_ne!(
        policy_a_strkey, policy_b_strkey,
        "[h3] the two deployed policy addresses must be distinct"
    );

    // ── Step 4: Install a rule with no policy ────────────────────────────────
    let signer_addr =
        parse_g_strkey_to_signer_address(&signer_g).expect("[h3] signer G-strkey must parse");

    let (rule_manager, signers_manager, audit_log_path, _audit_dir) = fresh_managers();
    let definition = ContextRuleDefinition::new(
        RuleContext::Default,
        "h3-add-policy-test".to_owned(),
        None,
        vec![ContextRuleSignerInput::Delegated {
            address: signer_addr,
        }],
        vec![],
    );

    let install_output = rule_manager
        .install_rule(
            sa_addr.clone(),
            definition,
            vec![ContextRuleId::new(0)],
            signer_box.as_ref(),
            None,
            rid(),
            false,
            false,
        )
        .await
        .expect("[h3] install_rule must succeed on testnet");

    let rule_id = install_output.rule_id;
    eprintln!("[h3] installed policyless rule: rule_id = {rule_id}");

    // ── Step 5: Precondition guard: assert policy_count == 0 ────────────────
    let scval_before = rule_manager
        .get_rule(sa_addr.clone(), rule_id, &signer_g)
        .await
        .expect("[h3] get_rule must succeed")
        .expect("[h3] rule must be present");

    let count_before = decode_policy_count_from_scval(&scval_before)
        .expect("[h3] decode_policy_count_from_scval must succeed");
    assert_eq!(
        count_before, 0,
        "[h3] precondition guard: installed rule must have no policy; got {count_before}"
    );
    eprintln!("[h3] precondition guard passed: policy_count = {count_before}");

    // ── Step 6: attach policy_addr_a with threshold 1 ─────────────────────────
    let request_id = rid();
    let add_policy_result = rule_manager
        .add_policy(
            sa_addr.clone(),
            rule_id,
            policy_addr_a.clone(),
            encode_threshold_params(1),
            // Rule 0, the bootstrap rule whose signer is this test's signer,
            // authorizes the attach.
            vec![ContextRuleId::new(0)],
            signer_box.as_ref(),
            None,
            request_id.clone(),
            false, // accept_mutable_verifier
            false, // accept_unknown_verifier
        )
        .await;

    let policy_id = add_policy_result.expect("[h3] add_policy must succeed on testnet");
    eprintln!("[h3] add_policy succeeded: policy_id = {policy_id}");

    // ── Step 7: Fetch the rule and assert policy_count == 1 ──────────────────
    let scval_after = rule_manager
        .get_rule(sa_addr.clone(), rule_id, &signer_g)
        .await
        .expect("[h3] get_rule (after add_policy) must succeed")
        .expect("[h3] rule must still be present");

    let count_after = decode_policy_count_from_scval(&scval_after)
        .expect("[h3] decode_policy_count_from_scval (after) must succeed");
    assert_eq!(
        count_after, 1,
        "[h3] policy_count must be 1 after add_policy; got {count_after}"
    );
    eprintln!("[h3] post-add_policy policy_count = {count_after}");

    // ── Step 8: Assert the attach's audit rows ────────────────────────────────
    let entries = rows_for_request(&audit_log_path, &request_id);
    assert!(
        !entries.is_empty(),
        "[h3] audit log must contain the attach's rows"
    );

    let threshold_position = entries
        .iter()
        .position(|e| {
            matches!(
                &e.event_kind,
                EventKind::SaThresholdChangedV2 {
                    rule_id: rid,
                    previous_threshold: None,
                    snapshot,
                    ..
                } if *rid == rule_id
                    && snapshot.threshold
                        == Some(ThresholdObservation {
                            policy: contract_id(&policy_addr_a),
                            threshold: 1,
                        })
            )
        })
        .expect(
            "[h3] the attach must record SaThresholdChangedV2 with no previous threshold and \
             threshold 1 on policy A",
        );

    let policy_added_positions: Vec<usize> = entries
        .iter()
        .enumerate()
        .filter(|(_, e)| {
            matches!(
                &e.event_kind,
                EventKind::SaPolicyAdded {
                    rule_id: rid,
                    policy_id: pid,
                    ..
                } if *rid == rule_id && *pid == policy_id
            )
        })
        .map(|(position, _)| position)
        .collect();
    assert_eq!(
        policy_added_positions.len(),
        1,
        "[h3] exactly one SaPolicyAdded row with rule_id={rule_id} and \
         policy_id={policy_id} must be present; found {}",
        policy_added_positions.len()
    );
    assert!(
        threshold_position < policy_added_positions[0],
        "[h3] SaThresholdChangedV2 must precede SaPolicyAdded"
    );

    let policy_added_entry = &entries[policy_added_positions[0]];
    assert_eq!(
        policy_added_entry.chain_id.as_deref(),
        Some(CHAIN_ID),
        "[h3] SaPolicyAdded row must carry chain_id={CHAIN_ID}; got {:?}",
        policy_added_entry.chain_id
    );
    let EventKind::SaPolicyAdded {
        transaction_hash_redacted,
        ..
    } = &policy_added_entry.event_kind
    else {
        panic!("[h3] selected audit entry must be SaPolicyAdded");
    };
    assert_eq!(
        transaction_hash_redacted.len(),
        19,
        "[h3] SaPolicyAdded row must carry first-8-last-8 redacted tx hash"
    );

    let raw_ok_count = entries
        .iter()
        .filter(|e| {
            matches!(
                &e.event_kind,
                EventKind::SaRawInvocation {
                    wire_code,
                    result: stellar_agent_core::audit_log::schema::SaInvocationResult::Success,
                    ..
                } if wire_code == "sa.ok"
            )
        })
        .count();
    assert_eq!(
        raw_ok_count, 1,
        "[h3] exactly one SaRawInvocation(Success) row with wire_code=sa.ok \
         must be present; found {raw_ok_count}"
    );

    // The recorded threshold change keeps the rule's state row in step with
    // the chain.
    let listed = signers_manager
        .list_signers(sa_addr.clone(), rule_id, Some(&signer_g), rid())
        .await
        .expect("[h3] list_signers after the attach must succeed");
    assert_eq!(
        listed.baseline,
        PreviousBaseline::Matched,
        "[h3] the recorded state must match the chain after the attach"
    );

    // ── Step 9: a second simple-threshold policy refuses ─────────────────────
    let second_request_id = rid();
    let second = rule_manager
        .add_policy(
            sa_addr.clone(),
            rule_id,
            policy_addr_b,
            encode_threshold_params(1),
            vec![ContextRuleId::new(0)],
            signer_box.as_ref(),
            None,
            second_request_id.clone(),
            false, // accept_mutable_verifier
            false, // accept_unknown_verifier
        )
        .await
        .expect_err("[h3] a second simple-threshold policy must be refused");
    assert!(
        matches!(second, SaError::ThresholdPolicyIdentificationFailed { .. }),
        "[h3] expected ThresholdPolicyIdentificationFailed; got {second:?}"
    );
    let second_entries = rows_for_request(&audit_log_path, &second_request_id);
    assert!(
        !second_entries
            .iter()
            .any(|e| matches!(&e.event_kind, EventKind::SaPolicyAdded { .. })),
        "[h3] the refused attach must write no SaPolicyAdded row"
    );
    let scval_refused = rule_manager
        .get_rule(sa_addr, rule_id, &signer_g)
        .await
        .expect("[h3] get_rule (after the refused attach) must succeed")
        .expect("[h3] rule must still be present");
    assert_eq!(
        decode_policy_count_from_scval(&scval_refused)
            .expect("[h3] decode_policy_count_from_scval (refused) must succeed"),
        1,
        "[h3] the refused attach must leave policy_count at 1"
    );
}

// ── h4_remove_policy_decrements_count_and_emits_audit_row ────────────────────

/// Deploy a fresh smart account, install a rule with no policy, attach the
/// simple-threshold policy `policy_addr_a` to reach `policy_count = 1`, then
/// call `manager.remove_policy` with the `policy_id` returned by `add_policy`,
/// assert `policy_count == 0`, and assert the detach's audit rows.
///
/// # Why the rule holds one simple-threshold policy
///
/// The wallet records a rule's simple-threshold value in its signer-set
/// state and attaches at most one simple-threshold policy to a rule. The
/// detach of the observed simple-threshold policy records a
/// `SaThresholdChangedV2` row (the observed threshold as previous, none as
/// resulting) before the `SaPolicyRemoved` row.
///
/// # Steps
///
/// 1. Generate + fund operator signer; deploy SA.
/// 2. Deploy a threshold-policy contract (salt `h4-policy-a`).
/// 3. Install a policyless rule through a rule manager and signers manager
///    over one audit log.
/// 4. Call `add_policy(policy_addr_a)` to reach `policy_count = 1`; store its
///    `policy_id`.
/// 5. Precondition guard: assert `policy_count == 1`.
/// 6. Call `manager.remove_policy(policy_id)`.
/// 7. Fetch the rule; assert `policy_count == 0`.
/// 8. Assert the audit log contains `SaThresholdChangedV2` before a
///    `SaPolicyRemoved` row with the correct `rule_id`, `policy_id`, and
///    `chain_id`, and one `SaRawInvocation(Success)` row for the removal.
///
/// # Reference cross-check
///
/// - The OpenZeppelin `remove_policy(context_rule_id, policy_id)`.
/// - The OpenZeppelin `remove_policy` implementation.
#[tokio::test]
async fn h4_remove_policy_decrements_count_and_emits_audit_row() {
    // ── Step 1: Generate and fund the operator signer ────────────────────────
    let (signer_g, signer_box) = fresh_signer();
    fund_via_friendbot(&signer_g).await;

    let sa_strkey = deploy_fresh_smart_account(&signer_g).await;
    let sa_addr = parse_c_strkey_to_smart_account(&sa_strkey).expect("[h4] SA C-strkey must parse");

    eprintln!("[h4] smart_account = {sa_strkey}");

    // ── Step 2: Deploy the threshold-policy contract ─────────────────────────
    let policy_a_strkey =
        deploy_threshold_policy_with_salt(&signer_g, signer_box.as_ref(), "h4-policy-a").await;
    let policy_addr_a = parse_c_strkey_to_smart_account(&policy_a_strkey)
        .expect("[h4] policy_a C-strkey must parse");
    eprintln!("[h4] threshold-policy A = {policy_a_strkey}");

    // ── Step 3: Install a policyless rule ─────────────────────────────────────
    let signer_addr =
        parse_g_strkey_to_signer_address(&signer_g).expect("[h4] signer G-strkey must parse");

    let (rule_manager, signers_manager, audit_log_path, _audit_dir) = fresh_managers();
    let definition = ContextRuleDefinition::new(
        RuleContext::Default,
        "h4-rm-policy-test".to_owned(),
        None,
        vec![ContextRuleSignerInput::Delegated {
            address: signer_addr,
        }],
        vec![],
    );

    let install_output = rule_manager
        .install_rule(
            sa_addr.clone(),
            definition,
            vec![ContextRuleId::new(0)],
            signer_box.as_ref(),
            None,
            rid(),
            false,
            false,
        )
        .await
        .expect("[h4] install_rule must succeed on testnet");

    let rule_id = install_output.rule_id;
    eprintln!("[h4] installed policyless rule: rule_id = {rule_id}");

    // ── Step 4: Call add_policy(policy_addr_a) to reach policy_count = 1 ─────
    // The policy_id returned here is the id that remove_policy will target.
    let policy_id_to_remove = rule_manager
        .add_policy(
            sa_addr.clone(),
            rule_id,
            policy_addr_a.clone(),
            encode_threshold_params(1),
            // Rule 0, the bootstrap rule whose signer is this test's signer,
            // authorizes the attach.
            vec![ContextRuleId::new(0)],
            signer_box.as_ref(),
            None,
            rid(),
            false, // accept_mutable_verifier
            false, // accept_unknown_verifier
        )
        .await
        .expect("[h4] add_policy(policy_addr_a) must succeed (establishing policy_count=1)");

    eprintln!("[h4] add_policy succeeded: policy_id_to_remove = {policy_id_to_remove}");

    // ── Step 5: Precondition guard: assert policy_count == 1 ────────────────
    let scval_before = rule_manager
        .get_rule(sa_addr.clone(), rule_id, &signer_g)
        .await
        .expect("[h4] get_rule (before remove) must succeed")
        .expect("[h4] rule must be present");

    let count_before = decode_policy_count_from_scval(&scval_before)
        .expect("[h4] decode_policy_count_from_scval must succeed");
    assert_eq!(
        count_before, 1,
        "[h4] precondition guard: must have 1 policy before remove_policy; \
         got {count_before}"
    );
    eprintln!("[h4] precondition guard passed: policy_count = {count_before}");

    // ── Step 6: call remove_policy ───────────────────────────────────────────
    let request_id = rid();

    let remove_result = rule_manager
        .remove_policy(
            sa_addr.clone(),
            rule_id,
            policy_id_to_remove,
            // Rule 0, the bootstrap rule whose signer is this test's signer,
            // authorizes the removal.
            vec![ContextRuleId::new(0)],
            signer_box.as_ref(),
            None,
            request_id.clone(),
        )
        .await;

    remove_result.expect("[h4] remove_policy must succeed on testnet");
    eprintln!("[h4] remove_policy succeeded");

    // ── Step 7: Fetch the rule and assert policy_count == 0 ──────────────────
    let scval_after = rule_manager
        .get_rule(sa_addr.clone(), rule_id, &signer_g)
        .await
        .expect("[h4] get_rule (after remove) must succeed")
        .expect("[h4] rule must still be present");

    let count_after = decode_policy_count_from_scval(&scval_after)
        .expect("[h4] decode_policy_count_from_scval (after) must succeed");
    assert_eq!(
        count_after, 0,
        "[h4] policy_count must be 0 after remove_policy; got {count_after}"
    );
    eprintln!("[h4] post-remove_policy policy_count = {count_after}");

    // ── Step 8: Assert the detach's audit rows ────────────────────────────────
    let entries = rows_for_request(&audit_log_path, &request_id);
    assert!(
        !entries.is_empty(),
        "[h4] audit log must contain the removal's rows"
    );

    let threshold_position = entries
        .iter()
        .position(|e| {
            matches!(
                &e.event_kind,
                EventKind::SaThresholdChangedV2 {
                    rule_id: rid,
                    previous_threshold: Some(previous),
                    snapshot,
                    ..
                } if *rid == rule_id
                    && *previous
                        == ThresholdObservation {
                            policy: contract_id(&policy_addr_a),
                            threshold: 1,
                        }
                    && snapshot.threshold.is_none()
            )
        })
        .expect(
            "[h4] the detach must record SaThresholdChangedV2 from threshold 1 on policy A \
             to no threshold",
        );

    let policy_removed_positions: Vec<usize> = entries
        .iter()
        .enumerate()
        .filter(|(_, e)| {
            matches!(
                &e.event_kind,
                EventKind::SaPolicyRemoved {
                    rule_id: rid,
                    policy_id: pid,
                    ..
                } if *rid == rule_id && *pid == policy_id_to_remove
            )
        })
        .map(|(position, _)| position)
        .collect();
    assert_eq!(
        policy_removed_positions.len(),
        1,
        "[h4] exactly one SaPolicyRemoved row with rule_id={rule_id} and \
         policy_id={policy_id_to_remove} must be present; found {}",
        policy_removed_positions.len()
    );
    assert!(
        threshold_position < policy_removed_positions[0],
        "[h4] SaThresholdChangedV2 must precede SaPolicyRemoved"
    );

    let policy_removed_entry = &entries[policy_removed_positions[0]];
    assert_eq!(
        policy_removed_entry.chain_id.as_deref(),
        Some(CHAIN_ID),
        "[h4] SaPolicyRemoved row must carry chain_id={CHAIN_ID}; got {:?}",
        policy_removed_entry.chain_id
    );
    let EventKind::SaPolicyRemoved {
        transaction_hash_redacted,
        ..
    } = &policy_removed_entry.event_kind
    else {
        panic!("[h4] selected audit entry must be SaPolicyRemoved");
    };
    assert_eq!(
        transaction_hash_redacted.len(),
        19,
        "[h4] SaPolicyRemoved row must carry first-8-last-8 redacted tx hash"
    );

    let raw_ok_count = entries
        .iter()
        .filter(|e| {
            matches!(
                &e.event_kind,
                EventKind::SaRawInvocation {
                    wire_code,
                    result: stellar_agent_core::audit_log::schema::SaInvocationResult::Success,
                    ..
                } if wire_code == "sa.ok"
            )
        })
        .count();
    assert_eq!(
        raw_ok_count, 1,
        "[h4] exactly one SaRawInvocation(Success) row must be present; \
         found {raw_ok_count}"
    );

    // The recorded threshold change keeps the rule's state row in step with
    // the chain.
    let listed = signers_manager
        .list_signers(sa_addr, rule_id, Some(&signer_g), rid())
        .await
        .expect("[h4] list_signers after the detach must succeed");
    assert_eq!(
        listed.baseline,
        PreviousBaseline::Matched,
        "[h4] the recorded state must match the chain after the detach"
    );
}

// ── h5_add_policy_type_mismatched_install_param_no_success_audit ─────────────

/// Supply an install parameter that base64-decodes correctly but is not the
/// simple-threshold policy's `SimpleThresholdAccountParams`.
///
/// `ScVal::Bool(true)` is valid XDR and decodes without error; it does NOT
/// match `SimpleThresholdAccountParams { threshold: u32 }` (which the on-chain
/// contract expects as `ScVal::Map([("threshold", ScVal::U32(N))])`).
///
/// # Why the refusal comes before submission
///
/// The wallet observes the policy's executable before submission. The
/// simple-threshold policy's attach records the threshold the parameter sets,
/// so the wallet reads the parameter first and refuses one that is not the
/// threshold map with `SimpleThresholdInstallRefused`, before anything is
/// simulated or signed. `policy_addr_b` is not attached to the rule, so the
/// refusal concerns the parameter alone.
///
/// # Assertions
///
/// 1. `manager.add_policy(...)` returns
///    `Err(SaError::SimpleThresholdInstallRefused { .. })`.
/// 2. No `SaPolicyAdded` row is present in the audit log (no audit-row
///    claiming success after a failed operation).
/// 3. Exactly one `SaRawInvocation` row is present for the call, with
///    `result: SaInvocationResult::PreSubmissionRefused`.
/// 4. The rule still holds its one policy.
///
/// # Steps
///
/// 1. Generate and fund the operator signer.
/// 2. Deploy a fresh smart account.
/// 3. Deploy TWO distinct threshold-policy contracts (salts `h5-policy-a`,
///    `h5-policy-b`).
/// 4. Install a rule with 1 policy (`policy_addr_a`).
/// 5. Call `manager.add_policy` with `policy_addr_b` and
///    `install_param = ScVal::Bool(true)`.
/// 6. Assert the call returns `Err` with `SimpleThresholdInstallRefused`.
/// 7. Assert the audit log has NO `SaPolicyAdded` row for the call.
/// 8. Assert the audit log has exactly one `SaRawInvocation(PreSubmissionRefused)`
///    row for the call.
/// 9. Assert the rule's policy count is unchanged.
///
/// # Reference cross-check
///
/// - The OpenZeppelin threshold policy defines
///   `SimpleThresholdAccountParams { threshold: u32 }` with
///   `#[contracttype]` — on-chain contract initialiser expects
///   `ScVal::Map([("threshold", ScVal::U32(N))])`.
/// - `sa_error_to_invocation_result`: `SimpleThresholdInstallRefused` maps to
///   `SaInvocationResult::PreSubmissionRefused`.
#[tokio::test]
async fn h5_add_policy_type_mismatched_install_param_no_success_audit() {
    // ── Step 1: Generate and fund the operator signer ────────────────────────
    let (signer_g, signer_box) = fresh_signer();
    fund_via_friendbot(&signer_g).await;

    // ── Step 2: Deploy a fresh smart account ─────────────────────────────────
    let sa_strkey = deploy_fresh_smart_account(&signer_g).await;
    let sa_addr = parse_c_strkey_to_smart_account(&sa_strkey)
        .expect("[h5] SA C-strkey must parse to ScAddress");

    eprintln!("[h5] smart_account = {sa_strkey}");

    // ── Step 3: Deploy TWO DISTINCT threshold-policy contracts ───────────────
    // policy_addr_a is installed in the initial rule; policy_addr_b, not
    // attached to the rule, carries the malformed parameter.
    let policy_a_strkey =
        deploy_threshold_policy_with_salt(&signer_g, signer_box.as_ref(), "h5-policy-a").await;
    let policy_addr_a = parse_c_strkey_to_smart_account(&policy_a_strkey)
        .expect("[h5] policy_a C-strkey must parse");
    eprintln!("[h5] threshold-policy A = {policy_a_strkey}");

    let policy_b_strkey =
        deploy_threshold_policy_with_salt(&signer_g, signer_box.as_ref(), "h5-policy-b").await;
    let policy_addr_b = parse_c_strkey_to_smart_account(&policy_b_strkey)
        .expect("[h5] policy_b C-strkey must parse");
    eprintln!("[h5] threshold-policy B = {policy_b_strkey}");

    assert_ne!(
        policy_a_strkey, policy_b_strkey,
        "[h5] the two deployed policy addresses must be distinct"
    );

    // ── Step 4: Install a rule with 1 policy (policy_addr_a) ─────────────────
    let threshold_params = encode_threshold_params(1);
    let signer_addr =
        parse_g_strkey_to_signer_address(&signer_g).expect("[h5] signer G-strkey must parse");

    let (rule_manager, _signers_manager, audit_log_path, _audit_dir) = fresh_managers();
    let definition = ContextRuleDefinition::new(
        RuleContext::Default,
        "h5-type-mismatch".to_owned(),
        None,
        vec![ContextRuleSignerInput::Delegated {
            address: signer_addr,
        }],
        vec![ContextRulePolicy::new(policy_addr_a, threshold_params)],
    );

    let install_output = rule_manager
        .install_rule(
            sa_addr.clone(),
            definition,
            vec![ContextRuleId::new(0)],
            signer_box.as_ref(),
            None,
            rid(),
            false,
            false,
        )
        .await
        .expect("[h5] install_rule must succeed on testnet");

    let rule_id = install_output.rule_id;
    eprintln!("[h5] installed 1-policy rule (policy_addr_a): rule_id = {rule_id}");

    // ── Step 5: Build a type-mismatched install_param ─────────────────────────
    // `ScVal::Bool(true)` is valid XDR and decodes without error.  It does NOT
    // match `SimpleThresholdAccountParams { threshold: u32 }`.
    let mismatched_param = ScVal::Bool(true);

    // ── Step 6: call add_policy with policy_addr_b + mismatched param ─────────
    let request_id = rid();

    let result = rule_manager
        .add_policy(
            sa_addr.clone(),
            rule_id,
            policy_addr_b,
            mismatched_param,
            // Rule 0, the bootstrap rule whose signer is this test's signer,
            // authorizes the attach.
            vec![ContextRuleId::new(0)],
            signer_box.as_ref(),
            None,
            request_id.clone(),
            false, // accept_mutable_verifier
            false, // accept_unknown_verifier
        )
        .await;

    // ── Step 7: Assert the refusal before submission ──────────────────────────
    match &result {
        Err(err @ SaError::SimpleThresholdInstallRefused { .. }) => {
            assert_eq!(
                err.wire_code(),
                "sa.simple_threshold_install_refused",
                "[h5] the refusal's wire code must be sa.simple_threshold_install_refused"
            );
            eprintln!("[h5] pre-submission refusal confirmed: {err}");
        }
        Ok(policy_id) => {
            panic!(
                "[h5] add_policy must fail with a type-mismatched install_param; \
                 got Ok(policy_id = {policy_id})"
            );
        }
        Err(other) => {
            panic!("[h5] expected SimpleThresholdInstallRefused; got {other:?}");
        }
    }

    // ── Step 8: Assert NO SaPolicyAdded audit row ─────────────────────────────
    let entries = rows_for_request(&audit_log_path, &request_id);

    let policy_added_count = entries
        .iter()
        .filter(|e| matches!(&e.event_kind, EventKind::SaPolicyAdded { .. }))
        .count();
    assert_eq!(
        policy_added_count, 0,
        "[h5] no SaPolicyAdded row must be present after the refusal; \
         found {policy_added_count}"
    );
    eprintln!("[h5] confirmed: no SaPolicyAdded row in audit log");

    // ── Step 9: Assert exactly one SaRawInvocation(PreSubmissionRefused) ──────
    let pre_sub_refused_count = entries
        .iter()
        .filter(|e| {
            matches!(
                &e.event_kind,
                EventKind::SaRawInvocation {
                    result: stellar_agent_core::audit_log::schema::SaInvocationResult::PreSubmissionRefused,
                    ..
                }
            )
        })
        .count();
    assert_eq!(
        pre_sub_refused_count, 1,
        "[h5] exactly one SaRawInvocation(PreSubmissionRefused) row must be \
         present after the refusal; found {pre_sub_refused_count}"
    );
    eprintln!("[h5] confirmed: 1 SaRawInvocation(PreSubmissionRefused) row in audit log");

    // ── Step 10: Assert the rule still holds its one policy ───────────────────
    let scval_after = rule_manager
        .get_rule(sa_addr, rule_id, &signer_g)
        .await
        .expect("[h5] get_rule (after the refusal) must succeed")
        .expect("[h5] rule must still be present");
    assert_eq!(
        decode_policy_count_from_scval(&scval_after)
            .expect("[h5] decode_policy_count_from_scval must succeed"),
        1,
        "[h5] the refused attach must leave the rule's policy count at 1"
    );
}
