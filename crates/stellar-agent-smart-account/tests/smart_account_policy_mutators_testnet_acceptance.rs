//! Testnet acceptance tests for `add_policy` / `remove_policy`.
//!
//! # Coverage
//!
//! | Fixture | Description |
//! |---------|-------------|
//! | [`h3_add_policy_increments_count_and_emits_audit_row`] | Deploy SA + rule with 1 policy, call `manager.add_policy`, assert `policy_count == 2`, assert `SaPolicyAdded` audit row |
//! | [`h4_remove_policy_decrements_count_and_emits_audit_row`] | Deploy SA + rule with 2 policies (installed + added), call `manager.remove_policy`, assert `policy_count == 1`, assert `SaPolicyRemoved` audit row |
//! | [`h5_add_policy_type_mismatched_install_param_no_success_audit`] | Deploy SA + rule, call `manager.add_policy` with a `ScVal::Bool(true)` install-param (base64-decodable but type-mismatches `SimpleThresholdAccountParams`), assert simulate-phase failure, no `SaPolicyAdded` row, exactly one `SaRawInvocation(PreSubmissionRefused)` row |
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
    clippy::await_holding_lock,
    reason = "test-only; panics and MutexGuard-across-await are acceptable in testnet \
              acceptance tests where async-aware Mutex would add test-only dependency complexity"
)]

use std::io::{BufRead as _, BufReader};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use sha2::{Digest as _, Sha256};
use stellar_agent_core::audit_log::entry::AuditEntry;
use stellar_agent_core::audit_log::schema::EventKind;
use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_core::smart_account::rule_id::ContextRuleId;
use stellar_agent_network::signing::envelope_signing::attach_signature;
use stellar_agent_network::{
    Signer, SoftwareSigningKey, StellarRpcClient, fetch_account, submit_transaction_and_wait,
};
use stellar_agent_smart_account::SaError;
use stellar_agent_smart_account::bindings::ContextRuleType;
use stellar_agent_smart_account::deployment::{
    DeployerKeypair, DeploymentArgs, ResolvedFeePerOp, deploy_smart_account,
    derive_smart_account_address,
};
use stellar_agent_smart_account::managers::rules::{
    ContextRuleDefinition, ContextRuleManager, ContextRuleManagerConfig, ContextRulePolicy,
    ContextRuleSignerInput, decode_policy_count_from_scval, parse_c_strkey_to_smart_account,
    parse_g_strkey_to_signer_address,
};
use stellar_agent_smart_account::signers::policy_identification::THRESHOLD_POLICY_WASM;
use stellar_baselib::account::{Account as BaselibAccount, AccountBehavior};
use stellar_baselib::transaction::{Transaction, TransactionBehavior};
use stellar_baselib::transaction_builder::{TransactionBuilder, TransactionBuilderBehavior};
use stellar_rpc_client::Client;
use stellar_xdr::{
    AccountId, BytesM, ContractExecutable, ContractIdPreimage, ContractIdPreimageFromAddress,
    CreateContractArgsV2, Hash, HostFunction, InvokeHostFunctionOp, LedgerKey,
    LedgerKeyContractCode, Limits, Operation, OperationBody, PublicKey as XdrPublicKey, ScAddress,
    ScMap, ScMapEntry, ScSymbol, ScVal, SorobanAuthorizationEntry, Uint256, VecM, WriteXdr,
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
    let resp = reqwest::get(&url)
        .await
        .expect("Friendbot HTTP must succeed");
    assert!(
        resp.status().is_success(),
        "Friendbot must return 200 for {g_strkey}; got {}",
        resp.status()
    );
}

fn tmp_audit_writer() -> (Arc<Mutex<AuditWriter>>, PathBuf, TempDir) {
    let dir = tempfile::tempdir().expect("tempdir must succeed");
    let path = dir.path().join("audit.jsonl");
    let writer = AuditWriter::open(path.clone(), None).expect("AuditWriter::open must succeed");
    (Arc::new(Mutex::new(writer)), path, dir)
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

fn fresh_rule_manager() -> ContextRuleManager {
    ContextRuleManager::new(ContextRuleManagerConfig::new(
        TESTNET_RPC_URL.to_owned(),
        TESTNET_PASSPHRASE.to_owned(),
        Duration::from_secs(TIMEOUT_SECS),
        CHAIN_ID.to_owned(),
    ))
    .expect("ContextRuleManager::new must succeed")
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

/// Deploys the OZ v0.7.1 threshold-policy WASM to testnet and returns the
/// resulting contract C-strkey.
///
/// The deployed contract address is deterministic:
/// `sha256("oz-threshold-policy-v0.7.1-{salt_suffix}")` combined with the
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

    let salt_input = format!("oz-threshold-policy-v0.7.1-{salt_suffix}");
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

/// Deploy a fresh smart account, install a rule with 1 policy (policy_addr_A),
/// call `manager.add_policy` with a SECOND distinct address (policy_addr_B),
/// assert `policy_count == 2`, and assert a `SaPolicyAdded` audit row was emitted.
///
/// # Why two distinct policy contracts are required
///
/// The OpenZeppelin `add_policy` calls `register_policy`,
/// which returns the same `policy_id` for the same `Address`, and then checks
/// `entry.policy_ids.contains(policy_id)` — panicking with `DuplicatePolicy` if
/// the id is already present.  Calling `add_policy(policy_addr_A)` on a rule
/// that was installed with `policy_addr_A` unconditionally fails on-chain.
///
/// Two distinct contracts are deployed with salt suffixes `"h3-policy-a"` and
/// `"h3-policy-b"`, guaranteeing distinct on-chain addresses and distinct
/// `policy_id` values.
///
/// # Steps
///
/// 1. Generate and fund the operator signer.
/// 2. Deploy a fresh smart account.
/// 3. Deploy two DISTINCT threshold-policy contracts (salts `h3-policy-a`, `h3-policy-b`).
/// 4. Install a rule with 1 policy (policy_addr_A).
/// 5. Fetch the installed rule; assert `decode_policy_count_from_scval == 1`
///    (precondition guard).
/// 6. Open an `AuditWriter` and call `manager.add_policy` with `policy_addr_B`.
/// 7. Fetch the rule again; assert `decode_policy_count_from_scval == 2`.
/// 8. Assert the audit log contains a `SaPolicyAdded` row with the correct
///    `rule_id` and `chain_id`.
/// 9. Assert the audit log also contains a `SaRawInvocation(Success)` row.
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
    // policy_addr_a is installed in the initial rule.
    // policy_addr_b is added via add_policy — a DISTINCT address is required
    // because the OpenZeppelin add_policy panics with DuplicatePolicy
    // when add_policy is called with an address already present in the rule.
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

    // ── Step 4: Install a 1-policy rule with policy_addr_a ───────────────────
    let threshold_params = encode_threshold_params(1);
    let signer_addr =
        parse_g_strkey_to_signer_address(&signer_g).expect("[h3] signer G-strkey must parse");

    let rule_manager = fresh_rule_manager();
    let definition = ContextRuleDefinition::new(
        ContextRuleType::Default,
        "h3-add-policy-test".to_owned(),
        None,
        vec![ContextRuleSignerInput::Delegated {
            address: signer_addr,
        }],
        vec![ContextRulePolicy::new(
            policy_addr_a.clone(),
            threshold_params.clone(),
        )],
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
    eprintln!("[h3] installed 1-policy rule: rule_id = {rule_id}");

    // ── Step 5: Precondition guard — assert policy_count == 1 ────────────────
    let scval_before = rule_manager
        .get_rule(sa_addr.clone(), rule_id, &signer_g)
        .await
        .expect("[h3] get_rule must succeed")
        .expect("[h3] rule must be present");

    let count_before = decode_policy_count_from_scval(&scval_before)
        .expect("[h3] decode_policy_count_from_scval must succeed");
    assert_eq!(
        count_before, 1,
        "[h3] precondition guard: installed rule must have exactly 1 policy; \
         got {count_before}"
    );
    eprintln!("[h3] precondition guard passed: policy_count = {count_before}");

    // ── Step 6: Open AuditWriter + call add_policy with policy_addr_b ─────────
    // Using policy_addr_b (distinct from policy_addr_a already installed in the
    // rule) avoids the DuplicatePolicy on-chain panic in the OpenZeppelin
    // add_policy.
    let (audit_writer_arc, audit_log_path, _tmp_dir) = tmp_audit_writer();
    let mut audit_writer = audit_writer_arc.lock().expect("audit writer lock");
    let request_id = rid();

    let auth_rule_ids = vec![ContextRuleId::new(rule_id)];

    let add_policy_result = rule_manager
        .add_policy(
            sa_addr.clone(),
            rule_id,
            policy_addr_b.clone(),
            threshold_params,
            auth_rule_ids,
            signer_box.as_ref(),
            Some(&mut *audit_writer),
            request_id.clone(),
        )
        .await;
    drop(audit_writer); // release the lock before reading the log

    let policy_id = add_policy_result.expect("[h3] add_policy must succeed on testnet");
    eprintln!("[h3] add_policy succeeded: policy_id = {policy_id}");

    // ── Step 7: Fetch the rule and assert policy_count == 2 ──────────────────
    let scval_after = rule_manager
        .get_rule(sa_addr.clone(), rule_id, &signer_g)
        .await
        .expect("[h3] get_rule (after add_policy) must succeed")
        .expect("[h3] rule must still be present");

    let count_after = decode_policy_count_from_scval(&scval_after)
        .expect("[h3] decode_policy_count_from_scval (after) must succeed");
    assert_eq!(
        count_after, 2,
        "[h3] policy_count must be 2 after add_policy; got {count_after}"
    );
    eprintln!("[h3] post-add_policy policy_count = {count_after}");

    // ── Step 8: Assert SaPolicyAdded audit row ────────────────────────────────
    let entries = read_audit_entries(&audit_log_path);
    assert!(
        !entries.is_empty(),
        "[h3] audit log must contain at least one entry after add_policy"
    );

    let policy_added_count = entries
        .iter()
        .filter(|e| {
            matches!(
                &e.event_kind,
                EventKind::SaPolicyAdded {
                    rule_id: rid,
                    policy_id: pid,
                    ..
                } if *rid == rule_id && *pid == policy_id
            )
        })
        .count();
    assert_eq!(
        policy_added_count, 1,
        "[h3] exactly one SaPolicyAdded row with rule_id={rule_id} and \
         policy_id={policy_id} must be present; found {policy_added_count}"
    );

    let policy_added_entry = entries
        .iter()
        .find(|e| {
            matches!(
                &e.event_kind,
                EventKind::SaPolicyAdded { rule_id: rid, .. } if *rid == rule_id
            )
        })
        .expect("[h3] add_policy must emit SaPolicyAdded");

    assert_eq!(
        policy_added_entry.chain_id.as_deref(),
        Some(CHAIN_ID),
        "[h3] SaPolicyAdded row must carry chain_id={CHAIN_ID}; got {:?}",
        policy_added_entry.chain_id
    );
    assert_eq!(
        policy_added_entry.request_id, request_id,
        "[h3] SaPolicyAdded row must carry the request_id used in the call"
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

    // ── Step 9: Assert SaRawInvocation(Success) audit row ────────────────────
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
}

// ── h4_remove_policy_decrements_count_and_emits_audit_row ────────────────────

/// Deploy a fresh smart account, install a rule with 1 policy (policy_addr_a),
/// call `add_policy(policy_addr_b)` to reach `policy_count = 2`, then call
/// `manager.remove_policy` with the `policy_id` returned by `add_policy`,
/// assert `policy_count == 1`, and assert a `SaPolicyRemoved` audit row is
/// emitted.
///
/// # Why two distinct policy contracts are required
///
/// The `add_policy` step that builds the 2-policy state MUST use a DISTINCT
/// address from the one installed in the initial rule: the OpenZeppelin
/// `add_policy` panics with `DuplicatePolicy` when `add_policy` is called with
/// an address already present in the rule.
///
/// Two distinct contracts are deployed with salt suffixes `"h4-policy-a"` and
/// `"h4-policy-b"`.  The rule is installed with `policy_addr_a`; then
/// `add_policy(policy_addr_b)` yields `policy_id_b`.  `remove_policy(policy_id_b)`
/// is then called, returning the rule to `policy_count = 1`.
///
/// # Steps
///
/// 1. Generate + fund operator signer; deploy SA.
/// 2. Deploy two DISTINCT threshold-policy contracts (salts `h4-policy-a`, `h4-policy-b`).
/// 3. Install a 1-policy rule with policy_addr_a.
/// 4. Call `add_policy(policy_addr_b)` to reach `policy_count = 2`; store `policy_id_b`.
/// 5. Precondition guard: assert `policy_count == 2`.
/// 6. Open a fresh `AuditWriter` and call `manager.remove_policy(policy_id_b)`.
/// 7. Fetch the rule; assert `policy_count == 1`.
/// 8. Assert the audit log contains a `SaPolicyRemoved` row with the correct
///    `rule_id`, `policy_id_b`, and `chain_id`.
/// 9. Assert the audit log also contains a `SaRawInvocation(Success)` row.
///
/// # Reference cross-check
///
/// - The OpenZeppelin `remove_policy(context_rule_id, policy_id)`.
/// - The OpenZeppelin `remove_policy` implementation.
/// - The OpenZeppelin `add_policy` `DuplicatePolicy` panic — reason
///   distinct contracts are required for the `add_policy` setup step.
/// - The OpenZeppelin `add_context_rule` accepts
///   `Map<Address, Val>` — unique address keys.
#[tokio::test]
async fn h4_remove_policy_decrements_count_and_emits_audit_row() {
    // ── Step 1: Generate and fund the operator signer ────────────────────────
    let (signer_g, signer_box) = fresh_signer();
    fund_via_friendbot(&signer_g).await;

    let sa_strkey = deploy_fresh_smart_account(&signer_g).await;
    let sa_addr = parse_c_strkey_to_smart_account(&sa_strkey).expect("[h4] SA C-strkey must parse");

    eprintln!("[h4] smart_account = {sa_strkey}");

    // ── Step 2: Deploy two DISTINCT threshold-policy contracts ────────────────
    // policy_addr_a is installed in the initial rule.
    // policy_addr_b is added via add_policy (distinct address required — the
    // OpenZeppelin add_policy panics with DuplicatePolicy if the
    // same address is passed to add_policy for a rule that already contains it).
    let policy_a_strkey =
        deploy_threshold_policy_with_salt(&signer_g, signer_box.as_ref(), "h4-policy-a").await;
    let policy_addr_a = parse_c_strkey_to_smart_account(&policy_a_strkey)
        .expect("[h4] policy_a C-strkey must parse");
    eprintln!("[h4] threshold-policy A = {policy_a_strkey}");

    let policy_b_strkey =
        deploy_threshold_policy_with_salt(&signer_g, signer_box.as_ref(), "h4-policy-b").await;
    let policy_addr_b = parse_c_strkey_to_smart_account(&policy_b_strkey)
        .expect("[h4] policy_b C-strkey must parse");
    eprintln!("[h4] threshold-policy B = {policy_b_strkey}");

    assert_ne!(
        policy_a_strkey, policy_b_strkey,
        "[h4] the two deployed policy addresses must be distinct"
    );

    // ── Step 3: Install 1-policy rule with policy_addr_a ─────────────────────
    let threshold_params = encode_threshold_params(1);
    let signer_addr =
        parse_g_strkey_to_signer_address(&signer_g).expect("[h4] signer G-strkey must parse");

    let rule_manager = fresh_rule_manager();
    let definition = ContextRuleDefinition::new(
        ContextRuleType::Default,
        "h4-rm-policy-test".to_owned(),
        None,
        vec![ContextRuleSignerInput::Delegated {
            address: signer_addr,
        }],
        vec![ContextRulePolicy::new(
            policy_addr_a.clone(),
            threshold_params.clone(),
        )],
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
    eprintln!("[h4] installed 1-policy rule: rule_id = {rule_id}");

    // ── Step 4: Call add_policy(policy_addr_b) to reach policy_count = 2 ─────
    // policy_addr_b is DISTINCT from policy_addr_a, so the DuplicatePolicy
    // guard in the OpenZeppelin add_policy does not fire.
    // The policy_id returned here is the id that remove_policy will target.
    let policy_id_to_remove = rule_manager
        .add_policy(
            sa_addr.clone(),
            rule_id,
            policy_addr_b.clone(),
            threshold_params.clone(),
            vec![ContextRuleId::new(rule_id)],
            signer_box.as_ref(),
            None,
            rid(),
        )
        .await
        .expect("[h4] add_policy(policy_addr_b) must succeed (establishing policy_count=2)");

    eprintln!("[h4] add_policy succeeded: policy_id_to_remove = {policy_id_to_remove}");

    // ── Step 5: Precondition guard — assert policy_count == 2 ────────────────
    let scval_before = rule_manager
        .get_rule(sa_addr.clone(), rule_id, &signer_g)
        .await
        .expect("[h4] get_rule (before remove) must succeed")
        .expect("[h4] rule must be present");

    let count_before = decode_policy_count_from_scval(&scval_before)
        .expect("[h4] decode_policy_count_from_scval must succeed");
    assert_eq!(
        count_before, 2,
        "[h4] precondition guard: must have 2 policies before remove_policy; \
         got {count_before}"
    );
    eprintln!("[h4] precondition guard passed: policy_count = {count_before}");

    // ── Step 6: Open AuditWriter + call remove_policy ─────────────────────────
    let (audit_writer_arc, audit_log_path, _tmp_dir) = tmp_audit_writer();
    let mut audit_writer = audit_writer_arc.lock().expect("audit writer lock");
    let request_id = rid();

    let remove_result = rule_manager
        .remove_policy(
            sa_addr.clone(),
            rule_id,
            policy_id_to_remove,
            vec![ContextRuleId::new(rule_id)],
            signer_box.as_ref(),
            Some(&mut *audit_writer),
            request_id.clone(),
        )
        .await;
    drop(audit_writer);

    remove_result.expect("[h4] remove_policy must succeed on testnet");
    eprintln!("[h4] remove_policy succeeded");

    // ── Step 7: Fetch the rule and assert policy_count == 1 ──────────────────
    let scval_after = rule_manager
        .get_rule(sa_addr.clone(), rule_id, &signer_g)
        .await
        .expect("[h4] get_rule (after remove) must succeed")
        .expect("[h4] rule must still be present");

    let count_after = decode_policy_count_from_scval(&scval_after)
        .expect("[h4] decode_policy_count_from_scval (after) must succeed");
    assert_eq!(
        count_after, 1,
        "[h4] policy_count must be 1 after remove_policy; got {count_after}"
    );
    eprintln!("[h4] post-remove_policy policy_count = {count_after}");

    // ── Step 8: Assert SaPolicyRemoved audit row ──────────────────────────────
    let entries = read_audit_entries(&audit_log_path);
    assert!(
        !entries.is_empty(),
        "[h4] audit log must contain at least one entry after remove_policy"
    );

    let policy_removed_count = entries
        .iter()
        .filter(|e| {
            matches!(
                &e.event_kind,
                EventKind::SaPolicyRemoved {
                    rule_id: rid,
                    policy_id: pid,
                    ..
                } if *rid == rule_id && *pid == policy_id_to_remove
            )
        })
        .count();
    assert_eq!(
        policy_removed_count, 1,
        "[h4] exactly one SaPolicyRemoved row with rule_id={rule_id} and \
         policy_id={policy_id_to_remove} must be present; found {policy_removed_count}"
    );

    let policy_removed_entry = entries
        .iter()
        .find(|e| {
            matches!(
                &e.event_kind,
                EventKind::SaPolicyRemoved { rule_id: rid, .. } if *rid == rule_id
            )
        })
        .expect("[h4] remove_policy must emit SaPolicyRemoved");

    assert_eq!(
        policy_removed_entry.chain_id.as_deref(),
        Some(CHAIN_ID),
        "[h4] SaPolicyRemoved row must carry chain_id={CHAIN_ID}; got {:?}",
        policy_removed_entry.chain_id
    );
    assert_eq!(
        policy_removed_entry.request_id, request_id,
        "[h4] SaPolicyRemoved row must carry the request_id used in the call"
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

    // ── Step 9: Assert SaRawInvocation(Success) audit row ────────────────────
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
}

// ── h5_add_policy_type_mismatched_install_param_no_success_audit ─────────────

/// Supply a `--install-param` that base64-decodes correctly but type-mismatches
/// the threshold-policy contract's expected `SimpleThresholdAccountParams`.
///
/// `ScVal::Bool(true)` is valid XDR and decodes without error; it does NOT
/// match `SimpleThresholdAccountParams { threshold: u32 }` (which the on-chain
/// contract expects as `ScVal::Map([("threshold", ScVal::U32(N))])`).
/// The mismatch is detected at the Soroban simulate phase.
///
/// # Why a DISTINCT second policy address is required
///
/// The OpenZeppelin `add_policy` executes in this order:
///
/// 1. `register_policy(e, policy)` → `policy_id`.
/// 2. `if entry.policy_ids.contains(policy_id) { panic_with_error!(DuplicatePolicy) }`.
/// 3. `PolicyClient::new(e, policy).install(&install_param, ...)`.
///
/// The `DuplicatePolicy` panic fires at step 2, BEFORE the `install` call at
/// step 3 where the type-mismatch would be caught.  If `policy_addr_a`
/// (installed in the rule at install-time) were reused here, the test would
/// receive `DuplicatePolicy` — not the `DeploymentFailed { phase: "simulate" }`
/// error that this test is designed to assert.
///
/// Therefore `policy_addr_b` (salt `"h5-policy-b"`) is deployed as a second
/// distinct address.  `policy_addr_b` is NOT in the rule's `policy_ids` list,
/// so step 2 passes and the `install(&ScVal::Bool(true), ...)` call at step 3
/// triggers the type-mismatch host trap at the simulate phase.
///
/// # Assertions
///
/// 1. `manager.add_policy(...)` returns
///    `Err(SaError::DeploymentFailed { phase: "simulate", .. })`.
/// 2. No `SaPolicyAdded` row is present in the audit log (no audit-row
///    claiming success after a failed operation).
/// 3. Exactly one `SaRawInvocation` row is present with
///    `result: SaInvocationResult::PreSubmissionRefused` (simulate is
///    classified as pre-submission by `sa_error_to_invocation_result`).
///
/// # Steps
///
/// 1. Generate and fund the operator signer.
/// 2. Deploy a fresh smart account.
/// 3. Deploy TWO distinct threshold-policy contracts (salts `h5-policy-a`,
///    `h5-policy-b`).
/// 4. Install a rule with 1 policy (`policy_addr_a`).
/// 5. Open a fresh `AuditWriter`; call `manager.add_policy` with
///    `policy_addr_b` and `install_param = ScVal::Bool(true)`.
/// 6. Assert the call returns `Err` with `DeploymentFailed { phase: "simulate" }`.
/// 7. Assert the audit log has NO `SaPolicyAdded` row.
/// 8. Assert the audit log has exactly one `SaRawInvocation(PreSubmissionRefused)` row.
///
/// # Reference cross-check
///
/// - The OpenZeppelin `add_policy` implementation fires `DuplicatePolicy`
///   before the `install` call. Using a distinct `policy_addr_b` bypasses
///   `DuplicatePolicy` and reaches the `install` call where the type-mismatch
///   is caught.
/// - The OpenZeppelin threshold policy defines
///   `SimpleThresholdAccountParams { threshold: u32 }` with
///   `#[contracttype]` — on-chain contract initialiser expects
///   `ScVal::Map([("threshold", ScVal::U32(N))])`.
/// - The OpenZeppelin `add_policy` invokes the policy installer
///   at simulate time; a type-mismatch surfaces as a Soroban host trap.
/// - `sa_error_to_invocation_result`: `DeploymentFailed { phase: "simulate" }`
///   maps to `SaInvocationResult::PreSubmissionRefused` (simulate is not in
///   the `["submit", "deploy", "upload", "post_deploy_verification"]` set).
/// - The OpenZeppelin `add_context_rule` takes
///   `policies: &Map<Address, Val>` — Soroban Map, unique Address keys.
/// - The Soroban host rejects `ScVal::Map` with
///   duplicate keys (reinforces why duplicate addresses at install-time also
///   fail).
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
    // policy_addr_a is installed in the initial rule.
    // policy_addr_b is used for the adversarial add_policy call (distinct address
    // required — the OpenZeppelin add_policy panics with DuplicatePolicy
    // BEFORE the install call where the type-mismatch would
    // be detected; reusing policy_addr_a would produce DuplicatePolicy, not the
    // DeploymentFailed { phase: "simulate" } error this test asserts).
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

    let rule_manager = fresh_rule_manager();
    let definition = ContextRuleDefinition::new(
        ContextRuleType::Default,
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
    // match `SimpleThresholdAccountParams { threshold: u32 }` expected by the
    // OpenZeppelin threshold-policy contract.
    // The mismatch surfaces as a Soroban host trap at the simulate phase.
    //
    // policy_addr_b (distinct from policy_addr_a) is used so that the DuplicatePolicy
    // guard in the OpenZeppelin add_policy does NOT fire; the test reaches the
    // install call where the type-mismatch is caught at simulate time.
    let mismatched_param = ScVal::Bool(true);

    // ── Step 6: Open AuditWriter + call add_policy with policy_addr_b + mismatched param ──
    let (audit_writer_arc, audit_log_path, _tmp_dir) = tmp_audit_writer();
    let mut audit_writer = audit_writer_arc.lock().expect("[h5] audit writer lock");
    let request_id = rid();

    let result = rule_manager
        .add_policy(
            sa_addr.clone(),
            rule_id,
            policy_addr_b,
            mismatched_param,
            vec![ContextRuleId::new(rule_id)],
            signer_box.as_ref(),
            Some(&mut *audit_writer),
            request_id.clone(),
        )
        .await;
    drop(audit_writer); // release lock before reading

    // ── Step 7: Assert simulate-phase failure ─────────────────────────────────
    // The on-chain contract rejects the malformed install_param at simulate time.
    match &result {
        Err(SaError::DeploymentFailed { phase, .. }) => {
            assert_eq!(
                *phase, "simulate",
                "[h5] failure must occur at the simulate phase; got phase = {phase:?}"
            );
            eprintln!("[h5] simulate-phase failure confirmed: phase = {phase}");
        }
        Ok(policy_id) => {
            panic!(
                "[h5] add_policy must fail with a type-mismatched install_param; \
                 got Ok(policy_id = {policy_id})"
            );
        }
        Err(other) => {
            panic!(
                "[h5] expected DeploymentFailed {{ phase: \"simulate\" }}; \
                 got {other:?}"
            );
        }
    }

    // ── Step 8: Assert NO SaPolicyAdded audit row ─────────────────────────────
    let entries = read_audit_entries(&audit_log_path);

    let policy_added_count = entries
        .iter()
        .filter(|e| matches!(&e.event_kind, EventKind::SaPolicyAdded { .. }))
        .count();
    assert_eq!(
        policy_added_count, 0,
        "[h5] no SaPolicyAdded row must be present after a simulate-phase \
         failure; found {policy_added_count}"
    );
    eprintln!("[h5] confirmed: no SaPolicyAdded row in audit log");

    // ── Step 9: Assert exactly one SaRawInvocation(PreSubmissionRefused) ──────
    // `sa_error_to_invocation_result` maps `DeploymentFailed { phase: "simulate" }`
    // to `PreSubmissionRefused` (simulate is not in the on-chain-rejection phase set).
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
         present after simulate-phase failure; found {pre_sub_refused_count}"
    );
    eprintln!("[h5] confirmed: 1 SaRawInvocation(PreSubmissionRefused) row in audit log");
}
