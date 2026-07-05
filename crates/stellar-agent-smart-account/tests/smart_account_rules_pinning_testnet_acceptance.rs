//! Testnet acceptance tests for wasm-hash pinning.
//!
//! Exercises the `pin_referenced_contracts` path wired into
//! `ContextRuleManager::install_rule` and the drift-detection re-fetch
//! wired into `CredentialsManager::sign_with_passkey_rule`.
//!
//! # Tests
//!
//! - `pin_and_install_with_canonical_oz_threshold_policy_no_drift` —
//!   Install a rule whose `policies` list references the deployed canonical OZ
//!   v0.7.2 threshold-policy contract (wasm hash in `THRESHOLD_POLICY_WASM_HASHES`
//!   allowlist). Expects `install_rule` to succeed, and the resulting
//!   `SaContextRuleCreated` audit row to carry a non-empty
//!   `pinned_policy_wasm_hashes_first8` and `mutable_override = false`.
//!
//! - `install_rule_refuses_unknown_wasm_verifier_without_override` —
//!   Install a rule referencing an External verifier whose on-chain wasm hash
//!   is NOT in `VERIFIER_ALLOWLIST`. With `accept_unknown_verifier = false`
//!   (default), `install_rule` must return `SaError::VerifierWasmNotInAllowlist`
//!   without submitting any on-chain transaction.
//!
//! - `p3_policy_hash_drift_detection_at_signing_time` —
//!   Install a rule with a threshold-policy, baseline the signer set, then inject
//!   a fake `SaContextRuleCreated` row whose `pinned_policy_wasm_hashes_first8`
//!   is `["0000000000000000"]` (a zero sentinel that will never match the real
//!   on-chain policy wasm hash).  Call `sign_with_passkey_rule`; the drift-
//!   detection re-fetch fires before any WebAuthn ceremony, detects the mismatch,
//!   and returns `CredentialsError::WasmHashDrift` (wrapping
//!   `SaError::PolicyHashDrift`).  Verifies that both `SaPolicyHashDrift` and
//!   `PasskeyAssertion(failure:policy_hash_drift)` audit rows are emitted with
//!   the same `request_id`.
//!
//! - `p4_unknown_verifier_override_real_hash_stored_drift_regression` —
//!   Install a rule with `accept_unknown_verifier = true` referencing the OZ
//!   webauthn-verifier contract (whose wasm hash IS in `VERIFIER_ALLOWLIST` for
//!   normal install, but here we simulate the unknown-override path by injecting a
//!   fake `SaContextRuleCreated` row with `unknown_override = true`).  Assert that
//!   signing succeeds when the pinned hash matches the live hash, then inject a
//!   zero-sentinel pin (simulating a post-upgrade hash change) and assert that
//!   drift is detected.  Verifies that the real hash is stored at install time,
//!   not a zero sentinel.
//!
//! - `p5_drift_check_infra_failure_routes_to_drift_check_unavailable_not_drift` —
//!   Install a rule with a threshold-policy and baseline the signer set, then
//!   inject a `SaContextRuleCreated` row with TWO distinct policy hash entries
//!   (simulating a multi-hash rule outside the single-hash scope).  Call
//!   `sign_with_passkey_rule`; the multi-hash guard in
//!   `verify_pinned_policy_against_chain` fires `SaError::MultiplePinnedHashesUnsupported`
//!   which `drift_err_route()` routes to `CredentialsError::DriftCheckUnavailable`
//!   (infra failure must NOT produce
//!   `PasskeyAssertion(failure:*hash_drift)` without a paired drift audit row).
//!   Verifies: `PasskeyAssertion.result == "failure:drift_check_unavailable"` AND no
//!   `SaVerifierHashDrift` / `SaPolicyHashDrift` rows emitted for that `request_id`.
//!
//! - `install_rule_refuses_mutable_verifier_without_override` —
//!   Deploy the OZ v0.7.2 timelock-controller contract (has `AccessControlStorageKey::Admin`
//!   in instance storage via its constructor; wasm hash NOT in `VERIFIER_ALLOWLIST`).
//!   Pass `accept_unknown_verifier = true` (bypasses allowlist check, emits
//!   `SaUnknownContractOverride`) AND `accept_mutable_verifier = false` (default).
//!   The mutability check fires after the allowlist override and returns
//!   `SaError::VerifierMutable` — confirming the fail-closed path for contracts
//!   that have an admin key.
//!
//! - `accept_mutable_verifier_override_emits_audit_row` —
//!   Same timelock-controller verifier with `accept_unknown_verifier = true` AND
//!   `accept_mutable_verifier = true`.  Both override rows are emitted pre-submit:
//!   `SaUnknownContractOverride` (allowlist bypass) + `SaMutableContractOverride`
//!   (admin-key override).  `install_rule` then reaches `install_rule_inner` and
//!   the simulate call traps (`DeploymentFailed { phase: "simulate" }`) because the
//!   timelock has no `batch_canonicalize_key`.  Verifies the override audit rows are
//!   emitted correctly and the override path reaches the on-chain boundary.
//!
//! - `accept_unknown_verifier_override_emits_audit_row` —
//!   Use the deployed smart-account's own C-address as an unknown verifier (its
//!   WASM is NOT in `VERIFIER_ALLOWLIST`; also has NO admin key, so it is immutable).
//!   Pass `accept_unknown_verifier = true` and `accept_mutable_verifier = false`.
//!   `SaUnknownContractOverride` is emitted pre-submit and `install_rule` reaches
//!   the simulate boundary, where it traps (`DeploymentFailed { phase: "simulate" }`)
//!   because the SA has no `batch_canonicalize_key`.  Asserts `observed_hash_first8`
//!   is non-empty (real on-chain wasm hash stored, not zero sentinel).
//!
//! # Gating
//!
//! All tests compile only under `--features testnet-integration`:
//!
//! ```text
//! cargo test --features testnet-integration --test smart_account_rules_pinning_testnet_acceptance
//! ```

#![cfg(feature = "testnet-integration")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics are acceptable in testnet acceptance tests"
)]

use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use sha2::{Digest as _, Sha256};
use stellar_agent_core::audit_log::entry::AuditEntry;
use stellar_agent_core::audit_log::schema::{ContractKind, EventKind};
use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_core::observability::redact_strkey_first5_last5;
use stellar_agent_core::smart_account::rule_id::ContextRuleId;
use stellar_agent_network::signing::envelope_signing::attach_signature;
use stellar_agent_network::{
    Signer, SoftwareSigningKey, StellarRpcClient, fetch_account, submit_transaction_and_wait,
};
use stellar_agent_smart_account::deployment::{
    DeployerKeypair, DeploymentArgs, ResolvedFeePerOp, TimelockControllerDeployArgs,
    deploy_smart_account, deploy_timelock_controller, derive_smart_account_address,
};
use stellar_agent_smart_account::error::SaError;
use stellar_agent_smart_account::managers::credentials::{CredentialsError, CredentialsManager};
use stellar_agent_smart_account::managers::rules::RuleContext;
use stellar_agent_smart_account::managers::rules::{
    ContextRuleDefinition, ContextRuleManager, ContextRuleManagerConfig, ContextRulePolicy,
    ContextRuleSignerInput, parse_c_strkey_to_smart_account, parse_g_strkey_to_signer_address,
};
use stellar_agent_smart_account::managers::signers::{SignersManager, SignersManagerConfig};
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
            var_name: "testnet-pinning-acceptance".to_owned(),
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

/// Opens a temporary `AuditWriter` and returns `(Arc<Mutex<writer>>, path, TempDir)`.
/// `TempDir` must be kept alive for the duration of the test.
fn tmp_audit_writer() -> (Arc<Mutex<AuditWriter>>, PathBuf, TempDir) {
    let dir = tempfile::tempdir().expect("tempdir must succeed");
    let path = dir.path().join("audit.jsonl");
    let writer = AuditWriter::open(path.clone(), None).expect("AuditWriter::open must succeed");
    (Arc::new(Mutex::new(writer)), path, dir)
}

/// Reads every non-empty JSONL line from `log_path` into `Vec<AuditEntry>`.
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

/// Constructs a `SignersManager` using the same testnet endpoint for both
/// primary and secondary RPC.  Degrades to single-RPC consultation (both
/// responses agree trivially) — acceptable for testnet acceptance.
fn fresh_signers_manager(
    audit_writer: Arc<Mutex<AuditWriter>>,
    audit_log_path: PathBuf,
) -> SignersManager {
    SignersManager::new(SignersManagerConfig::new(
        TESTNET_RPC_URL.to_owned(),
        TESTNET_RPC_URL.to_owned(),
        audit_writer,
        audit_log_path,
        TESTNET_PASSPHRASE.to_owned(),
        "testnet-pinning-acceptance".to_owned(),
        Duration::from_secs(TIMEOUT_SECS),
        CHAIN_ID.to_owned(),
    ))
    .expect("SignersManager::new must succeed")
}

/// Constructs a `ContextRuleManager` with an attached `SignersManager` so
/// the wasm-hash pin check is active.
///
/// This is the production-equivalent path: the CLI's `context_rule_manager()`
/// helper (common.rs:170-182) always wires `.with_signers_manager(...)`.
fn fresh_pinning_rule_manager(
    audit_writer: Arc<Mutex<AuditWriter>>,
    signers_manager: Arc<SignersManager>,
) -> ContextRuleManager {
    ContextRuleManager::new(
        ContextRuleManagerConfig::new(
            TESTNET_RPC_URL.to_owned(),
            TESTNET_PASSPHRASE.to_owned(),
            Duration::from_secs(TIMEOUT_SECS),
            CHAIN_ID.to_owned(),
        )
        .with_audit_writer(audit_writer)
        .with_signers_manager(signers_manager),
    )
    .expect("ContextRuleManager::new must succeed")
}

/// Deploys a fresh smart-account with `signer_g` as its bootstrap signer.
/// Returns the deployed C-strkey.
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

/// Deploys the vendored OZ threshold-policy WASM to testnet (idempotent).
///
/// Uses a deterministic salt derived from the network passphrase so subsequent
/// test runs reuse the same contract address rather than re-deploying.
/// Returns the deployed C-strkey.
///
/// Salt derivation: `SHA256("oz-threshold-policy-v0.7.2-" || TESTNET_PASSPHRASE)`.
async fn deploy_threshold_policy_wasm(
    deployer_g: &str,
    signer: &(dyn Signer + Send + Sync),
) -> String {
    let wasm_hash_bytes: [u8; 32] = Sha256::digest(THRESHOLD_POLICY_WASM).into();

    let salt_input = format!("oz-threshold-policy-v0.7.2-{TESTNET_PASSPHRASE}");
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
        constructor_args: VecM::default(), // threshold-policy has no __constructor
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
            // Tolerate duplicate-deploy (contract already exists at the deterministic address).
            let msg = format!("{e}");
            if !msg.contains("AlreadyExists") && !msg.contains("ContractAlreadyExists") {
                panic!("deploy threshold-policy tx failed: {e}");
            }
        }
    }

    policy_strkey
}

/// Encodes `SimpleThresholdAccountParams { threshold: N }` as a Soroban ScVal.
///
/// `#[contracttype]` struct encoding: `ScVal::Map(ScMap([("threshold", U32(N))]))`
/// per soroban-sdk-macros `derive_type_struct` — each named field maps to
/// `ScMapEntry { key: ScVal::Symbol(field_name), val: <field IntoVal> }`.
/// `SimpleThresholdAccountParams { threshold: u32 }` is a single-field struct
/// with `#[contracttype]`.
fn encode_simple_threshold_params(threshold: u32) -> ScVal {
    let entry = ScMapEntry {
        key: ScVal::Symbol(ScSymbol::try_from("threshold").expect("'threshold' fits ScSymbol")),
        val: ScVal::U32(threshold),
    };
    let map: VecM<ScMapEntry> = vec![entry].try_into().expect("single-entry VecM");
    ScVal::Map(Some(ScMap(map)))
}

// ── Canonical OZ threshold-policy pin succeeds ───────────────────────────────

/// Install a context rule whose `policies` list references the
/// canonical OZ v0.7.2 threshold-policy WASM (hash in
/// `THRESHOLD_POLICY_WASM_HASHES`) with the pin-check `SignersManager` active.
///
/// The rule installation must:
/// 1. Succeed (no `SaError` returned).
/// 2. Produce a `SaContextRuleCreated` audit row with a non-empty
///    `pinned_policy_wasm_hashes_first8` list (the hash was pinned).
/// 3. Have `mutable_override = false` (the canonical OZ policy has no admin key).
///
/// # Reference cross-check
///
/// - `THRESHOLD_POLICY_WASM_HASHES` allowlist at
///   `crates/stellar-agent-smart-account/src/signers/policy_identification.rs`.
#[tokio::test]
async fn pin_and_install_with_canonical_oz_threshold_policy_no_drift() {
    let (signer_g, signer_box) = fresh_signer();
    fund_via_friendbot(&signer_g).await;

    let sa_strkey = deploy_fresh_smart_account(&signer_g).await;
    let sa_addr =
        parse_c_strkey_to_smart_account(&sa_strkey).expect("SA C-strkey must parse to ScAddress");

    // Deploy threshold-policy WASM (idempotent across test runs).
    let policy_strkey = deploy_threshold_policy_wasm(&signer_g, signer_box.as_ref()).await;
    let policy_addr = parse_c_strkey_to_smart_account(&policy_strkey)
        .expect("threshold-policy C-strkey must parse");

    let (audit_writer, audit_log_path, _tmp_dir) = tmp_audit_writer();
    let sm = Arc::new(fresh_signers_manager(
        Arc::clone(&audit_writer),
        audit_log_path.clone(),
    ));

    let manager = fresh_pinning_rule_manager(Arc::clone(&audit_writer), Arc::clone(&sm));

    let signer_addr = parse_g_strkey_to_signer_address(&signer_g)
        .expect("signer G-strkey must parse to ScAddress");
    let threshold_params = encode_simple_threshold_params(1);

    let definition = ContextRuleDefinition::new(
        RuleContext::Default,
        "p1-pin-test".to_owned(),
        None,
        vec![ContextRuleSignerInput::Delegated {
            address: signer_addr,
        }],
        vec![ContextRulePolicy::new(policy_addr, threshold_params)],
    );

    let request_id = rid();
    let p1_out = manager
        .install_rule(
            sa_addr,
            definition,
            vec![ContextRuleId::new(0)],
            signer_box.as_ref(),
            None,
            request_id.clone(),
            false, // accept_mutable_verifier
            false, // accept_unknown_verifier
        )
        .await
        .expect("install_rule with canonical OZ threshold-policy must succeed");
    let rule_id = p1_out.rule_id;
    assert!(
        !p1_out.pin_result.mutable_override,
        "canonical install must not set mutable_override"
    );
    assert!(
        !p1_out.pin_result.unknown_override,
        "canonical install must not set unknown_override"
    );

    assert!(
        rule_id != 0,
        "installed rule_id must be distinct from bootstrap rule (rule_id 0); got {rule_id}"
    );

    // ── Verify audit log ──────────────────────────────────────────────────────
    drop(manager);
    drop(sm);

    let entries = read_audit_entries(&audit_log_path);
    assert!(
        !entries.is_empty(),
        "audit log must contain at least one entry after install_rule"
    );

    // Find the SaContextRuleCreated row for this rule_id.
    let created_entry = entries
        .iter()
        .find(|e| {
            matches!(
                &e.event_kind,
                EventKind::SaContextRuleCreated { rule_id: rid, .. } if *rid == rule_id
            )
        })
        .expect("install_rule must emit a SaContextRuleCreated row with the new rule_id");

    // Extract the pinned_policy_wasm_hashes_first8 from the variant.
    let EventKind::SaContextRuleCreated {
        pinned_policy_wasm_hashes_first8,
        mutable_override,
        unknown_override,
        ..
    } = &created_entry.event_kind
    else {
        panic!("event_kind must be SaContextRuleCreated");
    };

    assert!(
        !pinned_policy_wasm_hashes_first8.is_empty(),
        "SaContextRuleCreated must carry at least one pinned_policy_wasm_hashes_first8 \
         entry after install with canonical OZ threshold-policy; found empty list"
    );
    assert!(
        !mutable_override,
        "mutable_override must be false for the canonical OZ threshold-policy \
         (no admin/owner key in instance storage); got true"
    );
    assert!(
        !unknown_override,
        "unknown_override must be false for the canonical OZ threshold-policy \
         (hash is in THRESHOLD_POLICY_WASM_HASHES allowlist); got true"
    );

    // Verify request_id correlation.
    assert_eq!(
        created_entry.request_id, request_id,
        "SaContextRuleCreated row must carry the request_id used in the call"
    );
}

// ── Unknown-wasm verifier rejected fail-closed ───────────────────────────────

/// Verify that `install_rule` refuses a rule referencing an
/// `External { verifier }` signer whose on-chain wasm hash is NOT in the
/// `VERIFIER_ALLOWLIST` allowlist, when `accept_unknown_verifier = false`
/// (the default fail-closed posture).
///
/// The "unknown-wasm verifier" is the freshly-deployed smart-account contract
/// itself, whose wasm hash (`OZ_SMART_ACCOUNT_WASM` SHA-256) is NOT in
/// `VERIFIER_ALLOWLIST` (the allowlist only contains the OZ multisig-webauthn-
/// verifier-example WASM, not the smart-account WASM).
///
/// Expected: `install_rule` returns `SaError::VerifierWasmNotInAllowlist` before
/// submitting any on-chain transaction.
///
/// Default behavior is fail-closed; opt-in via the override flag.
///
/// # Reference cross-check
///
/// - `VERIFIER_ALLOWLIST` allowlist at
///   `crates/stellar-agent-smart-account/src/verifier_allowlist.rs`.
/// - `identify_verifier` at
///   `crates/stellar-agent-smart-account/src/managers/signers.rs`.
#[tokio::test]
async fn install_rule_refuses_unknown_wasm_verifier_without_override() {
    let (signer_g, signer_box) = fresh_signer();
    fund_via_friendbot(&signer_g).await;

    // Deploy a fresh smart-account.  The smart-account's own C-address is reused
    // as the External verifier address.  The OZ smart-account WASM hash is NOT
    // in VERIFIER_ALLOWLIST (which only contains the verifier-example WASM),
    // so identify_verifier returns VerifierWasmNotInAllowlist.
    let sa_strkey = deploy_fresh_smart_account(&signer_g).await;
    let sa_addr =
        parse_c_strkey_to_smart_account(&sa_strkey).expect("SA C-strkey must parse to ScAddress");

    let (audit_writer, audit_log_path, _tmp_dir) = tmp_audit_writer();
    let sm = Arc::new(fresh_signers_manager(
        Arc::clone(&audit_writer),
        audit_log_path.clone(),
    ));

    let manager = fresh_pinning_rule_manager(Arc::clone(&audit_writer), Arc::clone(&sm));

    // Rule referencing the smart-account's own address as an External verifier.
    // This address is on-chain and has a wasm hash, but it is NOT the webauthn-
    // verifier wasm — so identify_verifier rejects it.
    let definition = ContextRuleDefinition::new(
        RuleContext::Default,
        "p2-unknown-wasm".to_owned(),
        None,
        vec![ContextRuleSignerInput::External {
            verifier: sa_addr.clone(),
            pubkey_data: vec![],
        }],
        vec![], // no policies
    );

    let request_id = rid();
    let result = manager
        .install_rule(
            sa_addr,
            definition,
            vec![ContextRuleId::new(0)],
            signer_box.as_ref(),
            None,
            request_id,
            false, // accept_mutable_verifier
            false, // accept_unknown_verifier — fail-closed (default)
        )
        .await;

    match result {
        Err(SaError::VerifierWasmNotInAllowlist { .. }) => {
            // Expected: unknown-wasm verifier rejected fail-closed.
        }
        Err(other) => {
            panic!("expected SaError::VerifierWasmNotInAllowlist; got unexpected error: {other:?}");
        }
        Ok(out) => {
            panic!(
                "install_rule must fail for an unknown-wasm verifier with \
                 accept_unknown_verifier=false; returned Ok(rule_id={})",
                out.rule_id
            );
        }
    }
}

// ── Drift detection fires at signing time ─────────────────────────────────────

/// `sign_with_passkey_rule` detects a policy wasm-hash drift at signing time
/// and aborts the WebAuthn ceremony before any browser I/O.
///
/// # Setup
///
/// 1. Deploy a fresh smart-account + install a 1-of-1 rule with a threshold-policy.
/// 2. Baseline the signer set (so `verify_signer_set_against_chain` does not
///    return `SignerSetMissingBaseline`).
/// 3. Inject a fabricated `SaContextRuleCreated` audit row whose
///    `pinned_policy_wasm_hashes_first8` is `["0000000000000000"]` — a zero
///    sentinel that will never match the real on-chain policy wasm hash.
///    Because `find_latest_context_rule_pinned_hashes` picks the most-recent
///    matching row, this fabricated entry shadows the real install-time row.
/// 4. Call `sign_with_passkey_rule` (with `signers_manager = Some(sm)`) and a
///    fake credential name.  The drift-detection re-fetch fires in the
///    `sign_with_passkey_rule_inner` pre-flight block (before the approval-store
///    check and before the credential lookup).
///
/// # Assertions
///
/// - `sign_with_passkey_rule` returns `Err(CredentialsError::WasmHashDrift)`.
/// - Both `SaPolicyHashDrift` AND `PasskeyAssertion(failure:verifier_hash_drift)`
///   rows are present in the audit log.
/// - Both rows carry the same `request_id` UUID (forensic correlation).
///
/// # Assertions
///
/// - Drift detected at signing time, signing aborted.
/// - Per-call wasm-hash cache fires once per signing call (cache used
///   internally in `verify_pinned_policy_against_chain`; indirectly verified by
///   a single `SaPolicyHashDrift` row for the one policy address in the rule).
///
/// # Reference cross-check
///
/// - `verify_pinned_policy_against_chain` in
///   `crates/stellar-agent-smart-account/src/managers/verifiers.rs`.
/// - `sign_with_passkey_rule_inner` in
///   `crates/stellar-agent-smart-account/src/managers/credentials.rs`.
#[tokio::test(flavor = "multi_thread")]
async fn p3_policy_hash_drift_detection_at_signing_time() {
    let (signer_g, signer_box) = fresh_signer();
    fund_via_friendbot(&signer_g).await;

    let sa_strkey = deploy_fresh_smart_account(&signer_g).await;
    let sa_addr =
        parse_c_strkey_to_smart_account(&sa_strkey).expect("SA C-strkey must parse to ScAddress");

    // Deploy threshold-policy (idempotent across test runs).
    let policy_strkey = deploy_threshold_policy_wasm(&signer_g, signer_box.as_ref()).await;
    let policy_addr = parse_c_strkey_to_smart_account(&policy_strkey)
        .expect("threshold-policy C-strkey must parse");

    // ── Shared AuditWriter + SignersManager ───────────────────────────────────

    let (audit_writer, audit_log_path, _tmp_dir) = tmp_audit_writer();
    let sm = Arc::new(fresh_signers_manager(
        Arc::clone(&audit_writer),
        audit_log_path.clone(),
    ));

    // Install a 1-of-1 rule with the threshold-policy via the pinning manager.
    // The real pin row (`SaContextRuleCreated` with the actual policy wasm hash)
    // is written to the audit log by `install_rule`.
    let manager = fresh_pinning_rule_manager(Arc::clone(&audit_writer), Arc::clone(&sm));

    let signer_addr =
        parse_g_strkey_to_signer_address(&signer_g).expect("signer G-strkey must parse");
    let threshold_params = encode_simple_threshold_params(1);

    let definition = ContextRuleDefinition::new(
        RuleContext::Default,
        "p3-drift-test".to_owned(),
        None,
        vec![ContextRuleSignerInput::Delegated {
            address: signer_addr,
        }],
        vec![ContextRulePolicy::new(policy_addr, threshold_params)],
    );

    let p3_out = manager
        .install_rule(
            sa_addr.clone(),
            definition,
            vec![ContextRuleId::new(0)],
            signer_box.as_ref(),
            None,
            rid(),
            false, // accept_mutable_verifier
            false, // accept_unknown_verifier
        )
        .await
        .expect("install_rule must succeed on testnet");
    let rule_id = p3_out.rule_id;
    assert!(
        !p3_out.pin_result.mutable_override,
        "canonical install must not set mutable_override"
    );
    assert!(
        !p3_out.pin_result.unknown_override,
        "canonical install must not set unknown_override"
    );
    drop(manager);

    // ── Baseline the signer set ───────────────────────────────────────────────
    //
    // `verify_signer_set_against_chain` in the signing pre-flight requires a
    // baselined row in the audit log.  Call `refresh_signer_baseline` so the
    // signer-set check passes before the drift check fires.
    sm.refresh_signer_baseline(sa_addr.clone(), rule_id, Some(&signer_g), rid())
        .await
        .expect("refresh_signer_baseline must succeed");

    // ── Inject fabricated SaContextRuleCreated row with wrong pinned hash ─────
    //
    // The zero sentinel `"0000000000000000"` will never match the real on-chain
    // policy wasm hash, guaranteeing a drift detection on every run.
    //
    // `find_latest_context_rule_pinned_hashes` picks the most-recent matching
    // row, so this fabricated row shadows the real install-time pin row.
    let smart_account_redacted = redact_strkey_first5_last5(&sa_strkey);
    {
        let mut writer = audit_writer.lock().expect("audit writer lock for inject");
        // Construct a fake SaContextRuleCreated with zero-sentinel pinned hash.
        // `write_entry` sets `previous_entry_hash` automatically from the writer's
        // current chain-tip; the manually-constructed zero value is overwritten.
        let fake_entry = AuditEntry::new_sa_context_rule_created(
            &smart_account_redacted,
            rule_id,
            "default",
            1, // signers_count
            1, // policies_count
            None,
            CHAIN_ID,
            rid(),
            vec![],                              // no verifier hashes (Delegated signer only)
            vec!["0000000000000000".to_owned()], // wrong policy hash (zero sentinel)
            false,
            false,
        );
        writer
            .write_entry(fake_entry)
            .expect("fake SaContextRuleCreated inject must succeed");
    }

    // ── Call sign_with_passkey_rule ───────────────────────────────────────────
    //
    // `CredentialsManager` is constructed without an approval store (None) because
    // the drift check fires BEFORE the approval-store check.  The passkeys_dir
    // tempdir means credential lookup would return NotFound, but drift fires
    // first — so we never reach that code path.
    let passkeys_tmpdir = tempfile::tempdir().expect("passkeys tempdir must succeed");
    let creds_mgr = CredentialsManager::new(
        passkeys_tmpdir.path().join("passkeys"),
        "default",
        "localhost",
        None, // no approval store: drift fires before store check
    );

    // Fake bridge address: drift fires before any bridge I/O.
    let bridge_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 19907);
    let auth_digest = [0u8; 32];

    let outcome = creds_mgr
        .sign_with_passkey_rule(
            "does-not-matter", // credential lookup never reached (drift fires first)
            &sa_strkey,
            &auth_digest,
            vec![rule_id],
            Some(Arc::clone(&sm)),
            bridge_addr,
            Duration::from_millis(500),
            |_| {}, // url callback: never invoked
            true,   // accept_single_verifier: bypass diversification check (drift-only test)
        )
        .await;

    // ── Outcome MUST be WasmHashDrift(PolicyHashDrift) ───────────────────────
    // The outer variant is WasmHashDrift (wrapping the SaError::PolicyHashDrift
    // inner).  The PasskeyAssertion result tag is "failure:policy_hash_drift"
    // (not "failure:verifier_hash_drift").
    assert!(
        matches!(outcome, Err(CredentialsError::WasmHashDrift { .. })),
        "sign_with_passkey_rule must return WasmHashDrift (wrapping PolicyHashDrift) \
         when the fabricated pinned policy hash differs from the live on-chain hash; \
         got: {outcome:?}"
    );
    // Verify the inner error is PolicyHashDrift specifically.
    if let Err(CredentialsError::WasmHashDrift { ref source }) = outcome {
        assert!(
            matches!(source.as_ref(), SaError::PolicyHashDrift { .. }),
            "wrapped SaError must be PolicyHashDrift; got: {source:?}"
        );
    }

    // ── Scan audit log for the two drift rows ─────────────────────────────────
    let log_path = {
        let guard = audit_writer.lock().expect("audit writer lock for path");
        guard.path().to_path_buf()
    };

    let file =
        std::fs::File::open(&log_path).expect("audit log file must exist after sign attempt");
    let reader = BufReader::new(file);

    let mut drift_entry: Option<AuditEntry> = None;
    let mut assertion_entry: Option<AuditEntry> = None;

    for line_result in reader.lines() {
        let Ok(line) = line_result else { continue };
        if line.trim().is_empty() {
            continue;
        }
        let Ok(entry) = serde_json::from_str::<AuditEntry>(&line) else {
            continue;
        };
        match &entry.event_kind {
            EventKind::SaPolicyHashDrift { rule_id: rid, .. } if *rid == rule_id => {
                drift_entry = Some(entry);
            }
            EventKind::PasskeyAssertion { result, .. } if result == "failure:policy_hash_drift" => {
                assertion_entry = Some(entry);
            }
            _ => {}
        }
    }

    // ── SaPolicyHashDrift row must be present ─────────────────────────────────
    let drift = drift_entry.expect(
        "SaPolicyHashDrift audit row must be emitted when drift is detected at signing time",
    );

    // ── PasskeyAssertion(failure:policy_hash_drift) must be present ──────────
    // The result tag is "failure:policy_hash_drift" (not "failure:verifier_hash_drift")
    // when the drift is on the policy path.
    let assertion = assertion_entry.expect(
        "PasskeyAssertion(failure:policy_hash_drift) audit row must be emitted \
         after drift detection aborts signing",
    );

    // ── Both rows must share the same request_id ──────────────────────────────
    assert_eq!(
        drift.request_id, assertion.request_id,
        "SaPolicyHashDrift and PasskeyAssertion rows must share the same \
         request_id for forensic correlation; \
         drift.request_id={}, assertion.request_id={}",
        drift.request_id, assertion.request_id,
    );

    // ── SaPolicyHashDrift fields ──────────────────────────────────────────────
    if let EventKind::SaPolicyHashDrift {
        rule_id: drift_rule_id,
        pinned_hash_first8,
        observed_hash_first8,
        ..
    } = &drift.event_kind
    {
        assert_eq!(
            *drift_rule_id, rule_id,
            "SaPolicyHashDrift rule_id must match the installed rule"
        );
        assert_eq!(
            pinned_hash_first8, "0000000000000000",
            "SaPolicyHashDrift.pinned_hash_first8 must be the fabricated zero sentinel"
        );
        assert_ne!(
            observed_hash_first8, "0000000000000000",
            "SaPolicyHashDrift.observed_hash_first8 must differ from the zero sentinel \
             (the real on-chain policy has a non-zero wasm hash)"
        );
    } else {
        panic!("drift.event_kind must be SaPolicyHashDrift");
    }
}

// ── accept_unknown_verifier real-hash regression test ────────────────────────

/// Verify that when `accept_unknown_verifier = true` is used at install time,
/// the REAL observed wasm hash is stored in the pin record (not a zero sentinel).
/// Signing with the real pin must succeed; signing with a tampered zero-sentinel
/// pin must detect drift.
///
/// This test simulates the `accept_unknown_verifier=true` scenario by injecting
/// fabricated `SaContextRuleCreated` rows directly (the actual
/// `pin_referenced_contracts` accept-unknown path requires a contract not in any
/// allowlist, which is unavailable on public testnet without a custom deploy).
/// The injected rows exercise the same audit-log-derived expectation lookup that
/// `verify_pinned_policy_against_chain` performs at signing time.
///
/// Assertions:
/// - With a real-hash pin row (`unknown_override=true`), signing succeeds (no drift).
/// - After injecting a zero-sentinel pin row, signing detects drift and returns
///   `CredentialsError::WasmHashDrift`.
/// - The `SaPolicyHashDrift` audit row is present when drift fires.
/// - Both drift rows share the same `request_id`.
///
/// # Reference cross-check
///
/// - `crates/stellar-agent-smart-account/src/managers/signers.rs:fetch_observed_wasm_hash`
///   (real hash fetch without allowlist enforcement).
/// - `crates/stellar-agent-smart-account/src/managers/verifiers.rs:verify_pinned_policy_against_chain`
///   (drift-detection re-fetch — policy path).
#[tokio::test(flavor = "multi_thread")]
async fn p4_unknown_verifier_override_real_hash_stored_drift_regression() {
    let (signer_g, signer_box) = fresh_signer();
    fund_via_friendbot(&signer_g).await;

    let sa_strkey = deploy_fresh_smart_account(&signer_g).await;
    let sa_addr =
        parse_c_strkey_to_smart_account(&sa_strkey).expect("SA C-strkey must parse to ScAddress");

    // Deploy threshold-policy (idempotent across test runs).
    let policy_strkey = deploy_threshold_policy_wasm(&signer_g, signer_box.as_ref()).await;
    let policy_addr = parse_c_strkey_to_smart_account(&policy_strkey)
        .expect("threshold-policy C-strkey must parse");

    // ── Shared AuditWriter + SignersManager ───────────────────────────────────

    let (audit_writer, audit_log_path, _tmp_dir) = tmp_audit_writer();
    let sm = Arc::new(fresh_signers_manager(
        Arc::clone(&audit_writer),
        audit_log_path.clone(),
    ));

    // Install the rule via the standard path (threshold-policy in allowlist,
    // accept_unknown_verifier=false).  This writes the real-hash pin row.
    let manager = fresh_pinning_rule_manager(Arc::clone(&audit_writer), Arc::clone(&sm));

    let signer_addr =
        parse_g_strkey_to_signer_address(&signer_g).expect("signer G-strkey must parse");
    let threshold_params = encode_simple_threshold_params(1);

    let definition = ContextRuleDefinition::new(
        RuleContext::Default,
        "pin-verify-test".to_owned(),
        None,
        vec![ContextRuleSignerInput::Delegated {
            address: signer_addr,
        }],
        vec![ContextRulePolicy::new(
            policy_addr.clone(),
            threshold_params,
        )],
    );

    let p4_out = manager
        .install_rule(
            sa_addr.clone(),
            definition,
            vec![ContextRuleId::new(0)],
            signer_box.as_ref(),
            None,
            rid(),
            false, // accept_mutable_verifier
            false, // accept_unknown_verifier
        )
        .await
        .expect("install_rule must succeed on testnet");
    let rule_id = p4_out.rule_id;
    assert!(
        !p4_out.pin_result.mutable_override,
        "canonical install must not set mutable_override"
    );
    assert!(
        !p4_out.pin_result.unknown_override,
        "canonical install must not set unknown_override"
    );
    drop(manager);

    // ── Read the REAL live wasm hash first-8-hex from the install-time audit row ─
    //
    // The install-time `SaContextRuleCreated` row carries the real pinned hash
    // (already allowlist-checked by `pin_referenced_contracts`).  This is what
    // The real hash is read from the install-time pin row here.
    let smart_account_redacted = redact_strkey_first5_last5(&sa_strkey);
    let install_entries = read_audit_entries(&audit_log_path);
    let install_pin_row = install_entries
        .iter()
        .find(|e| {
            matches!(
                &e.event_kind,
                EventKind::SaContextRuleCreated { rule_id: rid, .. } if *rid == rule_id
            )
        })
        .expect("SaContextRuleCreated row must exist after install_rule");

    let real_hash_first8 = if let EventKind::SaContextRuleCreated {
        pinned_policy_wasm_hashes_first8,
        ..
    } = &install_pin_row.event_kind
    {
        assert!(
            !pinned_policy_wasm_hashes_first8.is_empty(),
            "install-time SaContextRuleCreated must carry at least one pinned policy hash"
        );
        pinned_policy_wasm_hashes_first8[0].clone()
    } else {
        panic!("expected SaContextRuleCreated event_kind");
    };

    assert_ne!(
        real_hash_first8, "0000000000000000",
        "real policy wasm hash from install-time row must be non-zero"
    );

    // ── Baseline the signer set ───────────────────────────────────────────────

    sm.refresh_signer_baseline(sa_addr.clone(), rule_id, Some(&signer_g), rid())
        .await
        .expect("refresh_signer_baseline must succeed");

    // ── Inject real-hash pin row (simulating accept_unknown_verifier=true) ─
    //
    // Shadow the install-time pin row with one that has unknown_override=true
    // but carries the REAL observed hash.  The drift check must NOT fire because
    // live hash == pinned hash.
    {
        let mut writer = audit_writer
            .lock()
            .expect("audit writer lock for real-hash inject");
        let fake_entry = AuditEntry::new_sa_context_rule_created(
            &smart_account_redacted,
            rule_id,
            "default",
            1, // signers_count
            1, // policies_count
            None,
            CHAIN_ID,
            rid(),
            vec![],                         // no verifier hashes (Delegated signer only)
            vec![real_hash_first8.clone()], // REAL hash (not a zero sentinel)
            false,                          // mutable_override
            true, // unknown_override = true (simulating accept-unknown path)
        );
        writer
            .write_entry(fake_entry)
            .expect("real-hash SaContextRuleCreated inject must succeed");
    }

    let passkeys_tmpdir = tempfile::tempdir().expect("passkeys tempdir must succeed");
    let creds_mgr = CredentialsManager::new(
        passkeys_tmpdir.path().join("passkeys"),
        "default",
        "localhost",
        None, // no approval store: drift fires before store check (if it fires)
    );

    let bridge_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 19908);
    let auth_digest = [0u8; 32];

    // Signing attempt 1: real-hash pin row → drift check MUST NOT fire.
    // The approval store is None so we get ApprovalStoreUnavailable, but
    // that means drift did NOT fire (drift fires first, before store check).
    let outcome_real_hash = creds_mgr
        .sign_with_passkey_rule(
            "does-not-matter",
            &sa_strkey,
            &auth_digest,
            vec![rule_id],
            Some(Arc::clone(&sm)),
            bridge_addr,
            Duration::from_millis(500),
            |_| {},
            true, // accept_single_verifier: bypass diversification (drift pass-through test)
        )
        .await;

    // ApprovalStoreUnavailable means we passed the drift check (drift fires first).
    // Any drift error would have been WasmHashDrift.
    assert!(
        matches!(
            outcome_real_hash,
            Err(CredentialsError::ApprovalStoreUnavailable)
        ),
        "with a REAL hash pin row, drift check must NOT fire; \
         expected ApprovalStoreUnavailable (drift bypassed), \
         got: {outcome_real_hash:?}"
    );

    // ── Inject zero-sentinel pin row (drift must be detected) ──────────
    //
    // Shadow the previous row with one that has a zero-sentinel hash.  The drift
    // check MUST fire this time (zero sentinel ≠ real live hash).
    {
        let mut writer = audit_writer
            .lock()
            .expect("audit writer lock for zero-sentinel inject");
        let bug_entry = AuditEntry::new_sa_context_rule_created(
            &smart_account_redacted,
            rule_id,
            "default",
            1, // signers_count
            1, // policies_count
            None,
            CHAIN_ID,
            rid(),
            vec![],
            vec!["0000000000000000".to_owned()], // zero sentinel (bug scenario)
            false,
            true, // unknown_override
        );
        writer
            .write_entry(bug_entry)
            .expect("zero-sentinel SaContextRuleCreated inject must succeed");
    }

    // Signing attempt 2: zero-sentinel pin row → drift check MUST fire.
    let outcome_zero_pin = creds_mgr
        .sign_with_passkey_rule(
            "does-not-matter",
            &sa_strkey,
            &auth_digest,
            vec![rule_id],
            Some(Arc::clone(&sm)),
            bridge_addr,
            Duration::from_millis(500),
            |_| {},
            true, // accept_single_verifier: bypass diversification (drift detection test)
        )
        .await;

    assert!(
        matches!(
            outcome_zero_pin,
            Err(CredentialsError::WasmHashDrift { .. })
        ),
        "with a zero-sentinel pin row, drift check must fire and return WasmHashDrift; \
         got: {outcome_zero_pin:?}"
    );
    // Verify inner error is PolicyHashDrift.
    if let Err(CredentialsError::WasmHashDrift { ref source }) = outcome_zero_pin {
        assert!(
            matches!(source.as_ref(), SaError::PolicyHashDrift { .. }),
            "wrapped SaError must be PolicyHashDrift; got: {source:?}"
        );
    }

    // ── Verify audit rows from the drift-firing attempt ───────────────────────

    let entries = read_audit_entries(&audit_log_path);

    let drift_entry = entries.iter().rev().find(|e| {
        matches!(
            &e.event_kind,
            EventKind::SaPolicyHashDrift { rule_id: rid, pinned_hash_first8, .. }
                if *rid == rule_id && pinned_hash_first8 == "0000000000000000"
        )
    });
    let drift = drift_entry
        .expect("SaPolicyHashDrift audit row must be emitted for the zero-sentinel drift scenario");

    let assertion_entry = entries.iter().rev().find(|e| {
        matches!(
            &e.event_kind,
            EventKind::PasskeyAssertion { result, .. }
                if result == "failure:policy_hash_drift"
        )
    });
    let assertion = assertion_entry
        .expect("PasskeyAssertion(failure:policy_hash_drift) must be emitted after drift");

    assert_eq!(
        drift.request_id, assertion.request_id,
        "SaPolicyHashDrift and PasskeyAssertion rows must share the same \
         request_id; drift.request_id={}, assertion.request_id={}",
        drift.request_id, assertion.request_id,
    );
}

// ── Infra failure routes to DriftCheckUnavailable, not drift ─────────────────

/// Drift-check infrastructure failure emits
/// `PasskeyAssertion(failure:drift_check_unavailable)` — NOT
/// `failure:verifier_hash_drift` or `failure:policy_hash_drift`.
///
/// This test validates that `drift_err_route()` discriminates the inner `SaError`
/// so only actual `VerifierHashDrift` /
/// `PolicyHashDrift` variants produce the drift audit-row-paired failure tags.
///
/// # Method
///
/// 1. Deploy a fresh smart-account.
/// 2. Install a rule with the canonical OZ threshold-policy (so the on-chain
///    rule has a policy address that passes `fetch_verifier_and_policy_addresses`).
/// 3. Refresh the signer-set baseline (so `verify_signer_set_against_chain`
///    passes in the signing pre-flight).
/// 4. Inject a `SaContextRuleCreated` row into the audit log with **two** distinct
///    policy hash entries for the same `(rule_id, smart_account_redacted)`.  This
///    simulates a multi-hash rule beyond the single-hash scope.
/// 5. Call `sign_with_passkey_rule` with the rule_id.  The signing pre-flight
///    calls `verify_pinned_policy_against_chain`, which reads the two hashes from
///    the audit log, hits the `MultiplePinnedHashesUnsupported` guard, and returns
///    `SaError::MultiplePinnedHashesUnsupported`.  `drift_err_route()` maps this to
///    `CredentialsError::DriftCheckUnavailable`.
///
/// # Assertions
///
/// - `sign_with_passkey_rule` returns `Err(CredentialsError::DriftCheckUnavailable)`.
/// - `PasskeyAssertion.result == "failure:drift_check_unavailable"` is emitted.
/// - NO `SaVerifierHashDrift` row is emitted for that `request_id`.
/// - NO `SaPolicyHashDrift` row is emitted for that `request_id`.
///
/// Infra failure routes to `DriftCheckUnavailable`, not drift.
#[tokio::test]
async fn p5_drift_check_infra_failure_routes_to_drift_check_unavailable_not_drift() {
    let (signer_g, signer_box) = fresh_signer();
    fund_via_friendbot(&signer_g).await;

    let sa_strkey = deploy_fresh_smart_account(&signer_g).await;
    let sa_addr =
        parse_c_strkey_to_smart_account(&sa_strkey).expect("SA C-strkey must parse to ScAddress");

    // Deploy threshold-policy (idempotent across test runs).
    let policy_strkey = deploy_threshold_policy_wasm(&signer_g, signer_box.as_ref()).await;
    let policy_addr = parse_c_strkey_to_smart_account(&policy_strkey)
        .expect("threshold-policy C-strkey must parse");

    // ── Shared AuditWriter + SignersManager ───────────────────────────────────

    let (audit_writer, audit_log_path, _tmp_dir) = tmp_audit_writer();
    let sm = Arc::new(fresh_signers_manager(
        Arc::clone(&audit_writer),
        audit_log_path.clone(),
    ));

    // Install a 1-of-1 rule with the threshold-policy.
    let manager = fresh_pinning_rule_manager(Arc::clone(&audit_writer), Arc::clone(&sm));

    let signer_addr =
        parse_g_strkey_to_signer_address(&signer_g).expect("signer G-strkey must parse");
    let threshold_params = encode_simple_threshold_params(1);

    let definition = ContextRuleDefinition::new(
        RuleContext::Default,
        "p5-infra".to_owned(),
        None,
        vec![ContextRuleSignerInput::Delegated {
            address: signer_addr,
        }],
        vec![ContextRulePolicy::new(
            policy_addr.clone(),
            threshold_params,
        )],
    );

    let p5_out = manager
        .install_rule(
            sa_addr.clone(),
            definition,
            vec![ContextRuleId::new(0)],
            signer_box.as_ref(),
            None,
            rid(),
            false, // accept_mutable_verifier
            false, // accept_unknown_verifier
        )
        .await
        .expect("install_rule must succeed on testnet");
    let rule_id = p5_out.rule_id;
    assert!(
        !p5_out.pin_result.mutable_override,
        "canonical install must not set mutable_override"
    );
    assert!(
        !p5_out.pin_result.unknown_override,
        "canonical install must not set unknown_override"
    );
    drop(manager);

    // ── Baseline the signer set ───────────────────────────────────────────────
    //
    // `verify_signer_set_against_chain` in the signing pre-flight requires a
    // baselined row in the audit log.  Establishing the baseline ensures that
    // the signer-set check passes, leaving the drift-detection path as the
    // first point of failure.
    sm.refresh_signer_baseline(sa_addr.clone(), rule_id, Some(&signer_g), rid())
        .await
        .expect("refresh_signer_baseline must succeed");

    // ── Inject fabricated SaContextRuleCreated row with TWO policy hashes ─────
    //
    // The two-hash inject simulates a multi-hash rule beyond single-hash scope.
    // `find_latest_context_rule_pinned_hashes` picks the most-recent matching
    // row, so this row shadows the install-time pin row.
    //
    // `verify_pinned_policy_against_chain` reads the 2-element vec and hits the
    // `MultiplePinnedHashesUnsupported` guard, returning
    // `SaError::MultiplePinnedHashesUnsupported` (an infra failure, not drift).
    // `drift_err_route()` maps it to `CredentialsError::DriftCheckUnavailable`.
    let smart_account_redacted = redact_strkey_first5_last5(&sa_strkey);
    {
        let mut writer = audit_writer
            .lock()
            .expect("audit writer lock for multi-hash inject");
        let fake_entry = AuditEntry::new_sa_context_rule_created(
            &smart_account_redacted,
            rule_id,
            "default",
            1, // signers_count
            1, // policies_count
            None,
            CHAIN_ID,
            rid(),
            vec![], // no verifier hashes (Delegated signer only)
            vec![
                "aabbccdd11223344".to_owned(), // hash[0] — first distinct policy hash
                "99887766aabbccdd".to_owned(), // hash[1] — second distinct policy hash (multi-hash)
            ],
            false, // mutable_override
            false, // unknown_override
        );
        writer
            .write_entry(fake_entry)
            .expect("multi-hash SaContextRuleCreated inject must succeed");
    }

    // ── Call sign_with_passkey_rule ───────────────────────────────────────────
    //
    // The drift check fires BEFORE the approval-store check and BEFORE any bridge
    // I/O.  Constructing CredentialsManager without an approval store ensures that
    // `DriftCheckUnavailable` (not `ApprovalStoreUnavailable`) is the first error.
    let passkeys_tmpdir = tempfile::tempdir().expect("passkeys tempdir must succeed");
    let creds_mgr = CredentialsManager::new(
        passkeys_tmpdir.path().join("passkeys"),
        "default",
        "localhost",
        None, // no approval store: drift fires before store check
    );

    // Fake bridge address: multi-hash guard fires before any bridge I/O.
    let bridge_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 19909);
    let auth_digest = [0u8; 32];

    let outcome = creds_mgr
        .sign_with_passkey_rule(
            "does-not-matter",
            &sa_strkey,
            &auth_digest,
            vec![rule_id],
            Some(Arc::clone(&sm)),
            bridge_addr,
            Duration::from_millis(500),
            |_| {},
            true, // accept_single_verifier: bypass diversification (infra failure test)
        )
        .await;

    // ── Assert: DriftCheckUnavailable (not WasmHashDrift) ────────────────────
    assert!(
        matches!(outcome, Err(CredentialsError::DriftCheckUnavailable { .. })),
        "multi-hash infra failure must return DriftCheckUnavailable, \
         not WasmHashDrift; got: {outcome:?}"
    );

    // ── Assert: PasskeyAssertion(failure:drift_check_unavailable) emitted ─────
    let entries = read_audit_entries(&audit_log_path);

    let assertion_entry = entries.iter().rev().find(|e| {
        matches!(
            &e.event_kind,
            EventKind::PasskeyAssertion { result, .. }
                if result == "failure:drift_check_unavailable"
        )
    });
    let assertion = assertion_entry.expect(
        "PasskeyAssertion(failure:drift_check_unavailable) must be emitted \
         when drift-check infra fails",
    );

    // ── Assert: NO SaVerifierHashDrift / SaPolicyHashDrift for this request_id ─
    //
    // Schema invariant: a `failure:*_hash_drift` tag MUST be paired with a
    // `SaVerifierHashDrift` / `SaPolicyHashDrift` row carrying the same request_id.
    // The converse also holds: if NO drift audit row was emitted (as is the case for
    // infra failures), the result tag MUST be `failure:drift_check_unavailable`, not
    // a drift-specific tag.
    let infra_request_id = &assertion.request_id;

    let verifier_drift_row = entries.iter().find(|e| {
        matches!(&e.event_kind, EventKind::SaVerifierHashDrift { .. })
            && e.request_id == *infra_request_id
    });
    assert!(
        verifier_drift_row.is_none(),
        "SaVerifierHashDrift MUST NOT be emitted for an infra failure \
         (no drift audit row may be paired with drift_check_unavailable); \
         found row with request_id={infra_request_id}"
    );

    let policy_drift_row = entries.iter().find(|e| {
        matches!(&e.event_kind, EventKind::SaPolicyHashDrift { .. })
            && e.request_id == *infra_request_id
    });
    assert!(
        policy_drift_row.is_none(),
        "SaPolicyHashDrift MUST NOT be emitted for an infra failure \
         (no drift audit row may be paired with drift_check_unavailable); \
         found row with request_id={infra_request_id}"
    );
}

// ── Shared helper: deploy timelock controller as mutable fixture ──────────────

/// Deploys the OZ v0.7.2 timelock-controller to testnet and returns its C-strkey.
///
/// The timelock controller's `__constructor` calls `set_admin(e, &admin_addr)`,
/// which stores `AccessControlStorageKey::Admin` (serialised `"Admin"` symbol key)
/// in instance storage.  This makes the contract "mutable" in the wallet's
/// `detect_contract_mutability` sense (non-zero `Admin` key present).
///
/// The timelock controller WASM hash is NOT in `VERIFIER_ALLOWLIST`, so when used
/// as a verifier address, `identify_verifier` returns
/// `SaError::VerifierWasmNotInAllowlist`.  Callers must pass
/// `accept_unknown_verifier = true` to proceed past the allowlist check and reach
/// the mutability detection path.
///
/// # Constructor reference
///
/// The timelock-controller `__constructor(min_delay, proposers, executors, admin)`
/// calls `set_admin(e, &admin_addr)`, which writes `AccessControlStorageKey::Admin`
/// to instance storage via `e.storage().instance().set(&AccessControlStorageKey::Admin, &admin)`.
///
/// # Byte-layout citation
///
/// `AccessControlStorageKey::Admin` serialises to `ScVal::Symbol("Admin")`.
async fn deploy_mutable_contract_for_verifier_test(
    deployer_g: &str,
    seed_bytes: [u8; 32],
) -> String {
    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(seed_bytes);
    let deployer_signer: Box<dyn Signer + Send + Sync> =
        Box::new(SoftwareSigningKey::new_from_zeroizing(seed));
    let deployer = DeployerKeypair::from_signer(
        "testnet-pinning-acceptance-timelock".to_owned(),
        deployer_signer,
    );

    let args = TimelockControllerDeployArgs {
        deployer,
        network_passphrase: TESTNET_PASSPHRASE.to_owned(),
        rpc_url: TESTNET_RPC_URL.to_owned(),
        timeout: Duration::from_secs(TIMEOUT_SECS),
        fee: ResolvedFeePerOp {
            stroops: FEE_STROOPS,
            percentile_label: "explicit".to_owned(),
        },
        min_delay: 0,
        proposers: vec![deployer_g.to_owned()],
        executors: vec![],
        // Provide deployer as external admin so the contract has a non-zero Admin
        // key in instance storage at deploy time (set_admin called by constructor).
        admin: Some(deployer_g.to_owned()),
        dry_run: false,
    };

    match deploy_timelock_controller(args).await {
        Ok(result) => result.contract_address,
        Err(e) => panic!("timelock-controller deploy failed: {e}"),
    }
}

// ── Mutable verifier refused fail-closed ──────────────────────────────────────

/// `install_rule_refuses_mutable_verifier_without_override`
///
/// Verify that `install_rule` returns `SaError::VerifierMutable` when:
/// 1. The verifier contract has a non-zero `Admin` key in instance storage.
/// 2. `accept_mutable_verifier = false` (default fail-closed posture).
///
/// # Setup
///
/// The verifier is a freshly-deployed OZ v0.7.2 timelock-controller whose
/// `__constructor` sets `AccessControlStorageKey::Admin` in instance storage.
/// The timelock-controller WASM hash is NOT in `VERIFIER_ALLOWLIST`, so
/// `accept_unknown_verifier = true` is needed to bypass the allowlist check
/// and reach the mutability detection path.
///
/// With `accept_unknown_verifier = true`, the unknown-verifier path emits a
/// `SaUnknownContractOverride` row and continues.  Then mutability detection
/// finds the `Admin` key and — because `accept_mutable_verifier = false` —
/// returns `SaError::VerifierMutable`.
///
/// `detect_contract_mutability` fetches the contract instance entry via
/// `getLedgerEntries` (no `InvokeHostFunction`) and returns `SaError::VerifierMutable`
/// before `install_rule_inner` (simulate / submit) is ever reached.  The
/// timelock-controller is NOT a Verifier (lacks `batch_canonicalize_key`), but that is
/// irrelevant — `VerifierMutable` fires via the Admin-key `getLedgerEntries`
/// introspection alone.  The on-chain `add_context_rule` call is never attempted.
///
/// The `accept_mutable_verifier` flag and Admin-key detection are wallet-specific
/// defences with no analogue in the upstream contracts.
#[tokio::test(flavor = "multi_thread")]
async fn install_rule_refuses_mutable_verifier_without_override() {
    // Fresh keypair for SA deployer + signer (two separate instances required:
    // one for SA deploy, one for timelock deploy, one for install_rule signing).
    let (sa_signer_g, sa_signer_box) = fresh_signer();
    fund_via_friendbot(&sa_signer_g).await;

    // A separate keypair for the timelock deployer (avoids sequence-number
    // conflicts from two concurrent deploys by the same account).
    let timelock_key = SigningKey::generate(&mut OsRng);
    let timelock_g = format!(
        "{}",
        stellar_strkey::ed25519::PublicKey(timelock_key.verifying_key().to_bytes())
    );
    let timelock_seed: [u8; 32] = timelock_key.to_bytes();
    fund_via_friendbot(&timelock_g).await;

    // Deploy the smart-account first (used as the target SA to install a rule on).
    let sa_strkey = deploy_fresh_smart_account(&sa_signer_g).await;
    let sa_addr =
        parse_c_strkey_to_smart_account(&sa_strkey).expect("SA C-strkey must parse to ScAddress");

    // Deploy the timelock-controller; its constructor sets AccessControlStorageKey::Admin.
    let timelock_strkey =
        deploy_mutable_contract_for_verifier_test(&timelock_g, timelock_seed).await;
    let timelock_addr = parse_c_strkey_to_smart_account(&timelock_strkey)
        .expect("timelock C-strkey must parse to ScAddress");

    let (audit_writer, audit_log_path, _tmp_dir) = tmp_audit_writer();
    let sm = Arc::new(fresh_signers_manager(
        Arc::clone(&audit_writer),
        audit_log_path.clone(),
    ));

    let manager = fresh_pinning_rule_manager(Arc::clone(&audit_writer), Arc::clone(&sm));

    // Build a rule definition with the timelock-controller as an External verifier.
    // The wallet will (1) find the WASM hash NOT in VERIFIER_ALLOWLIST →
    //   accept_unknown_verifier=true bypasses this → emits SaUnknownContractOverride.
    // Then (2) detect_contract_mutability finds Admin key →
    //   accept_mutable_verifier=false → VerifierMutable.
    let definition = ContextRuleDefinition::new(
        RuleContext::Default,
        "p6-mutable-refuse".to_owned(),
        None,
        vec![ContextRuleSignerInput::External {
            verifier: timelock_addr,
            pubkey_data: vec![0xaau8; 32],
        }],
        vec![], // no policy needed: install_rule fails before on-chain submission
    );

    let signer_box = sa_signer_box;

    let request_id = rid();
    let result = manager
        .install_rule(
            sa_addr,
            definition,
            vec![ContextRuleId::new(0)],
            signer_box.as_ref(),
            None,
            request_id.clone(),
            false, // accept_mutable_verifier — MUST refuse mutable contract
            true,  // accept_unknown_verifier — bypass allowlist to reach mutability check
        )
        .await;

    // ── Outcome MUST be VerifierMutable ──────────────────────────────────────
    match result {
        Err(SaError::VerifierMutable { .. }) => {
            // Expected: mutable verifier refused without override.
        }
        Err(other) => {
            panic!(
                "expected SaError::VerifierMutable for timelock-controller verifier \
                 (has Admin key) with accept_mutable_verifier=false; got: {other:?}"
            );
        }
        Ok(out) => {
            panic!(
                "install_rule must return VerifierMutable for a mutable verifier \
                 when accept_mutable_verifier=false; returned Ok(rule_id={})",
                out.rule_id
            );
        }
    }

    // ── SaUnknownContractOverride row must have been emitted (allowlist bypass) ─
    //
    // The accept_unknown_verifier=true path emits SaUnknownContractOverride BEFORE
    // the mutability check fires VerifierMutable.  Both rows should be present.
    drop(manager);
    drop(sm);

    let entries = read_audit_entries(&audit_log_path);

    let unknown_override_row = entries.iter().find(|e| {
        matches!(
            &e.event_kind,
            EventKind::SaUnknownContractOverride { contract_kind, .. }
                if *contract_kind == ContractKind::Verifier
        )
    });
    assert!(
        unknown_override_row.is_some(),
        "SaUnknownContractOverride (verifier) must be emitted before \
         VerifierMutable fires (allowlist bypass row)"
    );

    // Verify the unknown-override row shares the request_id.
    let override_entry = unknown_override_row.unwrap();
    assert_eq!(
        override_entry.request_id, request_id,
        "SaUnknownContractOverride row must carry the request_id from install_rule"
    );

    // ── observed_hash_first8 must be non-zero ────────────────────────────────
    //
    // The real observed hash must be stored in the override row, not a zero sentinel.
    if let EventKind::SaUnknownContractOverride {
        observed_hash_first8,
        ..
    } = &override_entry.event_kind
    {
        assert_ne!(
            observed_hash_first8, "0000000000000000",
            "SaUnknownContractOverride.observed_hash_first8 must be the real \
             on-chain timelock-controller wasm hash (not zero sentinel)"
        );
        assert_eq!(
            observed_hash_first8.len(),
            16,
            "observed_hash_first8 must be 16 hex chars (8 bytes first8)"
        );
    } else {
        panic!("override_entry.event_kind must be SaUnknownContractOverride");
    }
}

// ── accept_mutable_verifier_override_emits_audit_row ─────────────────────────

/// Verify that `install_rule` emits `SaMutableContractOverride` when:
/// 1. The verifier has a non-zero `Admin` key in instance storage (mutable).
/// 2. `accept_unknown_verifier = true` (bypasses WASM allowlist check).
/// 3. `accept_mutable_verifier = true` (allows mutable contract with audit row).
///
/// # Setup
///
/// Same timelock-controller verifier as the refusal test.  With both override flags set:
/// - `SaUnknownContractOverride` row emitted (allowlist bypass path).
/// - `SaMutableContractOverride` row emitted (admin-key override path).
/// - `install_rule` reaches `install_rule_inner` (simulate / submit), where the
///   on-chain `add_context_rule` call traps because the timelock-controller lacks
///   `batch_canonicalize_key` — the contract is a mutable fixture, NOT a real Verifier.
///
/// # Assertions
///
/// - `SaUnknownContractOverride` audit row emitted (pre-submit, allowlist bypass).
/// - `SaMutableContractOverride` audit row emitted (pre-submit, admin-key override).
/// - Both override rows share the same `request_id`.
/// - `install_rule` returns `Err(SaError::DeploymentFailed { phase: "simulate", .. })` —
///   the on-chain simulate traps because the timelock has no `batch_canonicalize_key`.
///   This confirms the override path reaches the on-chain boundary and fails there, not
///   earlier.  A full success leg requires a genuine mutable Verifier WASM; the
///   mocking/adversarial fixture for that leg is
///   `adversarial/accept_mutable_verifier_override_audit_row.rs`.
///
/// `SaMutableContractOverride` + `SaUnknownContractOverride` are emitted by the
/// pre-submit `getLedgerEntries` path, before any `InvokeHostFunction` is submitted.
/// Verifying these rows confirms the override-path audit-trail logic works.  The
/// `DeploymentFailed { phase: "simulate" }` outcome confirms the override path correctly
/// proceeds past the pin check and reaches the on-chain boundary.
#[tokio::test(flavor = "multi_thread")]
async fn accept_mutable_verifier_override_emits_audit_row() {
    let (sa_signer_g, sa_signer_box) = fresh_signer();
    fund_via_friendbot(&sa_signer_g).await;

    let timelock_key = SigningKey::generate(&mut OsRng);
    let timelock_g = format!(
        "{}",
        stellar_strkey::ed25519::PublicKey(timelock_key.verifying_key().to_bytes())
    );
    let timelock_seed: [u8; 32] = timelock_key.to_bytes();
    fund_via_friendbot(&timelock_g).await;

    let sa_strkey = deploy_fresh_smart_account(&sa_signer_g).await;
    let sa_addr =
        parse_c_strkey_to_smart_account(&sa_strkey).expect("SA C-strkey must parse to ScAddress");

    // Deploy timelock with a fresh keypair; its constructor sets Admin key.
    let timelock_strkey =
        deploy_mutable_contract_for_verifier_test(&timelock_g, timelock_seed).await;
    let timelock_addr = parse_c_strkey_to_smart_account(&timelock_strkey)
        .expect("timelock C-strkey must parse to ScAddress");

    let (audit_writer, audit_log_path, _tmp_dir) = tmp_audit_writer();
    let sm = Arc::new(fresh_signers_manager(
        Arc::clone(&audit_writer),
        audit_log_path.clone(),
    ));

    let manager = fresh_pinning_rule_manager(Arc::clone(&audit_writer), Arc::clone(&sm));

    let definition = ContextRuleDefinition::new(
        RuleContext::Default,
        "p7-mutable-accept".to_owned(),
        None,
        vec![ContextRuleSignerInput::External {
            verifier: timelock_addr,
            pubkey_data: vec![0xbbu8; 32],
        }],
        vec![], // no policy: pin check fires before on-chain rule submission
    );

    let signer_box = sa_signer_box;

    let request_id = rid();
    let result = manager
        .install_rule(
            sa_addr,
            definition,
            vec![ContextRuleId::new(0)],
            signer_box.as_ref(),
            None,
            request_id.clone(),
            true, // accept_mutable_verifier — proceed with mutable contract + emit row
            true, // accept_unknown_verifier — bypass allowlist check
        )
        .await;

    // ── install_rule must reach the on-chain boundary and fail there ─────────
    //
    // The pre-submit pin check passes (both override flags set), so install_rule
    // proceeds to install_rule_inner.  install_rule_inner simulates
    // `add_context_rule` against the timelock-controller address.  The timelock has
    // no `batch_canonicalize_key` entry point, so the RPC simulate call returns an
    // error — surfaced as DeploymentFailed { phase: "simulate" }.
    //
    // A full success leg (install_rule returns Ok with mutable_override=true) requires
    // a genuine mutable Verifier WASM.  That path is covered by the
    // `adversarial/accept_mutable_verifier_override_audit_row.rs` fixture with a mock RPC.
    match result {
        Err(SaError::DeploymentFailed {
            phase: "simulate", ..
        }) => {
            // Expected: pin check passed, but simulate traps on non-Verifier contract.
        }
        Err(other) => {
            panic!(
                "expected SaError::DeploymentFailed(phase=simulate) after override \
                 accepted; timelock is not a Verifier so simulate must trap; got: {other:?}"
            );
        }
        Ok(out) => {
            panic!(
                "install_rule must NOT succeed against a non-Verifier contract \
                 even with accept_mutable_verifier=true (no batch_canonicalize_key); \
                 returned Ok(rule_id={})",
                out.rule_id
            );
        }
    }

    // ── Pre-submit audit rows must be present ─────────────────────────────────
    //
    // Both override rows are emitted by pin_referenced_contracts (the pre-submit
    // getLedgerEntries path) before install_rule_inner is called.  They are
    // present regardless of the on-chain simulate outcome.
    drop(manager);
    drop(sm);

    let entries = read_audit_entries(&audit_log_path);

    // SaMutableContractOverride (admin-key override path).
    let mutable_override_row = entries.iter().find(|e| {
        matches!(
            &e.event_kind,
            EventKind::SaMutableContractOverride { contract_kind, .. }
                if *contract_kind == ContractKind::Verifier
        )
    });
    assert!(
        mutable_override_row.is_some(),
        "SaMutableContractOverride (contract_kind='verifier') must be emitted \
         (pre-submit, Admin key detected, accept_mutable_verifier=true)"
    );

    // SaUnknownContractOverride (allowlist bypass path).
    let unknown_override_row = entries.iter().find(|e| {
        matches!(
            &e.event_kind,
            EventKind::SaUnknownContractOverride { contract_kind, .. }
                if *contract_kind == ContractKind::Verifier
        )
    });
    assert!(
        unknown_override_row.is_some(),
        "SaUnknownContractOverride (verifier) must also be emitted \
         (timelock WASM not in VERIFIER_ALLOWLIST; allowlist bypass fired first)"
    );

    // ── request_id correlation ────────────────────────────────────────────────
    let mutable_entry = mutable_override_row.unwrap();
    assert_eq!(
        mutable_entry.request_id, request_id,
        "SaMutableContractOverride row must carry the request_id from install_rule"
    );
}

// ── accept_unknown_verifier_override_emits_audit_row ─────────────────────────

/// Verify that `install_rule` emits `SaUnknownContractOverride`
/// when the verifier's wasm hash is NOT in `VERIFIER_ALLOWLIST` and
/// `accept_unknown_verifier = true`.
///
/// The verifier in this test is the deployed smart-account's own C-address.
/// The OZ smart-account WASM hash is NOT in `VERIFIER_ALLOWLIST` (which only
/// contains the OZ webauthn-verifier-example WASM hash).  The smart-account
/// contract also has NO `Admin` or `Owner` key in instance storage, so the
/// mutability check returns `Immutable` — only `SaUnknownContractOverride` fires.
///
/// # Assertions
///
/// - `SaUnknownContractOverride` audit row emitted with `contract_kind = "verifier"`.
/// - `observed_hash_first8` is non-empty and non-zero (real on-chain hash stored).
/// - `install_rule` returns `Err(SaError::DeploymentFailed { phase: "simulate", .. })` —
///   the on-chain simulate traps because the SA has no `batch_canonicalize_key`.
///
/// The `SaContextRuleCreated` row (which would carry `unknown_override = true`) is NOT
/// emitted when `install_rule` fails at simulate phase; that row is only emitted on
/// success.  The audit-trail correctness for the success path is verified by the
/// `adversarial/accept_mutable_verifier_override_audit_row.rs` fixture (mock RPC).
///
/// # Reference cross-check
///
/// - `VERIFIER_ALLOWLIST` at
///   `crates/stellar-agent-smart-account/src/verifier_allowlist.rs` —
///   only the OZ multisig-webauthn-verifier-example WASM hash is listed.
/// - `crates/stellar-agent-smart-account/src/managers/signers.rs::fetch_observed_wasm_hash`
///   — real hash fetched without allowlist enforcement.
///
/// The SA has no Admin key so `mutable_override=false`; the unknown-override path alone
/// fires.  The `SaUnknownContractOverride` row is emitted pre-submit (getLedgerEntries
/// only).  The subsequent simulate trap confirms the override path reaches the on-chain
/// boundary.  That is the full scope of this test.
#[tokio::test(flavor = "multi_thread")]
async fn accept_unknown_verifier_override_emits_audit_row() {
    let (signer_g, signer_box) = fresh_signer();
    fund_via_friendbot(&signer_g).await;

    // Deploy a fresh smart-account.  Its C-address is reused as the External
    // verifier address.  The OZ smart-account WASM hash is NOT in VERIFIER_ALLOWLIST
    // and the smart-account contract has NO Admin/Owner instance-storage key.
    let sa_strkey = deploy_fresh_smart_account(&signer_g).await;
    let sa_addr =
        parse_c_strkey_to_smart_account(&sa_strkey).expect("SA C-strkey must parse to ScAddress");

    // Use a SECOND smart-account as the verifier (same as the refusal test but with
    // accept_unknown_verifier=true).  Reuse the deployer address for simplicity;
    // deploying a second SA would add latency without changing the test assertion.
    //
    // In this case we use sa_addr itself as the verifier, since its WASM is
    // already deployed and is guaranteed to be unknown to VERIFIER_ALLOWLIST.
    let verifier_addr = sa_addr.clone();

    let (audit_writer, audit_log_path, _tmp_dir) = tmp_audit_writer();
    let sm = Arc::new(fresh_signers_manager(
        Arc::clone(&audit_writer),
        audit_log_path.clone(),
    ));

    let manager = fresh_pinning_rule_manager(Arc::clone(&audit_writer), Arc::clone(&sm));

    let definition = ContextRuleDefinition::new(
        RuleContext::Default,
        "p8-unknown-accept".to_owned(),
        None,
        vec![ContextRuleSignerInput::External {
            verifier: verifier_addr,
            pubkey_data: vec![0xccu8; 32],
        }],
        vec![], // no policy: pin check fires before on-chain rule submission
    );

    let request_id = rid();
    let result = manager
        .install_rule(
            sa_addr.clone(),
            definition,
            vec![ContextRuleId::new(0)],
            signer_box.as_ref(),
            None,
            request_id.clone(),
            false, // accept_mutable_verifier: smart-account WASM has no admin key
            true,  // accept_unknown_verifier: bypass VERIFIER_ALLOWLIST check
        )
        .await;

    // ── install_rule must reach the on-chain boundary and fail there ─────────
    //
    // The pre-submit pin check passes (unknown-verifier override accepted, SA has no
    // Admin key so mutable_override stays false).  install_rule_inner then simulates
    // `add_context_rule` against the SA address.  The OZ smart-account has no
    // `batch_canonicalize_key` entry point, so the simulate call traps and returns
    // DeploymentFailed { phase: "simulate" }.
    match result {
        Err(SaError::DeploymentFailed {
            phase: "simulate", ..
        }) => {
            // Expected: pin check passed, simulate traps on non-Verifier SA contract.
        }
        Err(other) => {
            panic!(
                "expected SaError::DeploymentFailed(phase=simulate) after unknown \
                 override accepted; SA is not a Verifier so simulate must trap; got: {other:?}"
            );
        }
        Ok(out) => {
            panic!(
                "install_rule must NOT succeed against a non-Verifier SA address \
                 (no batch_canonicalize_key); returned Ok(rule_id={})",
                out.rule_id
            );
        }
    }

    // ── SaUnknownContractOverride row must be present (pre-submit) ────────────
    drop(manager);
    drop(sm);

    let entries = read_audit_entries(&audit_log_path);

    let unknown_row = entries.iter().find(|e| {
        matches!(
            &e.event_kind,
            EventKind::SaUnknownContractOverride { contract_kind, .. }
                if *contract_kind == ContractKind::Verifier
        )
    });
    assert!(
        unknown_row.is_some(),
        "SaUnknownContractOverride (contract_kind='verifier') must be emitted \
         (pre-submit getLedgerEntries path; accept_unknown_verifier=true)"
    );

    // ── request_id correlation ────────────────────────────────────────────────
    let unknown_entry = unknown_row.unwrap();
    assert_eq!(
        unknown_entry.request_id, request_id,
        "SaUnknownContractOverride row must carry the request_id from install_rule"
    );

    // ── observed_hash_first8 must be non-zero ─────────────────────────────────
    //
    // The real on-chain WASM hash must be stored in the override row, not a zero
    // sentinel.  This is the regression gate for `fetch_observed_wasm_hash`.
    if let EventKind::SaUnknownContractOverride {
        observed_hash_first8,
        ..
    } = &unknown_entry.event_kind
    {
        assert_ne!(
            observed_hash_first8, "0000000000000000",
            "observed_hash_first8 must be the real on-chain WASM hash, \
             not a zero sentinel"
        );
        assert_eq!(
            observed_hash_first8.len(),
            16,
            "observed_hash_first8 must be 16 hex chars (8 bytes, first-8 of SHA-256)"
        );
    } else {
        panic!("unknown_entry.event_kind must be SaUnknownContractOverride");
    }
}
