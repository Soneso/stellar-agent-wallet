//! Testnet acceptance tests for `SignersManager`.
//!
//! Exercises the signer-threshold lifecycle against testnet
//! (atomic two-op bundles are not possible under CAP-46):
//!
//! - **Threshold-brick refusal**.  `remove_signer` on the sole signer of a
//!   1-of-1 rule returns [`SaError::ThresholdUnreachable`] and does NOT submit
//!   a transaction (post-op signer_count=0 < threshold=1).
//!
//! - **`set_threshold` single-op**.  A standalone `set_threshold` call
//!   via the smart account's `execute()` entrypoint raises a 1-of-2 rule to
//!   2-of-2 on testnet.  No atomic bundle; each threshold or signer mutation
//!   is one independent `InvokeHostFunctionOp` transaction.
//!
//! - **Divergence detection (synthetic injected baseline)**.  A wallet
//!   whose audit-log baseline records `(signer_count=1, threshold=2)` while
//!   on-chain has `(signer_count=1, threshold=1)` returns
//!   [`SaError::SignerSetDiverged`] on `verify_signer_set_against_chain`.
//!   The mismatch is injected via a direct `AuditEntry::new_sa_signer_set_baselined`
//!   write — no out-of-band on-chain mutation is required.
//!
//! - **Fresh-wallet missing-baseline path**.  An empty audit log causes
//!   `verify_signer_set_against_chain` to return
//!   [`SaError::SignerSetMissingBaseline`].  After `refresh_signer_baseline`,
//!   the subsequent `verify` returns `Ok`.
//!
//! - **Threshold-read fail-closed**.  `list_signers` and
//!   `refresh_signer_baseline` return [`SaError::ThresholdPolicyNotInstalled`]
//!   when the rule has no threshold-policy installed (empty `policies` list),
//!   asserting that threshold reading routes through
//!   `identify_threshold_policy`, not a silent `signers.len()` proxy.
//!
//! - **External signer add**. A
//!   `Signer::External(verifier, key_data)` is added to an existing 1-of-1
//!   rule via `add_signer`. Verifies that:
//!   (a) the returned `new_signer_id` is valid (not-zero or consistently assigned),
//!   (b) `list_signers` shows `signer_count = 2` after the add,
//!   (c) a `SaSignerAdded` audit row is emitted.
//!
//! - **WebAuthn signer add**. A
//!   `Signer::External(webauthn_verifier, pubkey_65 || credential_id)` is added to
//!   an existing rule using a synthetic (non-browser-registered) credential.
//!   Verifies `signer_count` increases by 1 and the audit row is emitted.
//!   The synthetic credential uses a deterministic P-256-like 65-byte key_data and
//!   a 16-byte credential_id so the test is reproducible without a browser session.
//!
//! # Gating
//!
//! All tests compile only under `--features testnet-integration`:
//!
//! ```text
//! cargo test --features testnet-integration --test smart_account_signers_testnet_acceptance
//! ```

#![cfg(feature = "testnet-integration")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics are acceptable in testnet acceptance tests"
)]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use sha2::{Digest as _, Sha256};
use stellar_agent_core::audit_log::entry::AuditEntry;
use stellar_agent_core::audit_log::signer_set::{BaselineReason, ObservedSignerSet, SignerPubkey};
use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_core::observability::{RedactedStrkey, redact_strkey_first5_last5};
use stellar_agent_core::smart_account::rule_id::ContextRuleId;
use stellar_agent_network::signing::envelope_signing::attach_signature;
use stellar_agent_network::{
    Signer, SoftwareSigningKey, StellarRpcClient, fetch_account, submit_transaction_and_wait,
};
use stellar_agent_smart_account::deployment::{
    DeployerKeypair, DeploymentArgs, ResolvedFeePerOp, deploy_smart_account,
    derive_smart_account_address,
};
use stellar_agent_smart_account::error::SaError;
use stellar_agent_smart_account::managers::credentials::{CredentialsError, CredentialsManager};
use stellar_agent_smart_account::managers::rules::RuleContext;
use stellar_agent_smart_account::managers::rules::{
    ContextRuleDefinition, ContextRuleManager, ContextRuleManagerConfig, ContextRulePolicy,
    ContextRuleSignerInput, parse_c_strkey_to_smart_account, parse_g_strkey_to_signer_address,
};
use stellar_agent_smart_account::managers::signers::{
    SignersManager, SignersManagerConfig, build_external_signer_scval,
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
// u32: TransactionBuilderBehavior::fee() takes impl Into<u32>.
// 1_000_000 stroops fits in u32 (max ~4.3B stroops).
const FEE_STROOPS: u32 = 1_000_000;
const TIMEOUT_SECS: u64 = 120;

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Generates a fresh request-id for audit-log forensic correlation.
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
            var_name: "testnet-signers-acceptance".to_owned(),
            signer,
        },
    )
}

/// Funds a G-strkey via testnet Friendbot.
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
fn tmp_audit_writer() -> (Arc<Mutex<AuditWriter>>, PathBuf, TempDir) {
    let dir = tempfile::tempdir().expect("tempdir must succeed");
    let path = dir.path().join("audit.jsonl");
    let writer = AuditWriter::open(path.clone(), None).expect("AuditWriter::open must succeed");
    (Arc::new(Mutex::new(writer)), path, dir)
}

/// Constructs a `ContextRuleManager` for testnet.
fn fresh_rule_manager() -> ContextRuleManager {
    ContextRuleManager::new(ContextRuleManagerConfig::new(
        TESTNET_RPC_URL.to_owned(),
        TESTNET_PASSPHRASE.to_owned(),
        Duration::from_secs(TIMEOUT_SECS),
        CHAIN_ID.to_owned(),
    ))
    .expect("ContextRuleManager::new must succeed")
}

/// Constructs a `SignersManager` for testnet using the given audit writer.
///
/// Primary and secondary RPC are both set to `TESTNET_RPC_URL` (degrades to
/// single-RPC; acceptable for testnet acceptance — two-RPC consultation will
/// trivially agree since both RPCs return the same view).
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
        "testnet-acceptance".to_owned(),
        Duration::from_secs(TIMEOUT_SECS),
        CHAIN_ID.to_owned(),
    ))
    .expect("SignersManager::new must succeed")
}

/// Deploys a fresh smart-account whose bootstrap rule (rule_id 0) uses
/// `signer_g` as its sole `Delegated` signer with no policies.
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

/// Deploys the vendored OZ threshold-policy WASM to testnet.
///
/// Mirrors the two-tx split pattern from `deploy_webauthn_verifier_body` at
/// `crates/stellar-agent-smart-account/src/deployment/deploy_webauthn_verifier.rs:395-530`
/// (the upload-if-absent + `CreateContractV2` pattern).
///
/// Returns the deployed threshold-policy C-strkey.
///
/// # Byte-layout citations
///
/// - `CreateContractV2` with `ContractIdPreimageFromAddress`:
///   stellar-xdr `curr/src/generated.rs` (`Stellar-transaction.x` IDL).
/// - Deterministic salt: `SHA256("oz-threshold-policy-v0.7.2-" || network_passphrase)` —
///   pins the salt to the WASM version and network, matching the same convention used in
///   `deploy_webauthn_verifier_body` (VERIFIER_SALT_DOMAIN_PREFIX).
/// - No `__constructor` args for the threshold-policy contract: it exports
///   only `enforce`, `install`, `uninstall`, `get_threshold`, `set_threshold`.
async fn deploy_threshold_policy_wasm(
    deployer_g: &str,
    signer: &(dyn Signer + Send + Sync),
) -> String {
    // Compute wasm SHA-256 for LedgerKey construction and idempotency check.
    let wasm_hash_bytes: [u8; 32] = Sha256::digest(THRESHOLD_POLICY_WASM).into();

    // Deterministic salt: SHA256("oz-threshold-policy-v0.7.2-" || network_passphrase).
    let salt_input = format!("oz-threshold-policy-v0.7.2-{TESTNET_PASSPHRASE}");
    let salt: [u8; 32] = Sha256::digest(salt_input.as_bytes()).into();

    // Derive the expected contract address (pure; no network).
    let policy_strkey = derive_smart_account_address(deployer_g, &salt, TESTNET_PASSPHRASE)
        .expect("threshold-policy address derivation must succeed");

    let rpc_server = Client::new(TESTNET_RPC_URL).expect("Server::new must succeed");

    let network_client =
        StellarRpcClient::new(TESTNET_RPC_URL).expect("StellarRpcClient::new must succeed");

    // Fetch deployer account sequence.
    let deployer_view = fetch_account(&network_client, deployer_g, &[])
        .await
        .expect("deployer account fetch must succeed");
    let mut deployer_account =
        BaselibAccount::new(deployer_g, &deployer_view.sequence_number.to_string())
            .expect("BaselibAccount::new must succeed");

    // ── Upload WASM if not already on-chain ───────────────────────────────────

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

        // Re-fetch deployer sequence after upload tx.
        let updated_view = fetch_account(&network_client, deployer_g, &[])
            .await
            .expect("deployer re-fetch after upload must succeed");
        deployer_account =
            BaselibAccount::new(deployer_g, &updated_view.sequence_number.to_string())
                .expect("BaselibAccount::new after upload must succeed");
    }

    // ── Check if contract already deployed ────────────────────────────────────
    // Query a ContractData key for the contract; if present, skip deployment.
    // We use the wasm-hash-based ContractCode key to test WASM presence, then
    // attempt deployment and tolerate duplicate-deploy errors gracefully.

    // ── Deploy contract via CreateContractV2 ──────────────────────────────────

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
            // Tolerate duplicate-deploy (contract already exists).
            // The contract is addressed deterministically, so the strkey is still valid.
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
/// `ScMapEntry { key: ScVal::Symbol(field_name), val: <field IntoVal> }`,
/// entries sorted by key.
///
/// # Byte-layout
///
/// `SimpleThresholdAccountParams { threshold: u32 }` is a single-field struct with
/// `#[contracttype]`.
fn encode_simple_threshold_params(threshold: u32) -> ScVal {
    let entry = ScMapEntry {
        key: ScVal::Symbol(ScSymbol::try_from("threshold").expect("'threshold' fits ScSymbol")),
        val: ScVal::U32(threshold),
    };
    let map: VecM<ScMapEntry> = vec![entry].try_into().expect("single-entry VecM");
    ScVal::Map(Some(ScMap(map)))
}

/// Installs a 1-of-1 threshold-policy rule on a freshly-deployed smart account.
///
/// `deploy_fresh_smart_account` creates the bootstrap rule (rule_id=0) with no
/// threshold-policy in `policies`.  That bootstrap rule cannot be used by tests
/// that call `list_signers`, `refresh_signer_baseline`, or
/// `verify_signer_set_against_chain`, because those entry-points route through
/// `identify_threshold_policy` and fail closed with `ThresholdPolicyNotInstalled`
/// when `policies` is empty.
///
/// This helper:
/// 1. Deploys the vendored OZ threshold-policy WASM to testnet.
/// 2. Installs a new `ContextRule` on `sa_addr` with `signer_g` as its sole
///    `Delegated` signer, `threshold=1`, and the deployed policy in `policies`.
/// 3. Returns `(new_rule_id, policy_strkey)`.
///
/// Tests that require threshold-aware operations must use this new rule, not rule_id=0.
///
/// # Bootstrap rule (rule_id=0)
///
/// Rule_id=0 retains its empty `policies` list and is intentionally tested only
/// by `b5_threshold_read_routes_through_identify_threshold_policy`, which
/// verifies the fail-closed `ThresholdPolicyNotInstalled` behaviour.
async fn install_threshold_policy_on_fresh_sa(
    sa_addr: stellar_xdr::ScAddress,
    signer_g: &str,
    signer_box: &(dyn Signer + Send + Sync),
) -> (u32, String) {
    let rule_manager = fresh_rule_manager();

    let policy_strkey = deploy_threshold_policy_wasm(signer_g, signer_box).await;
    let policy_addr = parse_c_strkey_to_smart_account(&policy_strkey)
        .expect("threshold-policy C-strkey must parse");

    let signer_addr =
        parse_g_strkey_to_signer_address(signer_g).expect("signer_g must parse to ScAddress");

    let threshold_params = encode_simple_threshold_params(1); // 1-of-1 rule

    let definition = ContextRuleDefinition::new(
        RuleContext::Default,
        "b-test-rule".to_owned(),
        None,
        vec![ContextRuleSignerInput::Delegated {
            address: signer_addr,
        }],
        vec![ContextRulePolicy::new(policy_addr, threshold_params)],
    );

    let install_out = rule_manager
        .install_rule(
            sa_addr,
            definition,
            vec![ContextRuleId::new(0)], // bootstrap rule authorises the install
            signer_box,
            None,
            rid(),
            false, // accept_mutable_verifier
            false, // accept_unknown_verifier
        )
        .await
        .expect("install_threshold_policy_on_fresh_sa: install_rule must succeed");
    let new_rule_id = install_out.rule_id;

    (new_rule_id, policy_strkey)
}

// ── Fresh-wallet missing-baseline ────────────────────────────────────────────

/// A wallet with an empty audit log returns
/// [`SaError::SignerSetMissingBaseline`] on `verify_signer_set_against_chain`;
/// after `refresh_signer_baseline` the subsequent `verify` returns `Ok`.
///
/// Missing-baseline path returns `sa.signer_set_missing_baseline`
/// (NOT `sa.signer_set_diverged`).
///
/// Setup: installs a 1-of-1 rule with the threshold-policy in `policies` so that
/// `verify_signer_set_against_chain` / `refresh_signer_baseline` can route through
/// `identify_threshold_policy` (bootstrap rule_id=0 has no policy).
#[tokio::test]
async fn b4_fresh_wallet_missing_baseline_then_refresh_then_verify_ok() {
    let (signer_g, signer_box) = fresh_signer();
    fund_via_friendbot(&signer_g).await;

    let sa_strkey = deploy_fresh_smart_account(&signer_g).await;
    let sa_addr =
        parse_c_strkey_to_smart_account(&sa_strkey).expect("deployed C-strkey must parse");

    // Install a 1-of-1 rule with the threshold-policy (bootstrap rule_id=0 has no
    // policies; new rule is required for threshold-reading tests).
    let (rule_id, _policy_strkey) =
        install_threshold_policy_on_fresh_sa(sa_addr.clone(), &signer_g, signer_box.as_ref()).await;

    let (audit_writer, audit_log_path, _dir) = tmp_audit_writer();
    let mgr = fresh_signers_manager(audit_writer.clone(), audit_log_path);

    // Verify with empty audit log → SignerSetMissingBaseline.
    let missing = mgr
        .verify_signer_set_against_chain(sa_addr.clone(), rule_id, Some(&signer_g), rid())
        .await;
    assert!(
        matches!(missing, Err(SaError::SignerSetMissingBaseline { .. })),
        "empty audit log must return SignerSetMissingBaseline; got: {missing:?}"
    );

    // refresh_signer_baseline writes the SaSignerSetBaselined row.
    let observed = mgr
        .refresh_signer_baseline(sa_addr.clone(), rule_id, Some(&signer_g), rid())
        .await
        .expect("refresh_signer_baseline must succeed");
    assert_eq!(
        observed.signer_count, 1,
        "installed rule must have signer_count=1; got {}",
        observed.signer_count
    );
    assert_eq!(
        observed.threshold, 1,
        "installed rule must have threshold=1; got {}",
        observed.threshold
    );

    // Verify after refresh → Ok (on-chain matches baseline).
    let frozen = mgr
        .verify_signer_set_against_chain(sa_addr.clone(), rule_id, Some(&signer_g), rid())
        .await
        .expect("verify after refresh must succeed");

    assert_eq!(
        frozen.observed_chain_state().signer_count,
        1,
        "frozen tuple must report signer_count=1; got {}",
        frozen.observed_chain_state().signer_count
    );
    assert_eq!(
        frozen.observed_chain_state().threshold,
        1,
        "frozen tuple must report threshold=1; got {}",
        frozen.observed_chain_state().threshold
    );
}

// ── Threshold-brick refusal ───────────────────────────────────────────────────

/// `remove_signer` refuses when the post-op signer count would fall
/// below the current threshold.
///
/// Given a rule R, `remove_signer` refuses with `SaError::ThresholdUnreachable`
/// and no transaction is submitted when removing the sole signer would leave
/// signer_count < threshold.
///
/// Setup: installs a 1-of-1 rule with threshold-policy (bootstrap rule_id=0 has
/// no policies; `remove_signer` reads threshold via `identify_threshold_policy`
/// before the pre-flight invariant check).
/// The post-op state after removing the sole signer would be (0, 1) which
/// violates the invariant `threshold <= signer_count`.
///
/// Note: no atomic bundle; CAP-46 restricts each Soroban transaction to one
/// `InvokeHostFunctionOp`.
#[tokio::test]
async fn b1_threshold_brick_refusal() {
    let (signer_g, signer_box) = fresh_signer();
    fund_via_friendbot(&signer_g).await;

    let sa_strkey = deploy_fresh_smart_account(&signer_g).await;
    let sa_addr =
        parse_c_strkey_to_smart_account(&sa_strkey).expect("deployed C-strkey must parse");

    // Install a 1-of-1 rule with the threshold-policy (bootstrap rule_id=0 has no
    // policies; `remove_signer` reads threshold via `identify_threshold_policy`
    // before the invariant check).
    let (rule_id, _policy_strkey) =
        install_threshold_policy_on_fresh_sa(sa_addr.clone(), &signer_g, signer_box.as_ref()).await;

    // Signer_id of the sole signer in the newly installed rule.
    // The install places signer_g at index 0 within the new rule's signer list.
    let signer_id_in_rule: u32 = 0;

    let (audit_writer, audit_log_path, _dir) = tmp_audit_writer();
    let mgr = fresh_signers_manager(audit_writer.clone(), audit_log_path);

    // Establish baseline so the pre-flight invariant check can read signer_count + threshold.
    mgr.refresh_signer_baseline(sa_addr.clone(), rule_id, Some(&signer_g), rid())
        .await
        .expect("refresh_signer_baseline must succeed");

    // Remove the sole signer from the installed rule.
    // Post-op: signer_count=0 < threshold=1 → ThresholdUnreachable.
    // No atomic bundle; CAP-46 prohibits two InvokeHostFunctionOp per Soroban transaction.
    let result = mgr
        .remove_signer(
            sa_addr.clone(),
            rule_id,
            signer_id_in_rule,
            signer_box.as_ref(),
            rid(),
        )
        .await;

    assert!(
        matches!(result, Err(SaError::ThresholdUnreachable { .. })),
        "remove sole signer must return ThresholdUnreachable; got: {result:?}"
    );

    // Zero-row assertion: after a pre-flight refusal, the audit log MUST contain
    // ZERO `SaSignerRemoved` rows — the refusal must be genuinely pre-submission,
    // with no mutation submitted on-chain.
    //
    // This assertion holds across ALL rotated-file siblings: even if rotation
    // happened mid-test, the full log chain must be clean.
    {
        use std::fs;
        use std::io::{BufRead, BufReader};
        use stellar_agent_core::audit_log::entry::AuditEntry;
        use stellar_agent_core::audit_log::schema::EventKind;

        let writer_guard = audit_writer.lock().expect("audit writer lock");
        let log_path = writer_guard.path().to_path_buf();
        drop(writer_guard);

        // Collect the active log file. (No rotation expected in a short test run,
        // but scanning all siblings matches the reader's traversal semantics.)
        let mut signer_removed_count = 0usize;
        let mut threshold_changed_count = 0usize;
        let mut files_to_scan = vec![log_path.clone()];

        // Also check for rotated siblings (e.g. log_path + ".1", ".2", ...).
        if let Ok(parent) = log_path.parent().map(fs::read_dir).transpose() {
            for entry in parent.into_iter().flatten().flatten() {
                let sibling = entry.path();
                if sibling != log_path
                    && sibling
                        .file_name()
                        .and_then(|n| n.to_str())
                        .map(|n| {
                            n.starts_with(
                                log_path.file_name().and_then(|f| f.to_str()).unwrap_or(""),
                            )
                        })
                        .unwrap_or(false)
                {
                    files_to_scan.push(sibling);
                }
            }
        }

        for path in &files_to_scan {
            if let Ok(file) = fs::File::open(path) {
                let reader = BufReader::new(file);
                for line in reader.lines() {
                    let Ok(line) = line else { continue };
                    if line.trim().is_empty() {
                        continue;
                    }
                    if let Ok(entry) = serde_json::from_str::<AuditEntry>(&line) {
                        if matches!(entry.event_kind, EventKind::SaSignerRemoved { .. }) {
                            signer_removed_count += 1;
                        }
                        if matches!(entry.event_kind, EventKind::SaThresholdChanged { .. }) {
                            threshold_changed_count += 1;
                        }
                    }
                }
            }
        }

        assert_eq!(
            signer_removed_count, 0,
            "pre-flight refusal must leave ZERO SaSignerRemoved rows in the audit log \
             (across all rotated files); found {signer_removed_count} unexpected rows"
        );
        assert_eq!(
            threshold_changed_count, 0,
            "pre-flight refusal must leave ZERO SaThresholdChanged rows in the audit log \
             (across all rotated files); found {threshold_changed_count} unexpected rows"
        );
    }
}

// ── Divergence detection (synthetic injected baseline) ───────────────────────

/// Divergence detection via a synthetically injected audit-log baseline
/// that claims a different threshold than what is on-chain.
///
/// With a wallet whose audit-log baseline for rule R recorded
/// `(signer_count=1, threshold=2)` and on-chain shows `(signer_count=1,
/// threshold=1)`, `verify_signer_set_against_chain` refuses with
/// `SaError::SignerSetDiverged`.
///
/// The mismatch is threshold-only (signer_count matches, threshold diverges).
/// The on-chain threshold is read from `get_threshold(rule_id, smart_account)` via
/// the threshold-policy contract, not from `signers.len()`.
///
/// The mismatch is injected by writing a `SaSignerSetBaselined` row claiming
/// `(signer_count=1, threshold=2)` directly to the audit log, while the on-chain
/// bootstrap rule has `(signer_count=1, threshold=1)`.
///
/// Setup: installs a 1-of-1 rule with the threshold-policy (bootstrap rule_id=0
/// has no policies; `verify_signer_set_against_chain` routes threshold reading
/// through `identify_threshold_policy`).
#[tokio::test]
async fn b3_divergence_detection_via_injected_baseline() {
    let (signer_g, signer_box) = fresh_signer();
    fund_via_friendbot(&signer_g).await;

    let sa_strkey = deploy_fresh_smart_account(&signer_g).await;
    let sa_addr =
        parse_c_strkey_to_smart_account(&sa_strkey).expect("deployed C-strkey must parse");

    // Install a 1-of-1 rule with the threshold-policy (bootstrap rule_id=0 has no
    // policies; new rule is required for threshold-reading tests).
    let (rule_id, _policy_strkey) =
        install_threshold_policy_on_fresh_sa(sa_addr.clone(), &signer_g, signer_box.as_ref()).await;

    let (audit_writer, audit_log_path, _dir) = tmp_audit_writer();
    let mgr = fresh_signers_manager(audit_writer.clone(), audit_log_path.clone());

    // Inject a baseline claiming (signer_count=1, threshold=2) — same signer count
    // as on-chain but a higher threshold.  The installed rule's actual threshold=1
    // diverges from the injected threshold=2 (threshold-only divergence).
    let smart_account_redacted = redact_strkey_first5_last5(&sa_strkey);
    let fabricated_state = ObservedSignerSet {
        signer_count: 1,
        threshold: 2, // diverges from on-chain threshold=1
        signer_ids: vec![0],
        signer_pubkeys: vec![SignerPubkey::Ed25519 {
            pubkey: [0xaau8; 32],
        }],
    };
    let fabricated_pubkeys_first8 = vec!["aaaaaaaaaaaaaaaa".to_owned()];

    {
        let mut writer = audit_writer.lock().expect("audit writer lock");
        let prev_chain_tip = writer.current_chain_tip();
        let entry = AuditEntry::new_sa_signer_set_baselined(
            rule_id,
            &fabricated_state,
            fabricated_pubkeys_first8,
            0, // observed_at_unix_ms (sentinel)
            BaselineReason::first_observation(),
            prev_chain_tip,
            RedactedStrkey::from_already_redacted(smart_account_redacted.as_str()),
            CHAIN_ID,
            rid(),
        );
        writer.write_entry(entry).expect("audit write must succeed");
    }

    // Verify: audit log claims threshold=2; on-chain has threshold=1 → SignerSetDiverged.
    let req_id = rid();
    let result = mgr
        .verify_signer_set_against_chain(sa_addr.clone(), rule_id, Some(&signer_g), req_id.clone())
        .await;

    assert!(
        matches!(result, Err(SaError::SignerSetDiverged { .. })),
        "injected baseline divergence must return SignerSetDiverged; got: {result:?}"
    );

    // Audit-row assertion: `verify_signer_set_against_chain` MUST have emitted
    // a `SaSignerSetDiverged` audit row in addition to returning the typed error.
    // Scan the raw log file for an entry with EventKind::SaSignerSetDiverged and
    // assert the forensic-correlation fields are correctly populated.
    //
    // This asserts the dual-reporting contract (typed error to caller + audit row to log)
    // and that the forensic-field content is correctly populated.
    {
        use std::fs;
        use std::io::{BufRead, BufReader};
        use stellar_agent_core::audit_log::entry::AuditEntry;
        use stellar_agent_core::audit_log::schema::EventKind;

        let writer_guard = audit_writer.lock().expect("audit writer lock");
        let log_path = writer_guard.path().to_path_buf();
        drop(writer_guard);

        let file = fs::File::open(&log_path).expect("audit log file must exist after verify call");
        let reader = BufReader::new(file);
        let mut found_diverged_row = false;
        for line in reader.lines() {
            let line = line.expect("audit log line must be valid UTF-8");
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(entry) = serde_json::from_str::<AuditEntry>(&line)
                && let EventKind::SaSignerSetDiverged {
                    expected_signer_set_digest,
                    observed_signer_set_digest,
                    smart_account_redacted: row_sa_redacted,
                    expected_threshold,
                    observed_threshold,
                    ..
                } = &entry.event_kind
            {
                // a. Both digest fields must match the canonical <16hex>...<16hex> format.
                assert!(
                    digest_matches_first8_last8_pattern(expected_signer_set_digest),
                    "expected_signer_set_digest must match `<16hex>...<16hex>` pattern; \
                     got: {expected_signer_set_digest}"
                );
                assert!(
                    digest_matches_first8_last8_pattern(observed_signer_set_digest),
                    "observed_signer_set_digest must match `<16hex>...<16hex>` pattern; \
                     got: {observed_signer_set_digest}"
                );

                // b. smart_account_redacted must equal the redacted form of the SA strkey.
                assert_eq!(
                    row_sa_redacted, &smart_account_redacted,
                    "smart_account_redacted must equal redact_strkey_first5_last5 of \
                     the actual SA strkey"
                );

                // c. Top-level AuditEntry::request_id must equal the captured req_id.
                assert_eq!(
                    entry.request_id, req_id,
                    "AuditEntry::request_id must match the request ID passed to \
                     verify_signer_set_against_chain"
                );

                // d. Divergence semantics: injected baseline had threshold=2, on-chain=1.
                assert_eq!(
                    *expected_threshold, 2,
                    "expected_threshold must be 2 (from injected baseline); \
                     got: {expected_threshold}"
                );
                assert_eq!(
                    *observed_threshold, 1,
                    "observed_threshold must be 1 (on-chain bootstrap rule); \
                     got: {observed_threshold}"
                );

                found_diverged_row = true;
                break;
            }
        }
        assert!(
            found_diverged_row,
            "verify_signer_set_against_chain must emit SaSignerSetDiverged audit row"
        );
    }
}

// ── External signer add ───────────────────────────────────────────────────────

/// `add_signer` with a `Signer::External(verifier, key_data)` ScVal adds
/// an external-verifier signer to an existing rule on testnet.
///
/// Acceptance criteria (external path):
/// - `signer_count` increases from 1 to 2 after `add_signer`.
/// - A `SaSignerAdded` audit row is emitted.
/// - The returned `new_signer_id` is a valid u32.
///
/// A real OZ WebAuthn verifier contract is deployed for the external signer's
/// verifier address.  On-chain `add_signer` calls `batch_canonicalize_key` on
/// the verifier contract; the threshold-policy contract does not expose that
/// entrypoint and would trap.  The WebAuthn verifier exposes
/// `batch_canonicalize_key` and accepts the key_data without a browser ceremony.
///
/// # Byte-layout
///
/// - `Signer::External(Address, Bytes)` encodes as
///   `ScVal::Vec([Symbol("External"), Address, Bytes])`.
/// - [`build_external_signer_scval`] encodes this layout.
#[tokio::test]
async fn b7_add_external_signer_to_existing_rule() {
    use std::io::{BufRead, BufReader};
    use stellar_agent_core::audit_log::schema::EventKind;
    use stellar_agent_smart_account::deployment::{
        ResolvedFeePerOp, WebAuthnVerifierDeployArgs, deploy_webauthn_verifier,
    };
    use stellar_agent_smart_account::verifiers::{RecordOutcome, VerifierRegistry};
    use stellar_agent_smart_account::webauthn_verifier::WEBAUTHN_VERIFIER_WASM_SHA256;

    let (signer_g, signer_box) = fresh_signer();
    fund_via_friendbot(&signer_g).await;

    let sa_strkey = deploy_fresh_smart_account(&signer_g).await;
    let sa_addr =
        parse_c_strkey_to_smart_account(&sa_strkey).expect("deployed C-strkey must parse");

    // Install a 1-of-1 rule with the threshold-policy (bootstrap rule_id=0 has no policies).
    // `_policy_strkey` is bound with underscore prefix: only the rule_id is used below.
    let (rule_id, _policy_strkey) =
        install_threshold_policy_on_fresh_sa(sa_addr.clone(), &signer_g, signer_box.as_ref()).await;

    // Deploy the OZ WebAuthn verifier WASM to obtain a valid verifier C-strkey.
    //
    // On-chain `add_signer` calls `batch_canonicalize_key` on the verifier contract.
    // The threshold-policy contract does not implement `batch_canonicalize_key` and
    // would trap.  The WebAuthn verifier contract exposes `batch_canonicalize_key`
    // and accepts synthetic key_data without a browser registration ceremony.
    let (verifier_deployer_g, verifier_deployer_keypair) = fresh_deployer();
    fund_via_friendbot(&verifier_deployer_g).await;

    let tmp_registry_dir = tempfile::tempdir().expect("tempdir for verifier registry");
    let registry_path = tmp_registry_dir.path().join("verifier_registry.json");

    let verifier_deploy_args = WebAuthnVerifierDeployArgs {
        deployer: verifier_deployer_keypair,
        network_passphrase: TESTNET_PASSPHRASE.to_owned(),
        rpc_url: TESTNET_RPC_URL.to_owned(),
        timeout: Duration::from_secs(TIMEOUT_SECS),
        fee: ResolvedFeePerOp {
            stroops: FEE_STROOPS,
            percentile_label: "explicit".to_owned(),
        },
        dry_run: false,
        registry_path_override: Some(registry_path.clone()),
    };

    let verifier_deploy_result = deploy_webauthn_verifier(verifier_deploy_args, None)
        .await
        .expect("WebAuthn verifier deployment must succeed");

    let verifier_strkey = verifier_deploy_result.verifier_address.clone();

    // Record the verifier in the temp registry (required by the path but not
    // consumed further in this test — the strkey is used directly below).
    {
        let mut registry = VerifierRegistry::open_at(registry_path)
            .expect("VerifierRegistry::open_at must succeed");
        let outcome = registry
            .record_webauthn_verifier(
                TESTNET_PASSPHRASE,
                verifier_strkey.clone(),
                WEBAUTHN_VERIFIER_WASM_SHA256.to_owned(),
            )
            .expect("record_webauthn_verifier must succeed");
        assert!(
            matches!(
                outcome,
                RecordOutcome::Recorded | RecordOutcome::AlreadyRecorded
            ),
            "verifier registry record must succeed; got: {outcome:?}"
        );
    }

    let (audit_writer, audit_log_path, _dir) = tmp_audit_writer();
    let mgr = fresh_signers_manager(audit_writer.clone(), audit_log_path.clone());

    // Establish audit-log baseline.
    let baseline = mgr
        .refresh_signer_baseline(sa_addr.clone(), rule_id, Some(&signer_g), rid())
        .await
        .expect("refresh_signer_baseline must succeed");
    assert_eq!(baseline.signer_count, 1, "initial signer_count must be 1");

    // Build an External signer ScVal using the deployed WebAuthn verifier address.
    //
    // key_data: a WebAuthn-format key the verifier's `batch_canonicalize_key` accepts —
    //   a 65-byte uncompressed P-256 public key (0x04 || X[32] || Y[32]) followed by a
    //   credential_id. The verifier reads `key_data[0..65]` as the public key; a shorter
    //   key_data is rejected on-chain (Contract error #3119). Distinct fill bytes from b8
    //   keep the two External-add cases independent.
    //
    // Byte-layout:
    //   `Signer::External(Address, Bytes)` = `ScVal::Vec([Symbol("External"), Address, Bytes])`.
    let verifier_sc_addr = parse_c_strkey_to_smart_account(&verifier_strkey)
        .expect("WebAuthn verifier C-strkey must parse to ScAddress");

    let mut pubkey_65 = [0u8; 65];
    pubkey_65[0] = 0x04; // uncompressed point tag (SEC1 X9.62 §2.3.3)
    for (i, b) in pubkey_65[1..33].iter_mut().enumerate() {
        *b = (i as u8).wrapping_add(0x33);
    }
    for (i, b) in pubkey_65[33..65].iter_mut().enumerate() {
        *b = (i as u8).wrapping_add(0x44);
    }
    let credential_id: Vec<u8> = (0u8..16).map(|i| i.wrapping_add(0x55)).collect();
    let mut key_data = Vec::with_capacity(65 + credential_id.len());
    key_data.extend_from_slice(&pubkey_65);
    key_data.extend_from_slice(&credential_id);

    let external_scval = build_external_signer_scval(verifier_sc_addr, &key_data)
        .expect("build_external_signer_scval must succeed");

    let external_pubkey = SignerPubkey::External {
        verifier_contract: verifier_strkey.clone(),
        key_data_first16: key_data[..16].try_into().expect("16 bytes"),
    };

    // add_signer with External ScVal.
    let new_signer_id = mgr
        .add_signer(
            sa_addr.clone(),
            rule_id,
            external_scval,
            external_pubkey,
            signer_box.as_ref(),
            rid(),
        )
        .await
        .expect("add_signer (External) must succeed on testnet");

    // list_signers post-add must show signer_count = 2.
    let post_add = mgr
        .list_signers(sa_addr.clone(), rule_id, Some(&signer_g), rid())
        .await
        .expect("list_signers post-add must succeed");

    assert_eq!(
        post_add.signer_count, 2,
        "signer_count must be 2 after adding External signer; got {}",
        post_add.signer_count
    );
    assert_eq!(
        post_add.signer_ids.len(),
        2,
        "signer_ids length must be 2; got {}",
        post_add.signer_ids.len()
    );
    assert!(
        post_add.signer_ids.contains(&new_signer_id),
        "new_signer_id={new_signer_id} must appear in signer_ids"
    );

    // SaSignerAdded audit row must be emitted.
    //
    // SaSignerAdded carries `signer_id` (the assigned on-chain ID) and
    // `resulting_signer_pubkeys`. We verify `signer_id == new_signer_id` and
    // that at least one pubkey in `resulting_signer_pubkeys` is an External variant
    // (the added signer).
    {
        let writer_guard = audit_writer.lock().expect("audit writer lock");
        let log_path = writer_guard.path().to_path_buf();
        drop(writer_guard);

        let file =
            std::fs::File::open(&log_path).expect("audit log file must exist after add_signer");
        let reader = BufReader::new(file);
        let mut found = false;
        for line in reader.lines() {
            let line = line.expect("audit line must be valid UTF-8");
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(entry) = serde_json::from_str::<AuditEntry>(&line)
                && let EventKind::SaSignerAdded {
                    rule_id: row_rule_id,
                    signer_id: row_id,
                    resulting_signer_pubkeys,
                    ..
                } = &entry.event_kind
                && *row_rule_id == rule_id
                && *row_id == new_signer_id
            {
                // Verify the new signer appears as an External pubkey in the result.
                let has_external = resulting_signer_pubkeys
                    .iter()
                    .any(|pk| matches!(pk, SignerPubkey::External { .. }));
                assert!(
                    has_external,
                    "resulting_signer_pubkeys must include at least one External variant"
                );
                found = true;
                break;
            }
        }
        assert!(
            found,
            "SaSignerAdded audit row for rule_id={rule_id}, \
             signer_id={new_signer_id} must be emitted"
        );
    }
}

// ── WebAuthn signer add ───────────────────────────────────────────────────────

/// `add_signer` with a `Signer::External(webauthn_verifier, pubkey_65 || cred_id)`
/// ScVal adds a WebAuthn signer to an existing rule on testnet using a synthetic
/// (non-browser-registered) credential.
///
/// Acceptance criteria (WebAuthn path):
/// - `signer_count` increases from 1 to 2 after `add_signer`.
/// - A `SaSignerAdded` audit row is emitted.
///
/// The test uses a synthetic P-256-style uncompressed public key (65 bytes with
/// leading `0x04` tag) and a 16-byte credential_id.  No browser ceremony is required
/// because the WebAuthn authentication ceremony is not exercised here — only the
/// `add_signer` on-chain encoding path is tested.
///
/// The WebAuthn verifier contract is deployed fresh for this test to ensure the
/// verifier address is valid on testnet (any deployed contract with the OZ WebAuthn
/// verifier WASM hash is acceptable; we use a fresh deployment for isolation).
///
/// On-chain, OZ `Signer` has only `Delegated` and `External` variants; there is no
/// `WebAuthn` variant in the contract storage layer.  A WebAuthn signer is stored as
/// `External(webauthn_verifier_address, pubkey_65 || credential_id)`.  When the wallet
/// reads back the signer set, the decoder always projects to `SignerPubkey::External`;
/// the assertion therefore checks for an `External` entry whose `verifier_contract`
/// matches the deployed WebAuthn verifier, not a `WebAuthn` entry.
///
/// The `webauthn_pubkey = SignerPubkey::WebAuthn { .. }` argument supplied to
/// `add_signer` is the wallet's local label for the in-flight call; this is correct
/// as input and is not changed.  Only the READ-BACK assertion in the `SaSignerAdded`
/// audit row changes.
///
/// # Byte-layout
///
/// - `canonicalize_key` reads `key_data[0..65]` as the public key; credential_id
///   at bytes 65+ is metadata. Full `pubkey_65 || cred_id` concatenation stored on-chain.
/// - `Signer::External(Address, Bytes)` ScVal encoding (no WebAuthn variant on-chain).
#[tokio::test]
async fn b8_add_webauthn_signer_to_existing_rule() {
    use std::io::{BufRead, BufReader};
    use stellar_agent_core::audit_log::schema::EventKind;
    use stellar_agent_smart_account::deployment::{
        ResolvedFeePerOp, WebAuthnVerifierDeployArgs, deploy_webauthn_verifier,
    };
    use stellar_agent_smart_account::verifiers::{RecordOutcome, VerifierRegistry};
    use stellar_agent_smart_account::webauthn_verifier::WEBAUTHN_VERIFIER_WASM_SHA256;

    let (signer_g, signer_box) = fresh_signer();
    fund_via_friendbot(&signer_g).await;

    let sa_strkey = deploy_fresh_smart_account(&signer_g).await;
    let sa_addr =
        parse_c_strkey_to_smart_account(&sa_strkey).expect("deployed C-strkey must parse");

    // Install a 1-of-1 rule with the threshold-policy (bootstrap rule_id=0 has no policies).
    let (rule_id, _policy_strkey) =
        install_threshold_policy_on_fresh_sa(sa_addr.clone(), &signer_g, signer_box.as_ref()).await;

    // Deploy the OZ WebAuthn verifier WASM to get a valid verifier C-strkey.
    //
    // This mirrors the `deploy_verifier_to_temp_registry` pattern from
    // `smart_account_rules_webauthn_testnet_acceptance.rs`.
    let (deployer_g, deployer_keypair) = fresh_deployer();
    fund_via_friendbot(&deployer_g).await;

    let tmp_registry_dir = tempfile::tempdir().expect("tempdir for verifier registry");
    let registry_path = tmp_registry_dir.path().join("verifier_registry.json");

    let verifier_deploy_args = WebAuthnVerifierDeployArgs {
        deployer: deployer_keypair,
        network_passphrase: TESTNET_PASSPHRASE.to_owned(),
        rpc_url: TESTNET_RPC_URL.to_owned(),
        timeout: Duration::from_secs(TIMEOUT_SECS),
        fee: ResolvedFeePerOp {
            stroops: FEE_STROOPS,
            percentile_label: "explicit".to_owned(),
        },
        dry_run: false,
        registry_path_override: Some(registry_path.clone()),
    };

    let deploy_result = deploy_webauthn_verifier(verifier_deploy_args, None)
        .await
        .expect("WebAuthn verifier deployment must succeed");

    let verifier_strkey = deploy_result.verifier_address.clone();

    // Record the verifier in the temp registry (required by the path but not
    // used further in this test — we use the strkey directly).
    {
        let mut registry = VerifierRegistry::open_at(registry_path)
            .expect("VerifierRegistry::open_at must succeed");
        let outcome = registry
            .record_webauthn_verifier(
                TESTNET_PASSPHRASE,
                verifier_strkey.clone(),
                WEBAUTHN_VERIFIER_WASM_SHA256.to_owned(),
            )
            .expect("record_webauthn_verifier must succeed");
        assert!(
            matches!(
                outcome,
                RecordOutcome::Recorded | RecordOutcome::AlreadyRecorded
            ),
            "verifier registry record must succeed; got: {outcome:?}"
        );
    }

    let verifier_sc_addr =
        parse_c_strkey_to_smart_account(&verifier_strkey).expect("verifier C-strkey must parse");

    // Build a synthetic WebAuthn key_data: pubkey_65_bytes || credential_id_bytes.
    //
    // Canonical layout:
    //   bytes 0..65 = uncompressed secp256r1 public key (0x04 || X[32] || Y[32]).
    //   bytes 65..  = credential_id (variable length; 16 bytes here for a short ID).
    //
    // This synthetic key does NOT correspond to a registered WebAuthn credential.
    // The test exercises the `add_signer` on-chain write path only, not the
    // authentication ceremony.  The on-chain `add_signer` does NOT validate key_data
    // format at the OZ smart-account layer (validation occurs during `__check_auth`
    // when a signing attempt uses the signer, not at registration time).
    //
    // Per the OpenZeppelin smart-account contract,
    // `add_signer` inserts the signer without key_data validation.
    let mut pubkey_65 = [0u8; 65];
    pubkey_65[0] = 0x04; // uncompressed point tag (SEC1 X9.62 §2.3.3)
    // Fill X[32] and Y[32] with deterministic bytes for reproducibility.
    for (i, b) in pubkey_65[1..33].iter_mut().enumerate() {
        *b = (i as u8).wrapping_add(0x11);
    }
    for (i, b) in pubkey_65[33..65].iter_mut().enumerate() {
        *b = (i as u8).wrapping_add(0x22);
    }
    let credential_id: Vec<u8> = (0u8..16).map(|i| i.wrapping_add(0xaa)).collect();

    let mut key_data = Vec::with_capacity(65 + credential_id.len());
    key_data.extend_from_slice(&pubkey_65);
    key_data.extend_from_slice(&credential_id);

    let external_scval = build_external_signer_scval(verifier_sc_addr, &key_data)
        .expect("build_external_signer_scval must succeed");

    let cred_id_first16: [u8; 16] = credential_id.as_slice().try_into().expect("16 bytes");
    let webauthn_pubkey = SignerPubkey::WebAuthn {
        credential_id_first16: cred_id_first16,
    };

    // Establish audit-log baseline.
    let (audit_writer, audit_log_path, _dir) = tmp_audit_writer();
    let mgr = fresh_signers_manager(audit_writer.clone(), audit_log_path.clone());

    let baseline = mgr
        .refresh_signer_baseline(sa_addr.clone(), rule_id, Some(&signer_g), rid())
        .await
        .expect("refresh_signer_baseline must succeed");
    assert_eq!(baseline.signer_count, 1, "initial signer_count must be 1");

    // add_signer with WebAuthn External ScVal.
    let new_signer_id = mgr
        .add_signer(
            sa_addr.clone(),
            rule_id,
            external_scval,
            webauthn_pubkey,
            signer_box.as_ref(),
            rid(),
        )
        .await
        .expect("add_signer (WebAuthn External) must succeed on testnet");

    // list_signers post-add must show signer_count = 2.
    let post_add = mgr
        .list_signers(sa_addr.clone(), rule_id, Some(&signer_g), rid())
        .await
        .expect("list_signers post-add must succeed");

    assert_eq!(
        post_add.signer_count, 2,
        "signer_count must be 2 after adding WebAuthn signer; got {}",
        post_add.signer_count
    );
    assert!(
        post_add.signer_ids.contains(&new_signer_id),
        "new_signer_id={new_signer_id} must appear in signer_ids"
    );

    // SaSignerAdded audit row for the WebAuthn signer must be emitted.
    //
    // Verified by: `signer_id == new_signer_id` AND `resulting_signer_pubkeys`
    // includes at least one `SignerPubkey::External` entry whose `verifier_contract`
    // equals the deployed WebAuthn verifier strkey.
    //
    // A WebAuthn signer reads back as `External(webauthn_verifier_address, ...)` because
    // the on-chain OZ `Signer` type has no `WebAuthn` variant; the decoder always
    // projects to `SignerPubkey::External`.
    {
        let writer_guard = audit_writer.lock().expect("audit writer lock");
        let log_path = writer_guard.path().to_path_buf();
        drop(writer_guard);

        let file =
            std::fs::File::open(&log_path).expect("audit log file must exist after add_signer");
        let reader = BufReader::new(file);
        let mut found = false;
        for line in reader.lines() {
            let line = line.expect("audit line must be valid UTF-8");
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(entry) = serde_json::from_str::<AuditEntry>(&line)
                && let EventKind::SaSignerAdded {
                    rule_id: row_rule_id,
                    signer_id: row_id,
                    resulting_signer_pubkeys,
                    ..
                } = &entry.event_kind
                && *row_rule_id == rule_id
                && *row_id == new_signer_id
            {
                // The added WebAuthn signer reads back as External(webauthn_verifier, ...)
                // because the on-chain OZ Signer enum has no WebAuthn variant.
                let has_external_webauthn = resulting_signer_pubkeys.iter().any(|pk| {
                    matches!(
                        pk,
                        SignerPubkey::External { verifier_contract, .. }
                            if verifier_contract == &verifier_strkey
                    )
                });
                assert!(
                    has_external_webauthn,
                    "resulting_signer_pubkeys must include an External entry with \
                     verifier_contract={verifier_strkey} (WebAuthn signer reads back \
                     as External on-chain)"
                );
                found = true;
                break;
            }
        }
        assert!(
            found,
            "SaSignerAdded audit row for rule_id={rule_id}, \
             signer_id={new_signer_id} must be emitted"
        );
    }
}

/// Returns `true` when `s` matches the canonical `<16hex>...<16hex>` format
/// produced by [`stellar_agent_core::audit_log::signer_set::format_digest_first8_last8`].
///
/// The expected format is exactly 35 characters: 16 ASCII lowercase hex digits,
/// the literal `"..."` separator, and 16 more ASCII lowercase hex digits.
///
/// Used by the divergence-detection testnet test to assert that `expected_signer_set_digest` and
/// `observed_signer_set_digest` in a `SaSignerSetDiverged` audit row are correctly
/// formatted.
fn digest_matches_first8_last8_pattern(s: &str) -> bool {
    // Expected: "<16 hex chars>...<16 hex chars>" — total 35 chars.
    let Some((left, right)) = s.split_once("...") else {
        return false;
    };
    left.len() == 16
        && right.len() == 16
        && left
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        && right
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

// ── `set_threshold` single-op ────────────────────────────────────────────────

/// `set_threshold` as a standalone single-op transaction on testnet.
///
/// Exercises `set_threshold` as an independent `execute()` invocation on the
/// smart account, routed through the threshold-policy contract.  Atomic two-op
/// bundles are not possible under CAP-46.
///
/// Setup:
/// 1. Deploy a smart account with bootstrap signer S1.
/// 2. Deploy the threshold-policy WASM to testnet.
/// 3. Install a 1-of-2 rule with signers `[S1, S2]` and threshold=1.
/// 4. Establish audit-log baseline (signer_count=2, threshold=1).
/// 5. `set_threshold(new_threshold=2)` → upgrades rule to 2-of-2.
/// 6. Verify post-op: signer_count=2, threshold=2.
///
/// # ABI signatures
///
/// - `set_threshold(threshold: u32, context_rule: ContextRule, smart_account: Address)`.
/// - `execute(target: Address, target_fn: Symbol, target_args: Vec<Val>)`.
/// - `get_threshold(e, context_rule_id: u32, smart_account: Address) -> u32`.
#[tokio::test]
async fn b2_set_threshold_single_op() {
    let (signer_g, signer_box) = fresh_signer();
    fund_via_friendbot(&signer_g).await;

    let sa_strkey = deploy_fresh_smart_account(&signer_g).await;
    let sa_addr =
        parse_c_strkey_to_smart_account(&sa_strkey).expect("deployed C-strkey must parse");

    let rule_manager = fresh_rule_manager();

    // ── Step 1: Deploy threshold-policy WASM to testnet ──────────────────────
    let policy_strkey = deploy_threshold_policy_wasm(&signer_g, signer_box.as_ref()).await;
    let policy_addr = parse_c_strkey_to_smart_account(&policy_strkey)
        .expect("threshold-policy C-strkey must parse");

    // ── Step 2: Install a 1-of-2 rule with the threshold policy ──────────────
    // threshold=1 so that S1 alone can authorize `set_threshold` to raise it to 2.
    // S2 is an ephemeral key; it need not be funded.
    let (signer2_g, _signer2_box) = fresh_signer();
    let signer_addr1 =
        parse_g_strkey_to_signer_address(&signer_g).expect("signer_g must parse to ScAddress");
    let signer_addr2 =
        parse_g_strkey_to_signer_address(&signer2_g).expect("signer2_g must parse to ScAddress");

    let threshold_params = encode_simple_threshold_params(1); // install with threshold=1

    let definition = ContextRuleDefinition::new(
        RuleContext::Default,
        "b2-set-threshold".to_owned(),
        None,
        vec![
            ContextRuleSignerInput::Delegated {
                address: signer_addr1,
            },
            ContextRuleSignerInput::Delegated {
                address: signer_addr2,
            },
        ],
        vec![ContextRulePolicy::new(policy_addr, threshold_params)],
    );

    let b2_install_out = rule_manager
        .install_rule(
            sa_addr.clone(),
            definition,
            vec![ContextRuleId::new(0)], // bootstrap rule authorises the install
            signer_box.as_ref(),
            None,
            rid(),
            false, // accept_mutable_verifier
            false, // accept_unknown_verifier
        )
        .await
        .expect("install_rule must succeed");
    let new_rule_id = b2_install_out.rule_id;

    // ── Step 3: Establish audit-log baseline ─────────────────────────────────
    let (audit_writer, audit_log_path, _dir) = tmp_audit_writer();
    let mgr = fresh_signers_manager(audit_writer.clone(), audit_log_path);

    let baseline = mgr
        .refresh_signer_baseline(sa_addr.clone(), new_rule_id, Some(&signer_g), rid())
        .await
        .expect("refresh_signer_baseline must succeed");

    assert_eq!(
        baseline.signer_count, 2,
        "installed rule must have signer_count=2; got {}",
        baseline.signer_count
    );
    assert_eq!(
        baseline.threshold, 1,
        "installed rule must have threshold=1; got {}",
        baseline.threshold
    );

    // ── Step 4: Raise threshold from 1 to 2 (single-op set_threshold) ────────
    // `set_threshold` succeeds as a standalone op; no atomic bundle under CAP-46.
    mgr.set_threshold(
        sa_addr.clone(),
        new_rule_id,
        2, // raise threshold to 2-of-2
        signer_box.as_ref(),
        rid(),
    )
    .await
    .expect("set_threshold to 2-of-2 must succeed");

    // ── Step 5: Verify post-op state ─────────────────────────────────────────
    let post_op = mgr
        .list_signers(sa_addr.clone(), new_rule_id, Some(&signer_g), rid())
        .await
        .expect("list_signers post-set_threshold must succeed");

    assert_eq!(
        post_op.signer_count, 2,
        "signer_count must remain 2 after set_threshold; got {}",
        post_op.signer_count
    );
    assert_eq!(
        post_op.threshold, 2,
        "threshold must be 2 after set_threshold; got {}",
        post_op.threshold
    );
}

// ── Threshold-read routes through identify_threshold_policy ──────────────────

/// `list_signers` and `refresh_signer_baseline` fail closed with
/// `SaError::ThresholdPolicyNotInstalled` when the rule's `policies` list is
/// empty, asserting that threshold reading is routed through
/// `identify_threshold_policy`.
///
/// The wallet must not silently use `signers.len()` as a proxy for the threshold
/// value when `policies.is_empty()`.  This test asserts the correct fail-closed
/// behaviour: both entry-points that call `identify_threshold_policy` return
/// `ThresholdPolicyNotInstalled` instead of proceeding with a silently incorrect
/// threshold value.
///
/// The bootstrap smart-account bootstrap rule (rule_id = 0) is deployed with
/// zero policies (see `deploy_fresh_smart_account`), making it a convenient
/// in-protocol way to reproduce the no-policy condition on testnet without
/// patching on-chain state.
///
#[tokio::test(flavor = "multi_thread")]
async fn b5_threshold_read_routes_through_identify_threshold_policy() {
    let (signer_g, _signer_box) = fresh_signer();
    fund_via_friendbot(&signer_g).await;

    // Bootstrap smart-account rule (rule_id = 0) has NO policies installed.
    // `deploy_smart_account` installs the bootstrap signer but does not attach
    // any threshold-policy contract.
    let sa_strkey = deploy_fresh_smart_account(&signer_g).await;
    let sa_addr =
        parse_c_strkey_to_smart_account(&sa_strkey).expect("deployed C-strkey must parse");

    let (audit_writer, audit_log_path, _dir) = tmp_audit_writer();
    let mgr = fresh_signers_manager(audit_writer.clone(), audit_log_path);

    // `list_signers` on the no-policy bootstrap rule must fail closed.
    let result_list = mgr
        .list_signers(sa_addr.clone(), 0, Some(&signer_g), rid())
        .await;

    assert!(
        matches!(
            result_list,
            Err(SaError::ThresholdPolicyNotInstalled { rule_id: 0, .. })
        ),
        "list_signers on a rule with no threshold policy must return \
         ThresholdPolicyNotInstalled (fail-closed); got: {result_list:?}"
    );

    // `refresh_signer_baseline` must also fail closed on the same rule.
    let result_refresh = mgr
        .refresh_signer_baseline(sa_addr.clone(), 0, Some(&signer_g), rid())
        .await;

    assert!(
        matches!(
            result_refresh,
            Err(SaError::ThresholdPolicyNotInstalled { rule_id: 0, .. })
        ),
        "refresh_signer_baseline on a rule with no threshold policy must return \
         ThresholdPolicyNotInstalled (fail-closed); got: {result_refresh:?}"
    );
}

// ── Cross-row request_id pairing across divergence emit ──────────────────────

/// `sign_with_passkey_rule` emits TWO audit rows — `SaSignerSetDiverged`
/// (from `verify_signer_set_against_chain`) AND `PasskeyAssertion(failure:signer_set_diverged)`
/// (from the outer `sign_with_passkey_rule` wrapper) — that share the SAME
/// `request_id` UUID.
///
/// Forensic-correlation invariant: both rows MUST land in the same JSONL file
/// (single shared writer) and carry the same `request_id` so operators can
/// correlate the divergence event with the signing attempt that triggered it.
///
/// # What this tests
///
/// `CredentialsManager::sign_with_passkey_rule` and `SignersManager` share the
/// same `Arc<Mutex<AuditWriter>>` so there is no second open and both rows land
/// in the same file.
///
/// # Setup
///
/// 1. Deploy a fresh smart account + install a 1-of-1 rule with threshold-policy.
/// 2. Inject a divergent `SaSignerSetBaselined` row (threshold=2 vs on-chain=1).
/// 3. Call `sign_with_passkey_rule` with `signers_manager = Some(sm)` where `sm`
///    wraps the shared `Arc<Mutex<AuditWriter>>`.
/// 4. The divergence check fires before the WebAuthn ceremony (no browser needed).
/// 5. Both `SaSignerSetDiverged` and `PasskeyAssertion` rows are emitted to the
///    SAME writer instance; verify that their `request_id` fields match.
///
/// # Note
///
/// The divergence refusal path reuses the signer-set verification flow;
/// the paired `PasskeyAssertion` audit row is wallet-internal
/// writer-sharing architecture, not an on-chain contract surface.
#[tokio::test(flavor = "multi_thread")]
async fn b6_audit_log_request_id_pairing_across_divergence_emit() {
    use std::io::{BufRead, BufReader};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    let (signer_g, signer_box) = fresh_signer();
    fund_via_friendbot(&signer_g).await;

    let sa_strkey = deploy_fresh_smart_account(&signer_g).await;
    let sa_addr =
        parse_c_strkey_to_smart_account(&sa_strkey).expect("deployed C-strkey must parse");

    // Install a 1-of-1 rule with the threshold-policy (required by
    // verify_signer_set_against_chain; bootstrap rule_id=0 has no policies).
    let (rule_id, _policy_strkey) =
        install_threshold_policy_on_fresh_sa(sa_addr.clone(), &signer_g, signer_box.as_ref()).await;

    // ── Shared AuditWriter + SignersManager ───────────────────────────────────

    let (audit_writer, audit_log_path, _dir) = tmp_audit_writer();
    // Key invariant: the same Arc<Mutex<AuditWriter>> is held by BOTH:
    //   - SignersManager (emits SaSignerSetDiverged inside verify_signer_set_against_chain)
    //   - sign_with_passkey_rule outer wrapper (emits PasskeyAssertion via sm.audit_writer())
    // Both managers share the same Arc so there is no second open on the same path.
    let sm = Arc::new(fresh_signers_manager(
        Arc::clone(&audit_writer),
        audit_log_path.clone(),
    ));

    // ── Inject divergent baseline ─────────────────────────────────────────────

    let smart_account_redacted = redact_strkey_first5_last5(&sa_strkey);
    let fabricated_state = ObservedSignerSet {
        signer_count: 1,
        threshold: 2, // diverges from on-chain threshold=1
        signer_ids: vec![0],
        signer_pubkeys: vec![SignerPubkey::Ed25519 {
            pubkey: [0xaau8; 32],
        }],
    };
    {
        let mut writer = audit_writer.lock().expect("audit writer lock for inject");
        let prev_chain_tip = writer.current_chain_tip();
        let entry = AuditEntry::new_sa_signer_set_baselined(
            rule_id,
            &fabricated_state,
            vec!["aaaaaaaaaaaaaaaa".to_owned()],
            0,
            BaselineReason::first_observation(),
            prev_chain_tip,
            RedactedStrkey::from_already_redacted(smart_account_redacted.as_str()),
            CHAIN_ID,
            rid(),
        );
        writer
            .write_entry(entry)
            .expect("baseline inject must succeed");
    }

    // ── Call sign_with_passkey_rule ───────────────────────────────────────────
    //
    // CredentialsManager is constructed without an approval store (None) because
    // the divergence check fires BEFORE the approval-store check.  No browser
    // ceremony is triggered.
    //
    // passkeys_dir is a tempdir; credential lookup will fail with NotFound (but
    // divergence fires first, so we never reach the credential lookup).
    let tmpdir = tempfile::tempdir().expect("tempdir must succeed");
    let creds_mgr = CredentialsManager::new(
        tmpdir.path().join("passkeys"),
        "default",
        "localhost",
        None, // no approval store: divergence fires before the store check
    );

    // Provide a fake bridge address (divergence fires before any bridge I/O).
    let bridge_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 19906);
    let auth_digest = [0u8; 32];

    let outcome = creds_mgr
        .sign_with_passkey_rule(
            "does-not-matter", // credential lookup never reached
            &sa_strkey,
            &auth_digest,
            vec![rule_id],
            Some(Arc::clone(&sm)),
            bridge_addr,
            Duration::from_millis(500),
            |_| {}, // url callback: never invoked (divergence fires first)
            true,   // accept_single_verifier: bypass diversification (tests signer divergence)
        )
        .await;

    // Outcome MUST be SignerSetDivergence (on-chain threshold=1 ≠ baseline=2).
    assert!(
        matches!(outcome, Err(CredentialsError::SignerSetDivergence { .. })),
        "sign_with_passkey_rule must return SignerSetDivergence \
         when the baseline claims a different threshold than on-chain; got: {outcome:?}"
    );

    // ── Scan audit rows for request_id pairing ────────────────────────────────

    // Drop the lock guard if any (the managers released it; scanning is safe).
    let log_path = {
        let guard = audit_writer.lock().expect("audit writer lock for path");
        guard.path().to_path_buf()
    };

    let file = std::fs::File::open(&log_path)
        .expect("audit log file must exist after sign_with_passkey_rule");
    let reader = BufReader::new(file);

    use stellar_agent_core::audit_log::schema::EventKind;

    // Retain the full entry for each row so we can check both request_id AND
    // smart_account_redacted across the two-row set (forensic-correlation invariant).
    let mut diverged_entry: Option<AuditEntry> = None;
    let mut assertion_entry: Option<AuditEntry> = None;

    for line in reader.lines() {
        let line = line.expect("audit log line must be valid UTF-8");
        if line.trim().is_empty() {
            continue;
        }
        let Ok(entry) = serde_json::from_str::<AuditEntry>(&line) else {
            continue;
        };

        match &entry.event_kind {
            EventKind::SaSignerSetDiverged { .. } => {
                diverged_entry = Some(entry);
            }
            // Only the failure:signer_set_diverged row from this signing call
            // matters; skip any rows from the baseline injection.
            EventKind::PasskeyAssertion { result, .. }
                if result == "failure:signer_set_diverged" =>
            {
                assertion_entry = Some(entry);
            }
            _ => {}
        }
    }

    // Both rows MUST have been emitted.
    let diverged =
        diverged_entry.expect("SaSignerSetDiverged audit row must be present in the audit log");
    let assertion = assertion_entry
        .expect("PasskeyAssertion(failure:signer_set_diverged) audit row must be present");

    // Both rows MUST share the SAME request_id UUID — forensic correlation.
    assert_eq!(
        diverged.request_id, assertion.request_id,
        "SaSignerSetDiverged and PasskeyAssertion rows MUST share the same \
         request_id UUID (cross-row forensic correlation invariant); \
         SaSignerSetDiverged.request_id={}, PasskeyAssertion.request_id={}",
        diverged.request_id, assertion.request_id,
    );

    // Both rows MUST carry the SAME smart_account_redacted value.
    let diverged_sa = match &diverged.event_kind {
        EventKind::SaSignerSetDiverged {
            smart_account_redacted,
            ..
        } => smart_account_redacted.clone(),
        _ => unreachable!("matched as SaSignerSetDiverged above"),
    };
    let assertion_sa = match &assertion.event_kind {
        EventKind::PasskeyAssertion {
            smart_account_redacted,
            ..
        } => smart_account_redacted.clone(),
        _ => unreachable!("matched as PasskeyAssertion above"),
    };
    assert_eq!(
        diverged_sa, assertion_sa,
        "SaSignerSetDiverged and PasskeyAssertion rows MUST carry the same \
         smart_account_redacted value (forensic-correlation invariant); \
         SaSignerSetDiverged.smart_account_redacted={diverged_sa}, \
         PasskeyAssertion.smart_account_redacted={assertion_sa}"
    );
}
