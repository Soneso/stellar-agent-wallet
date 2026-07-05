//! Testnet acceptance test for smart-account ergonomics (Package C, GH issue #9).
//!
//! Exercises the unified policy-deploy verb, the weighted-threshold
//! mutators, non-Delegated genesis signers on `deploy-c`, and batch signer
//! add against testnet.
//!
//! # Coverage
//!
//! 1. `deploy_policy_all_kinds_and_idempotent_testnet_acceptance` — deploys
//!    all three `PolicyDeployKind`s fresh, re-runs each with the same
//!    deployer (idempotent `already_deployed`), and confirms registry
//!    entries.
//! 2. `weighted_threshold_ordering_proof_testnet_acceptance` — installs a
//!    weighted-threshold policy with a mixed Delegated + External
//!    `signer_weights` map (2/1, threshold 2) on a rule whose signers are the
//!    same Delegated operator + External agent; the install submission
//!    itself proves heterogeneous-signer-key map ordering is host-accepted.
//!    Verified via the exported `get_threshold` / `get_signer_weights` views
//!    (`get_weighted_threshold_data`).
//! 3. `weighted_threshold_enforcement_proof_testnet_acceptance` — a separate
//!    rule with two Delegated signers, weighted install (1/1, threshold 1):
//!    single-signer (A) auth succeeds; `set_signer_weight` bumps signer B's
//!    weight 1 -> 2 authorized by A ALONE (must run before the retune, since
//!    the mutators are single-signer-authorized, not quorum — threshold is
//!    still 1 at this point), with the pre-read old weight asserted in the
//!    audit row; `set_weighted_threshold` to 2 (still authorized by A alone,
//!    against the pre-call threshold of 1); the same single-signer (A) auth
//!    now fails (3213 `NotAllowed`, weight 1 < threshold 2); dual-signer auth
//!    via `AuthorizationInfo`/`collect_quorum_signatures` succeeds (weight
//!    sum 1 + 2 = 3 >= threshold 2).
//! 4. `deploy_c_external_ed25519_genesis_testnet_acceptance` — two decoupled
//!    claims kept in one test: (a) deploys a smart account with an
//!    External(ed25519-verifier) genesis signer (no browser); the bootstrap
//!    rule's sole signer is verified on-chain via `get_rule_signers`; (b) on
//!    a SEPARATE, ordinarily Delegated-genesis account, attaches a
//!    simple-threshold(1) policy to a fresh rule and `add_signer`s a
//!    fallback co-signer. The two claims are decoupled because
//!    `install_rule` / `add_signer` / `batch_add_signers` authorize only via
//!    the Delegated (G-key) `Signer` flow — a rule whose sole signer is
//!    External cannot self-authorize a further mutation through this
//!    wallet's current tooling.
//! 5. `deploy_c_webauthn_genesis_and_batch_add_testnet_acceptance`
//!    (`#[ignore]`, requires Chromium) — likewise two decoupled claims: (a)
//!    a CDP virtual-authenticator registration ceremony produces a real
//!    WebAuthn credential, used as a smart account's sole genesis signer,
//!    verified on-chain via `get_rule_signers`; (b) on a SEPARATE,
//!    ordinarily Delegated-genesis account, `batch_add_signers` THREE
//!    signers (Delegated, External-Ed25519, External-WebAuthn — the last
//!    from a second credential registered in the same browser session) in
//!    one transaction; the resulting four-signer set is verified on-chain.
//! 6. `batch_add_delegated_signers_testnet_acceptance` — NOT `#[ignore]`d:
//!    `batch_add_signers` with THREE Delegated signers in one transaction on
//!    a simple-threshold rule. Puts the batch-add success path and its
//!    `new_signer_ids` extraction (`rev().take(n).rev()` over the resulting
//!    `signer_ids`) into every routine (non-Chromium) CI leg — cross-checked
//!    against a separate `get_rule_signers` read of the complete post-batch
//!    signer-id set, plus the per-signer `SaSignerAdded` audit rows.
//! 7. `weighted_threshold_negatives_testnet_acceptance` — `set_signer_weight`
//!    / `set_weighted_threshold` against a rule with no weighted-threshold
//!    policy fail with `WeightedThresholdNotInstalled`. On a rule whose ONLY
//!    threshold policy is weighted-threshold — the hardening item this Block
//!    closed — `refresh_signer_baseline` (which identifies a simple-threshold
//!    policy internally) fails with a typed `ThresholdPolicyNotInstalled` /
//!    `ThresholdPolicyIdentificationFailed`, and `batch_add_signers` on the
//!    same never-baselined rule fails at its OWN first pre-flight check
//!    (`SignerSetMissingBaseline`) before reaching policy identification at
//!    all — either refusal leaves no on-chain side effect.
//!
//! Client-side refusal of a weighted install whose threshold exceeds the
//! signer-weight sum, and `batch_add_signers`'s empty-batch refusal, are
//! already covered by offline unit tests
//! (`weighted_threshold_policy::tests::threshold_exceeding_weight_sum_is_refused`,
//! `managers::signers::tests::batch_add_signers_refuses_empty_batch_before_any_io`)
//! and are not duplicated here. The `deploy-c` external-genesis-without-ack
//! refusal guard is likewise covered by an offline CLI unit test
//! (`deploy_c_external_genesis_without_ack_is_refused`) — it fires before any
//! RPC call, so a live re-test would add no coverage.
//!
//! # Gate
//!
//! Compiled only under `--features testnet-integration`:
//!
//! ```text
//! cargo test --features testnet-integration \
//!   --test smart_account_ergonomics_testnet_acceptance
//! ```
//!
//! Test 5 additionally requires a Chromium binary on `PATH` (or `CHROME` env
//! var) and is marked `#[ignore]`; run it explicitly with:
//!
//! ```text
//! cargo test --features testnet-integration \
//!   --test smart_account_ergonomics_testnet_acceptance -- --ignored
//! ```
//!
//! # Reference cross-check
//!
//! - OZ `examples/multisig-smart-account/weighted-threshold-policy/src/contract.rs`
//!   (SHA `a9c4216`) — `install` / `set_threshold` / `set_signer_weight` /
//!   `get_threshold` / `get_signer_weights`.
//! - OZ `examples/multisig-smart-account/account/src/contract.rs:43` — `batch_add_signer`.

#![cfg(feature = "testnet-integration")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics are acceptable in testnet acceptance tests"
)]

mod common;

use std::io::BufRead;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chromiumoxide::browser::{Browser, BrowserConfig};
use chromiumoxide::cdp::browser_protocol::web_authn::{
    AddVirtualAuthenticatorParams, AuthenticatorProtocol, AuthenticatorTransport, EnableParams,
    VirtualAuthenticatorOptions,
};
use common::{TESTNET_PASSPHRASE, TESTNET_RPC_URL, fund_via_friendbot};
use ed25519_dalek::SigningKey;
use futures::StreamExt as _;
use rand_core::{OsRng, RngCore};
use sha2::{Digest as _, Sha256};
use stellar_agent_core::approval::store::PendingApprovalStore;
use stellar_agent_core::audit_log::entry::AuditEntry;
use stellar_agent_core::audit_log::schema::EventKind;
use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_core::observability::is_loopback_http_url;
use stellar_agent_core::smart_account::rule_id::ContextRuleId;
use stellar_agent_network::signing::envelope_signing::attach_signature;
use stellar_agent_network::{Signer, SoftwareSigningKey, StellarRpcClient, fetch_account};
use stellar_agent_smart_account::deployment::{
    DeployerKeypair, DeploymentArgs, Ed25519VerifierDeployArgs,
    ResolvedFeePerOp as DeployResolvedFeePerOp, WebAuthnVerifierDeployArgs,
    deploy_ed25519_verifier, deploy_policy, deploy_smart_account, deploy_webauthn_verifier,
    derive_smart_account_address,
};
use stellar_agent_smart_account::error::SaError;
use stellar_agent_smart_account::managers::authorization::{
    AuthorizationInfo, Combinator, SignerGroup,
};
use stellar_agent_smart_account::managers::credentials::{AddPasskeyOutcome, CredentialsManager};
use stellar_agent_smart_account::managers::rules::{
    ContextRuleDefinition, ContextRuleManager, ContextRuleManagerConfig, ContextRulePolicy,
    ContextRuleSignerInput, RuleContext, parse_c_strkey_to_smart_account,
    parse_g_strkey_to_signer_address,
};
use stellar_agent_smart_account::managers::signers::{SignersManager, SignersManagerConfig};
use stellar_agent_smart_account::managers::signers::{
    build_delegated_signer_scval, build_external_signer_scval,
};
use stellar_agent_smart_account::signers::policy_identification::THRESHOLD_POLICY_WASM;
use stellar_agent_smart_account::submit::{SubmitInvokeArgs, submit_signed_invoke};
use stellar_agent_smart_account::verifiers::VerifierRegistry;
use stellar_agent_smart_account::weighted_threshold_policy::{
    WEIGHTED_THRESHOLD_POLICY_WASM_SHA256, WeightedThresholdSignerInput,
    build_weighted_threshold_install_param,
};
use stellar_baselib::account::{Account as BaselibAccount, AccountBehavior};
use stellar_baselib::transaction::{Transaction, TransactionBehavior};
use stellar_baselib::transaction_builder::{TransactionBuilder, TransactionBuilderBehavior};
use stellar_rpc_client::Client;
use stellar_xdr::{
    AccountId, BytesM, ContractExecutable, ContractIdPreimage, ContractIdPreimageFromAddress,
    CreateContractArgsV2, Hash, HostFunction, InvokeContractArgs, InvokeHostFunctionOp, LedgerKey,
    LedgerKeyContractCode, Limits, Operation, OperationBody, PublicKey as XdrPublicKey, ScAddress,
    ScMap, ScMapEntry, ScSymbol, ScVal, ScVec, SorobanAuthorizationEntry, Uint256, VecM, WriteXdr,
};
use tempfile::TempDir;
use uuid::Uuid;
use zeroize::Zeroizing;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const CHAIN_ID: &str = "stellar:testnet";
const TIMEOUT_SECS: u64 = 120;
const FEE_STROOPS: u32 = 1_000_000;

/// RP-ID for the WebAuthn ceremony. `"localhost"` is the correct loopback
/// RP-ID per WebAuthn Level 2 §5.1.2; IP literals are not valid RP-IDs.
const TEST_RP_ID: &str = "localhost";

// ─────────────────────────────────────────────────────────────────────────────
// Helpers: keys, deployers, managers
// ─────────────────────────────────────────────────────────────────────────────

fn rid() -> String {
    Uuid::new_v4().to_string()
}

/// Generates a fresh ed25519 keypair. Returns `(g_strkey, software_signer)`.
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

/// Generates a fresh ed25519 keypair and returns `(g_strkey, raw_seed)` so the
/// caller can construct MULTIPLE independent `DeployerKeypair`s wrapping the
/// SAME underlying key (needed to re-run a deploy with an identical deployer
/// G-key for the idempotent-address proof).
fn fresh_reusable_seed() -> (String, [u8; 32]) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let g_strkey = format!(
        "{}",
        stellar_strkey::ed25519::PublicKey(signing_key.verifying_key().to_bytes())
    );
    (g_strkey, signing_key.to_bytes())
}

/// Wraps a raw ed25519 seed in a fresh `DeployerKeypair::SecretEnv`.
fn deployer_from_seed(seed: [u8; 32], var_name: &'static str) -> DeployerKeypair {
    let signer: Box<dyn Signer + Send + Sync> =
        Box::new(SoftwareSigningKey::new_from_zeroizing(Zeroizing::new(seed)));
    DeployerKeypair::SecretEnv {
        var_name: var_name.to_owned(),
        signer,
    }
}

/// Generates a fresh deployer keypair wrapped in `DeployerKeypair::SecretEnv`.
fn fresh_deployer_keypair() -> (String, DeployerKeypair) {
    let (g_strkey, signer) = fresh_signer();
    let deployer = DeployerKeypair::SecretEnv {
        var_name: "testnet-ergonomics-acceptance-generated".to_owned(),
        signer,
    };
    (g_strkey, deployer)
}

/// Opens a temporary `AuditWriter` and returns `(Arc<Mutex<writer>>, path, TempDir)`.
fn tmp_audit_writer() -> (Arc<Mutex<AuditWriter>>, PathBuf, TempDir) {
    let dir = tempfile::tempdir().expect("tempdir must succeed");
    let path = dir.path().join("audit.jsonl");
    let writer = AuditWriter::open(path.clone(), None).expect("AuditWriter::open must succeed");
    (Arc::new(Mutex::new(writer)), path, dir)
}

/// Reads back every `AuditEntry` from a JSONL audit log.
fn read_audit_entries(log_path: &Path) -> Vec<AuditEntry> {
    let file = std::fs::File::open(log_path).expect("audit log file must be readable");
    let reader = std::io::BufReader::new(file);
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

/// Constructs a `ContextRuleManager` against testnet.
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
        "ergonomics-acceptance".to_owned(),
        Duration::from_secs(TIMEOUT_SECS),
        CHAIN_ID.to_owned(),
    ))
    .expect("SignersManager::new must succeed")
}

/// Deploys a fresh smart account whose bootstrap rule (rule_id 0) uses
/// `initial_signer_g` as its sole `Delegated` signer with no policies, unless
/// `genesis_override` is supplied (replaces the sole genesis signer entirely).
async fn deploy_fresh_smart_account(
    initial_signer_g: &str,
    genesis_override: Option<ScVal>,
) -> String {
    let (deployer_g, deployer) = fresh_deployer_keypair();
    fund_via_friendbot(&deployer_g).await;

    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);

    let args = DeploymentArgs {
        deployer,
        initial_signer: initial_signer_g.to_owned(),
        salt,
        network_passphrase: TESTNET_PASSPHRASE.to_owned(),
        rpc_url: TESTNET_RPC_URL.to_owned(),
        timeout: Duration::from_secs(TIMEOUT_SECS),
        fee: DeployResolvedFeePerOp {
            stroops: 1_000_000,
            percentile_label: "explicit".to_owned(),
        },
        dry_run: false,
        genesis_signer_scval_override: genesis_override,
    };
    deploy_smart_account(args, None)
        .await
        .expect("smart-account deployment must succeed on testnet")
        .smart_account
}

/// Deploys the OZ simple threshold-policy WASM at a deterministic, idempotent
/// address (tolerates `AlreadyExists` on a repeat run). Returns the deployed
/// C-strkey.
///
/// Mirrors `deploy_threshold_policy_wasm` in
/// `smart_account_policy_observability_testnet_acceptance.rs`: `deploy_policy`
/// (`PolicyDeployKind::SimpleThreshold`) is exercised directly in
/// `deploy_policy_all_kinds_and_idempotent_testnet_acceptance`; this helper
/// exists only for the OTHER tests in this file that need a quick
/// simple-threshold(1) policy attached without re-deriving `PolicyDeployArgs`
/// plumbing at every call site.
async fn deploy_simple_threshold_policy_wasm(
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

        stellar_agent_network::submit_transaction_and_wait(
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

    let deploy_result = stellar_agent_network::submit_transaction_and_wait(
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
                panic!("deploy simple-threshold-policy tx failed: {e}");
            }
        }
    }

    policy_strkey
}

/// Encodes `SimpleThresholdAccountParams { threshold: N }` as a Soroban ScVal.
fn encode_simple_threshold_params(threshold: u32) -> ScVal {
    let entry = ScMapEntry {
        key: ScVal::Symbol(ScSymbol::try_from("threshold").expect("'threshold' fits ScSymbol")),
        val: ScVal::U32(threshold),
    };
    ScVal::Map(Some(ScMap(
        vec![entry].try_into().expect("single-entry map fits ScMap"),
    )))
}

/// Builds the `execute(target, target_fn, target_args)` `HostFunction` that
/// routes a policy-contract call through the smart account's `execute()`
/// entrypoint (avoids Soroban re-entry; the standard pattern for reading or
/// mutating a policy contract's own storage from an authorized rule).
fn execute_host_function(
    smart_account: ScAddress,
    target: ScAddress,
    target_fn: &str,
    target_args: Vec<ScVal>,
) -> HostFunction {
    let inner_args: VecM<ScVal> = target_args
        .try_into()
        .expect("target_args must fit VecM<ScVal>");
    let execute_args: VecM<ScVal> = vec![
        ScVal::Address(target),
        ScVal::Symbol(ScSymbol::try_from(target_fn).expect("target_fn must fit ScSymbol")),
        ScVal::Vec(Some(ScVec(inner_args))),
    ]
    .try_into()
    .expect("execute_args must fit VecM<ScVal>");
    HostFunction::InvokeContract(InvokeContractArgs {
        contract_address: smart_account,
        function_name: ScSymbol::try_from("execute").expect("'execute' fits ScSymbol"),
        args: execute_args,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 1: deploy-policy — all three kinds, fresh + idempotent, registry entries
// ─────────────────────────────────────────────────────────────────────────────

/// Deploys all three `PolicyDeployKind`s fresh, re-deploys each with the SAME
/// deployer G-key (idempotent `already_deployed`, deterministic salt-per-kind
/// address), and confirms each kind's `VerifierRegistry` entry round-trips.
#[tokio::test]
async fn deploy_policy_all_kinds_and_idempotent_testnet_acceptance() {
    use stellar_agent_smart_account::deployment::{PolicyDeployArgs, PolicyDeployKind};

    let tmp = tempfile::tempdir().expect("tempdir must be created");
    let registry_path = tmp.path().join("networks.toml");

    let (deployer_g, deployer_seed) = fresh_reusable_seed();
    fund_via_friendbot(&deployer_g).await;

    for kind in [
        PolicyDeployKind::SimpleThreshold,
        PolicyDeployKind::SpendingLimit,
        PolicyDeployKind::WeightedThreshold,
    ] {
        let fresh_args = PolicyDeployArgs {
            kind,
            deployer: deployer_from_seed(deployer_seed, "ergonomics-deploy-policy-fresh"),
            network_passphrase: TESTNET_PASSPHRASE.to_owned(),
            rpc_url: TESTNET_RPC_URL.to_owned(),
            timeout: Duration::from_secs(TIMEOUT_SECS),
            fee: DeployResolvedFeePerOp {
                stroops: 1_000_000,
                percentile_label: "explicit".to_owned(),
            },
            dry_run: false,
            registry_path_override: Some(registry_path.clone()),
        };
        let fresh_result = deploy_policy(fresh_args, None)
            .await
            .unwrap_or_else(|e| panic!("deploy_policy({}) must succeed: {e}", kind.label()));
        assert_eq!(
            fresh_result.status,
            "deployed",
            "first deploy_policy({}) must report status=deployed",
            kind.label()
        );
        assert!(
            fresh_result.tx_hash.is_some(),
            "first deploy_policy({}) must carry a tx_hash",
            kind.label()
        );
        stellar_strkey::Contract::from_string(&fresh_result.policy_address).unwrap_or_else(|_| {
            panic!("{}: policy_address must be a valid C-strkey", kind.label())
        });

        let repeat_args = PolicyDeployArgs {
            kind,
            deployer: deployer_from_seed(deployer_seed, "ergonomics-deploy-policy-repeat"),
            network_passphrase: TESTNET_PASSPHRASE.to_owned(),
            rpc_url: TESTNET_RPC_URL.to_owned(),
            timeout: Duration::from_secs(TIMEOUT_SECS),
            fee: DeployResolvedFeePerOp {
                stroops: 1_000_000,
                percentile_label: "explicit".to_owned(),
            },
            dry_run: false,
            registry_path_override: Some(registry_path.clone()),
        };
        let repeat_result = deploy_policy(repeat_args, None)
            .await
            .unwrap_or_else(|e| panic!("repeat deploy_policy({}) must succeed: {e}", kind.label()));
        assert_eq!(
            repeat_result.status,
            "already_deployed",
            "repeat deploy_policy({}) with the same deployer must report already_deployed",
            kind.label()
        );
        assert_eq!(
            repeat_result.policy_address,
            fresh_result.policy_address,
            "{}: repeat deploy must derive the SAME address as the fresh deploy",
            kind.label()
        );
        assert!(
            repeat_result.tx_hash.is_none(),
            "{}: already_deployed result must not carry a tx_hash",
            kind.label()
        );

        let registry =
            VerifierRegistry::open_at(registry_path.clone()).expect("registry open must succeed");
        match kind {
            PolicyDeployKind::SimpleThreshold => {
                let entry = registry
                    .simple_threshold_policy_for(TESTNET_PASSPHRASE)
                    .expect("simple-threshold registry entry must exist");
                assert_eq!(entry.address, fresh_result.policy_address);
            }
            PolicyDeployKind::SpendingLimit => {
                let entry = registry
                    .spending_limit_policy_for(TESTNET_PASSPHRASE)
                    .expect("spending-limit registry entry must exist");
                assert_eq!(entry.address, fresh_result.policy_address);
            }
            PolicyDeployKind::WeightedThreshold => {
                let entry = registry
                    .weighted_threshold_policy_for(TESTNET_PASSPHRASE)
                    .expect("weighted-threshold registry entry must exist");
                assert_eq!(entry.address, fresh_result.policy_address);
                assert_eq!(
                    entry.wasm_sha256, WEIGHTED_THRESHOLD_POLICY_WASM_SHA256,
                    "persisted weighted-threshold WASM hash must match the vendored hash"
                );
            }
            other => panic!("unhandled PolicyDeployKind variant: {other:?}"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 2: weighted-threshold ordering proof (3a)
// ─────────────────────────────────────────────────────────────────────────────

/// Installs a weighted-threshold policy with a mixed Delegated + External
/// `signer_weights` map (weights 2/1, threshold 2) on a rule whose signers
/// are the SAME Delegated operator + External agent. The install submission
/// itself — authorized by the genesis signer — is the on-chain proof that a
/// heterogeneous Delegated+External `signer_weights` map is host-accepted.
/// Verified via `get_weighted_threshold_data` (the exported `get_threshold` /
/// `get_signer_weights` views).
#[tokio::test]
async fn weighted_threshold_ordering_proof_testnet_acceptance() {
    let tmp = tempfile::tempdir().expect("tempdir must be created");
    let registry_path = tmp.path().join("networks.toml");

    let (verifier_deployer_g, verifier_deployer) = fresh_deployer_keypair();
    fund_via_friendbot(&verifier_deployer_g).await;
    let verifier_result = deploy_ed25519_verifier(
        Ed25519VerifierDeployArgs {
            deployer: verifier_deployer,
            network_passphrase: TESTNET_PASSPHRASE.to_owned(),
            rpc_url: TESTNET_RPC_URL.to_owned(),
            timeout: Duration::from_secs(TIMEOUT_SECS),
            fee: DeployResolvedFeePerOp {
                stroops: 1_000_000,
                percentile_label: "explicit".to_owned(),
            },
            dry_run: false,
            registry_path_override: Some(registry_path.clone()),
        },
        None,
    )
    .await
    .expect("ed25519 verifier deployment must succeed on testnet");
    let verifier_sc_addr = parse_c_strkey_to_smart_account(&verifier_result.verifier_address)
        .expect("verifier C-strkey must parse");

    use stellar_agent_smart_account::deployment::{PolicyDeployArgs, PolicyDeployKind};
    let (policy_deployer_g, policy_deployer) = fresh_deployer_keypair();
    fund_via_friendbot(&policy_deployer_g).await;
    let policy_result = deploy_policy(
        PolicyDeployArgs {
            kind: PolicyDeployKind::WeightedThreshold,
            deployer: policy_deployer,
            network_passphrase: TESTNET_PASSPHRASE.to_owned(),
            rpc_url: TESTNET_RPC_URL.to_owned(),
            timeout: Duration::from_secs(TIMEOUT_SECS),
            fee: DeployResolvedFeePerOp {
                stroops: 1_000_000,
                percentile_label: "explicit".to_owned(),
            },
            dry_run: false,
            registry_path_override: Some(registry_path.clone()),
        },
        None,
    )
    .await
    .expect("weighted-threshold policy deployment must succeed on testnet");
    let weighted_policy_sc_addr = parse_c_strkey_to_smart_account(&policy_result.policy_address)
        .expect("weighted-threshold policy C-strkey must parse");

    let (operator_g, operator_signer_box) = fresh_signer();
    fund_via_friendbot(&operator_g).await;
    let smart_account_strkey = deploy_fresh_smart_account(&operator_g, None).await;
    let smart_account_sc = parse_c_strkey_to_smart_account(&smart_account_strkey)
        .expect("deployed smart-account C-strkey must parse");
    let operator_signer_sc =
        parse_g_strkey_to_signer_address(&operator_g).expect("operator G-strkey must parse");

    let agent_signing_key = SigningKey::generate(&mut OsRng);
    let agent_pubkey_bytes: [u8; 32] = agent_signing_key.verifying_key().to_bytes();

    let weighted_install_param = build_weighted_threshold_install_param(
        &[
            (
                WeightedThresholdSignerInput::Delegated {
                    g_strkey: operator_g.clone(),
                },
                2,
            ),
            (
                WeightedThresholdSignerInput::External {
                    verifier: verifier_sc_addr.clone(),
                    key_data: agent_pubkey_bytes.to_vec(),
                },
                1,
            ),
        ],
        2,
    )
    .expect("weighted-threshold install param must build");

    let rule_manager = fresh_rule_manager();
    let definition = ContextRuleDefinition::new(
        RuleContext::Default,
        "wt-ordering".to_owned(), // 11 bytes; OZ MAX_NAME_SIZE = 20
        None,
        vec![
            ContextRuleSignerInput::Delegated {
                address: operator_signer_sc,
            },
            ContextRuleSignerInput::External {
                verifier: verifier_sc_addr,
                pubkey_data: agent_pubkey_bytes.to_vec(),
            },
        ],
        vec![ContextRulePolicy::new(
            weighted_policy_sc_addr.clone(),
            weighted_install_param,
        )],
    );
    let install_out = rule_manager
        .install_rule(
            smart_account_sc.clone(),
            definition,
            vec![ContextRuleId::new(0)],
            operator_signer_box.as_ref(),
            None,
            rid(),
            false,
            false,
        )
        .await
        .expect(
            "weighted-threshold rule install with a mixed Delegated+External \
             signer_weights map must succeed on-chain",
        );
    let rule_id = install_out.rule_id;
    assert!(rule_id != 0, "installed rule_id must differ from bootstrap");

    let (audit_writer, audit_log_path, _audit_dir) = tmp_audit_writer();
    let signers_mgr = fresh_signers_manager(audit_writer, audit_log_path);

    let identified_policy = signers_mgr
        .identify_weighted_threshold_policy(
            smart_account_sc.clone(),
            rule_id,
            Some(&operator_g),
            rid(),
        )
        .await
        .expect("identify_weighted_threshold_policy must succeed");
    assert_eq!(identified_policy, weighted_policy_sc_addr);

    let view = signers_mgr
        .get_weighted_threshold_data(
            identified_policy,
            rule_id,
            smart_account_sc.clone(),
            Some(&operator_g),
            rid(),
        )
        .await
        .expect("get_weighted_threshold_data must succeed");
    assert_eq!(view.threshold, 2, "installed threshold must be 2");

    let operator_key =
        build_delegated_signer_scval(&operator_g).expect("operator canonical key must encode");
    let agent_key = build_external_signer_scval(
        parse_c_strkey_to_smart_account(&verifier_result.verifier_address)
            .expect("verifier C-strkey must parse"),
        &agent_pubkey_bytes,
    )
    .expect("agent canonical key must encode");
    assert_eq!(
        view.weight_of(&operator_key),
        2,
        "operator (Delegated) weight must be 2"
    );
    assert_eq!(
        view.weight_of(&agent_key),
        1,
        "agent (External) weight must be 1"
    );
    assert_eq!(
        view.total_weight().expect("weight sum must not overflow"),
        3,
        "total weight must be the sum of both entries"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 3: weighted-threshold enforcement proof (3b)
// ─────────────────────────────────────────────────────────────────────────────

/// Two Delegated signers, weighted install (1/1, threshold 1). Executed
/// sequence:
/// 1. Single-signer (A) auth succeeds (weight 1 >= threshold 1).
/// 2. `set_signer_weight` bumps signer B's weight 1 -> 2, authorized by
///    signer A ALONE — this must run BEFORE the threshold retune below,
///    since `SignersManager::set_signer_weight` / `set_weighted_threshold`
///    authorize via a single `Signer`, not a quorum; at this point the
///    threshold is still 1, so A's weight-1 auth still satisfies it. The
///    audit row's pre-read old_weight (1) is asserted.
/// 3. `set_weighted_threshold` bumps the threshold 1 -> 2, still authorized
///    by signer A alone (the retune itself validates against the threshold
///    as it stood BEFORE this call takes effect, i.e. 1).
/// 4. The SAME single-signer (A) auth now fails (weight 1 < threshold 2).
/// 5. Dual-signer auth via `AuthorizationInfo` / `collect_quorum_signatures`
///    succeeds — the weight sum is now 1 (A) + 2 (B, bumped in step 2) = 3,
///    which is >= threshold 2.
#[tokio::test]
async fn weighted_threshold_enforcement_proof_testnet_acceptance() {
    let tmp = tempfile::tempdir().expect("tempdir must be created");
    let registry_path = tmp.path().join("networks.toml");

    use stellar_agent_smart_account::deployment::{PolicyDeployArgs, PolicyDeployKind};
    let (policy_deployer_g, policy_deployer) = fresh_deployer_keypair();
    fund_via_friendbot(&policy_deployer_g).await;
    let policy_result = deploy_policy(
        PolicyDeployArgs {
            kind: PolicyDeployKind::WeightedThreshold,
            deployer: policy_deployer,
            network_passphrase: TESTNET_PASSPHRASE.to_owned(),
            rpc_url: TESTNET_RPC_URL.to_owned(),
            timeout: Duration::from_secs(TIMEOUT_SECS),
            fee: DeployResolvedFeePerOp {
                stroops: 1_000_000,
                percentile_label: "explicit".to_owned(),
            },
            dry_run: false,
            registry_path_override: Some(registry_path.clone()),
        },
        None,
    )
    .await
    .expect("weighted-threshold policy deployment must succeed on testnet");
    let weighted_policy_sc_addr = parse_c_strkey_to_smart_account(&policy_result.policy_address)
        .expect("weighted-threshold policy C-strkey must parse");

    let (bootstrap_g, bootstrap_signer) = fresh_signer();
    fund_via_friendbot(&bootstrap_g).await;
    let (signer_a_g, signer_a) = fresh_signer();
    fund_via_friendbot(&signer_a_g).await;
    let (signer_b_g, signer_b) = fresh_signer();
    fund_via_friendbot(&signer_b_g).await;

    let smart_account_strkey = deploy_fresh_smart_account(&bootstrap_g, None).await;
    let smart_account_sc = parse_c_strkey_to_smart_account(&smart_account_strkey)
        .expect("deployed smart-account C-strkey must parse");

    let signer_a_sc =
        parse_g_strkey_to_signer_address(&signer_a_g).expect("signer A G-strkey must parse");
    let signer_b_sc =
        parse_g_strkey_to_signer_address(&signer_b_g).expect("signer B G-strkey must parse");

    let weighted_install_param = build_weighted_threshold_install_param(
        &[
            (
                WeightedThresholdSignerInput::Delegated {
                    g_strkey: signer_a_g.clone(),
                },
                1,
            ),
            (
                WeightedThresholdSignerInput::Delegated {
                    g_strkey: signer_b_g.clone(),
                },
                1,
            ),
        ],
        1,
    )
    .expect("weighted-threshold install param must build");

    let rule_manager = fresh_rule_manager();
    let definition = ContextRuleDefinition::new(
        RuleContext::Default,
        "wt-enforce".to_owned(), // 10 bytes
        None,
        vec![
            ContextRuleSignerInput::Delegated {
                address: signer_a_sc,
            },
            ContextRuleSignerInput::Delegated {
                address: signer_b_sc,
            },
        ],
        vec![ContextRulePolicy::new(
            weighted_policy_sc_addr.clone(),
            weighted_install_param,
        )],
    );
    let install_out = rule_manager
        .install_rule(
            smart_account_sc.clone(),
            definition,
            vec![ContextRuleId::new(0)],
            bootstrap_signer.as_ref(),
            None,
            rid(),
            false,
            false,
        )
        .await
        .expect("two-Delegated-signer weighted-threshold rule install must succeed");
    let rule_id = install_out.rule_id;

    let (audit_writer, audit_log_path, _audit_dir) = tmp_audit_writer();
    let signers_mgr = fresh_signers_manager(audit_writer, audit_log_path.clone());
    let auth_rule_ids = vec![ContextRuleId::new(rule_id)];

    // ── single-signer auth succeeds at threshold 1 ───────────────────────────
    let read_threshold_fn = execute_host_function(
        smart_account_sc.clone(),
        weighted_policy_sc_addr.clone(),
        "get_threshold",
        vec![
            ScVal::U32(rule_id),
            ScVal::Address(smart_account_sc.clone()),
        ],
    );
    let single_signer_result_1 = submit_signed_invoke(
        SubmitInvokeArgs::builder()
            .target_contract(&smart_account_strkey)
            .auth_rule_ids(auth_rule_ids.as_slice())
            .host_function(read_threshold_fn.clone())
            .signer(signer_a.as_ref())
            .primary_rpc_url(TESTNET_RPC_URL)
            .network_passphrase(TESTNET_PASSPHRASE)
            .chain_id(CHAIN_ID)
            .timeout(Duration::from_secs(TIMEOUT_SECS))
            .op_label("wt_enforce_single_signer_at_threshold_1")
            .emit_observability_logs(true)
            .build(),
    )
    .await;
    assert!(
        single_signer_result_1.is_ok(),
        "single-signer auth (weight 1) must succeed at threshold 1: {single_signer_result_1:?}"
    );

    // ── set_signer_weight: bump signer B's weight 1 -> 2 ─────────────────────
    //
    // `SignersManager::set_signer_weight` / `set_weighted_threshold` authorize
    // via a SINGLE `Signer`, not a quorum (unlike `submit_signed_invoke`'s
    // separate `maybe_authorization`/`signers` quorum path) — this step MUST
    // run while a single signer's weight alone still satisfies the CURRENT
    // threshold (1), i.e. before the threshold retune below; once threshold
    // is 2, no single weight-1 signer can self-authorize a further weighted-
    // policy mutation through this manager API (proven by the FAILING
    // single-signer read further down, which exercises the identical
    // authorization constraint on a plain read instead).
    let identified_policy = signers_mgr
        .identify_weighted_threshold_policy(
            smart_account_sc.clone(),
            rule_id,
            Some(&signer_a_g),
            rid(),
        )
        .await
        .expect("identify_weighted_threshold_policy must succeed");
    let view_before_bump = signers_mgr
        .get_weighted_threshold_data(
            identified_policy.clone(),
            rule_id,
            smart_account_sc.clone(),
            Some(&signer_a_g),
            rid(),
        )
        .await
        .expect("get_weighted_threshold_data before weight bump must succeed");
    let old_weight_pre_read = view_before_bump.weight_of(
        &build_delegated_signer_scval(&signer_b_g).expect("signer B canonical key must encode"),
    );
    assert_eq!(
        old_weight_pre_read, 1,
        "signer B's weight must be 1 pre-bump"
    );

    signers_mgr
        .set_signer_weight(
            smart_account_sc.clone(),
            rule_id,
            WeightedThresholdSignerInput::Delegated {
                g_strkey: signer_b_g.clone(),
            },
            2,
            &auth_rule_ids,
            signer_a.as_ref(),
            rid(),
        )
        .await
        .expect("set_signer_weight must succeed");

    let view_after_weight_bump = signers_mgr
        .get_weighted_threshold_data(
            identified_policy.clone(),
            rule_id,
            smart_account_sc.clone(),
            Some(&signer_a_g),
            rid(),
        )
        .await
        .expect("get_weighted_threshold_data after weight bump must succeed");
    assert_eq!(
        view_after_weight_bump.weight_of(
            &build_delegated_signer_scval(&signer_b_g).expect("signer B canonical key must encode")
        ),
        2,
        "signer B's weight must be 2 after the bump"
    );

    let entries_after_bump = read_audit_entries(&audit_log_path);
    let weight_changed_entry = entries_after_bump.iter().find_map(|e| match &e.event_kind {
        EventKind::SaSignerWeightChanged {
            rule_id: entry_rule_id,
            old_weight,
            new_weight,
            ..
        } if *entry_rule_id == rule_id => Some((*old_weight, *new_weight)),
        _ => None,
    });
    assert_eq!(
        weight_changed_entry,
        Some((1, 2)),
        "SaSignerWeightChanged audit row with old_weight=1, new_weight=2 must be emitted; \
         entries: {entries_after_bump:?}"
    );

    // ── retune threshold 1 -> 2 (authorized against the OLD threshold, 1;
    // signer A's weight-1 auth still satisfies it at the moment of this call) ──
    signers_mgr
        .set_weighted_threshold(
            smart_account_sc.clone(),
            rule_id,
            2,
            &auth_rule_ids,
            signer_a.as_ref(),
            rid(),
        )
        .await
        .expect("set_weighted_threshold to 2 must succeed");

    let view_after_retune = signers_mgr
        .get_weighted_threshold_data(
            identified_policy,
            rule_id,
            smart_account_sc.clone(),
            Some(&signer_a_g),
            rid(),
        )
        .await
        .expect("get_weighted_threshold_data after retune must succeed");
    assert_eq!(view_after_retune.threshold, 2, "threshold must now be 2");

    // ── the SAME single-signer auth now fails (weight 1 < threshold 2) ───────
    let single_signer_result_2 = submit_signed_invoke(
        SubmitInvokeArgs::builder()
            .target_contract(&smart_account_strkey)
            .auth_rule_ids(auth_rule_ids.as_slice())
            .host_function(read_threshold_fn.clone())
            .signer(signer_a.as_ref())
            .primary_rpc_url(TESTNET_RPC_URL)
            .network_passphrase(TESTNET_PASSPHRASE)
            .chain_id(CHAIN_ID)
            .timeout(Duration::from_secs(TIMEOUT_SECS))
            .op_label("wt_enforce_single_signer_at_threshold_2")
            .emit_observability_logs(true)
            .build(),
    )
    .await
    .expect_err("single-signer auth (weight 1) must fail once threshold is 2");
    match single_signer_result_2 {
        SaError::DeploymentFailed {
            phase: "simulate",
            ref redacted_reason,
        } => {
            assert!(
                redacted_reason.contains("[OZ:NotAllowed]")
                    || redacted_reason.contains("Error(Contract, #3213)"),
                "expected NotAllowed (3213); got: {redacted_reason}"
            );
        }
        other => panic!("expected DeploymentFailed{{phase:\"simulate\"}}; got {other:?}"),
    }

    // ── dual-signer auth via AuthorizationInfo/collect_quorum_signatures succeeds ──
    let signer_a_pk = stellar_strkey::ed25519::PublicKey::from_string(&signer_a_g)
        .expect("signer A G-strkey must parse")
        .0;
    let signer_b_pk = stellar_strkey::ed25519::PublicKey::from_string(&signer_b_g)
        .expect("signer B G-strkey must parse")
        .0;
    let group = SignerGroup::new(
        "wt-enforce-quorum".into(),
        vec![signer_a_pk, signer_b_pk],
        2,
    )
    .expect("SignerGroup must be valid");
    let authz = AuthorizationInfo::new(vec![group], Combinator::And);
    let quorum_signers: Vec<&(dyn Signer + Send + Sync)> =
        vec![signer_a.as_ref(), signer_b.as_ref()];

    let dual_signer_result = submit_signed_invoke(
        SubmitInvokeArgs::builder()
            .target_contract(&smart_account_strkey)
            .auth_rule_ids(auth_rule_ids.as_slice())
            .host_function(read_threshold_fn)
            .signer(signer_a.as_ref())
            .maybe_authorization(Some(&authz))
            .signers(quorum_signers.as_slice())
            .primary_rpc_url(TESTNET_RPC_URL)
            .network_passphrase(TESTNET_PASSPHRASE)
            .chain_id(CHAIN_ID)
            .timeout(Duration::from_secs(TIMEOUT_SECS))
            .op_label("wt_enforce_dual_signer_at_threshold_2")
            .emit_observability_logs(true)
            .build(),
    )
    .await;
    assert!(
        dual_signer_result.is_ok(),
        "dual-signer auth (weight sum 2) must succeed at threshold 2: {dual_signer_result:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 4: deploy-c External-Ed25519 genesis (no browser) + Delegated fallback
// ─────────────────────────────────────────────────────────────────────────────

/// Deploys a smart account with an `External(ed25519-verifier)` genesis
/// signer (no browser) and verifies the bootstrap rule's sole signer
/// on-chain via `get_rule_signers`.
///
/// `install_rule` / `add_signer` / `batch_add_signers` authorize exclusively
/// via the `Signer` trait's Delegated (G-key) signing flow — there is no
/// External/Agent-authorized variant of these three verbs (unlike
/// `submit_signed_invoke`'s separate `ed25519_rule_signer` parameter for
/// ordinary contract invocations). A rule whose sole signer is External
/// therefore cannot self-authorize a further rule mutation through this
/// wallet's current tooling; this test does not attempt one. The
/// "Delegated fallback co-signer" ergonomics this test's flow otherwise
/// exercises — attach simple-threshold(1), then `add_signer` a second
/// signer — is proven on a separately-deployed, ordinarily Delegated-genesis
/// account below, in the SAME test function to keep the two claims together.
#[tokio::test]
async fn deploy_c_external_ed25519_genesis_testnet_acceptance() {
    let tmp = tempfile::tempdir().expect("tempdir must be created");
    let registry_path = tmp.path().join("networks.toml");

    // ── Claim 1: External(ed25519-verifier) as sole genesis signer ───────────
    let (verifier_deployer_g, verifier_deployer) = fresh_deployer_keypair();
    fund_via_friendbot(&verifier_deployer_g).await;
    let verifier_result = deploy_ed25519_verifier(
        Ed25519VerifierDeployArgs {
            deployer: verifier_deployer,
            network_passphrase: TESTNET_PASSPHRASE.to_owned(),
            rpc_url: TESTNET_RPC_URL.to_owned(),
            timeout: Duration::from_secs(TIMEOUT_SECS),
            fee: DeployResolvedFeePerOp {
                stroops: 1_000_000,
                percentile_label: "explicit".to_owned(),
            },
            dry_run: false,
            registry_path_override: Some(registry_path.clone()),
        },
        None,
    )
    .await
    .expect("ed25519 verifier deployment must succeed on testnet");
    let verifier_sc_addr = parse_c_strkey_to_smart_account(&verifier_result.verifier_address)
        .expect("verifier C-strkey must parse");

    let genesis_signing_key = SigningKey::generate(&mut OsRng);
    let genesis_pubkey_bytes: [u8; 32] = genesis_signing_key.verifying_key().to_bytes();
    let genesis_scval = build_external_signer_scval(verifier_sc_addr, &genesis_pubkey_bytes)
        .expect("genesis External signer ScVal must encode");

    // The genesis signer itself never signs anything at deploy time (a native
    // Stellar account — the deployer — authorizes CreateContractV2); a fresh
    // ed25519 deployer key is used exactly as in every other deploy in this
    // file.
    let (deployer_g, _deployer_seed) = fresh_reusable_seed();
    let external_genesis_smart_account_strkey =
        deploy_fresh_smart_account(&deployer_g, Some(genesis_scval)).await;
    let external_genesis_smart_account_sc =
        parse_c_strkey_to_smart_account(&external_genesis_smart_account_strkey)
            .expect("deployed smart-account C-strkey must parse");

    let (audit_writer, audit_log_path, _audit_dir) = tmp_audit_writer();
    let signers_mgr = fresh_signers_manager(audit_writer, audit_log_path);

    let genesis_signers = signers_mgr
        .get_rule_signers(external_genesis_smart_account_sc, 0, None)
        .await
        .expect("get_rule_signers on the External-genesis bootstrap rule must succeed");
    assert_eq!(
        genesis_signers.len(),
        1,
        "bootstrap rule must carry exactly the External genesis signer at deploy time"
    );
    match &genesis_signers[0].1 {
        stellar_agent_core::audit_log::signer_set::SignerPubkey::External {
            verifier_contract,
            ..
        } => {
            assert_eq!(
                verifier_contract, &verifier_result.verifier_address,
                "genesis signer's verifier_contract must match the deployed ed25519 verifier"
            );
        }
        other => panic!("expected an External genesis signer; got {other:?}"),
    }

    // ── Claim 2: attach simple-threshold(1) + add_signer a fallback co-signer ─
    //
    // Ordinarily Delegated-genesis account: `add_signer`'s post-op
    // result-fetch requires a simple-threshold policy on the target rule
    // (hardening item (b)'s documented constraint); rule 0 is policy-less at
    // genesis, so the policy is attached via a fresh Default rule first.
    let (admin_g, admin_signer) = fresh_signer();
    fund_via_friendbot(&admin_g).await;
    let fallback_smart_account_strkey = deploy_fresh_smart_account(&admin_g, None).await;
    let fallback_smart_account_sc = parse_c_strkey_to_smart_account(&fallback_smart_account_strkey)
        .expect("deployed smart-account C-strkey must parse");

    let (policy_deployer_g, policy_deployer_box) = fresh_signer();
    fund_via_friendbot(&policy_deployer_g).await;
    let simple_threshold_policy_strkey =
        deploy_simple_threshold_policy_wasm(&policy_deployer_g, policy_deployer_box.as_ref()).await;
    let simple_threshold_policy_sc =
        parse_c_strkey_to_smart_account(&simple_threshold_policy_strkey)
            .expect("simple-threshold policy C-strkey must parse");

    let admin_sc = parse_g_strkey_to_signer_address(&admin_g).expect("admin G-strkey must parse");
    let rule_manager = fresh_rule_manager();
    let definition = ContextRuleDefinition::new(
        RuleContext::Default,
        "fallback-add".to_owned(), // 12 bytes
        None,
        vec![ContextRuleSignerInput::Delegated { address: admin_sc }],
        vec![ContextRulePolicy::new(
            simple_threshold_policy_sc,
            encode_simple_threshold_params(1),
        )],
    );
    let install_out = rule_manager
        .install_rule(
            fallback_smart_account_sc.clone(),
            definition,
            vec![ContextRuleId::new(0)],
            admin_signer.as_ref(),
            None,
            rid(),
            false,
            false,
        )
        .await
        .expect("simple-threshold rule install must succeed");
    let rule_id = install_out.rule_id;

    // `add_signer` requires an established audit-log baseline
    // (`SaError::SignerSetMissingBaseline` otherwise); a freshly-installed
    // rule has none until `refresh_signer_baseline` writes the first
    // `SaSignerSetBaselined` row.
    signers_mgr
        .refresh_signer_baseline(
            fallback_smart_account_sc.clone(),
            rule_id,
            Some(&admin_g),
            rid(),
        )
        .await
        .expect("refresh_signer_baseline must succeed");

    let (fallback_g, _fallback_signer) = fresh_signer();
    let fallback_scval =
        build_delegated_signer_scval(&fallback_g).expect("fallback signer ScVal must encode");
    let fallback_pubkey = stellar_strkey::ed25519::PublicKey::from_string(&fallback_g)
        .expect("fallback G-strkey must parse");
    let new_signer_id = signers_mgr
        .add_signer(
            fallback_smart_account_sc.clone(),
            rule_id,
            fallback_scval,
            stellar_agent_core::audit_log::signer_set::SignerPubkey::Ed25519 {
                pubkey: fallback_pubkey.0,
            },
            admin_signer.as_ref(),
            rid(),
        )
        .await
        .expect("add_signer (Delegated fallback co-signer) must succeed");
    assert!(new_signer_id > 0, "new signer id must be assigned");

    let final_signers = signers_mgr
        .get_rule_signers(fallback_smart_account_sc, rule_id, None)
        .await
        .expect("get_rule_signers on the retrofit rule must succeed");
    assert_eq!(
        final_signers.len(),
        2,
        "rule must carry the Delegated admin genesis signer + the added fallback co-signer"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: batch-add with 3 Delegated signers on a simple-threshold rule (no
// browser dependency — routine CI coverage for the batch-add success path)
// ─────────────────────────────────────────────────────────────────────────────

/// `batch_add_signers` with THREE Delegated signers, in one transaction, on a
/// rule carrying a simple-threshold policy. Not `#[ignore]`d: this is the
/// mandatory live-acceptance coverage for `batch_add_signers`'s success path
/// and its `new_signer_ids` ID-extraction logic (`rev().take(n).rev()` over
/// the resulting `signer_ids`), independent of the Chromium-gated
/// three-signer-KIND proof in the WebAuthn test.
///
/// Verifies:
/// - `new_signer_ids.len()` equals the batch length.
/// - The returned IDs, taken together with the pre-batch signer id, form the
///   COMPLETE post-batch on-chain signer-id set (cross-checked via a
///   SEPARATE `get_rule_signers` read) — this directly exercises the
///   `rev().take(n).rev()` extraction against ground truth, not merely a
///   length check.
/// - One `SaSignerAdded` audit row per new signer, each carrying the correct
///   `rule_id` and one of the returned `new_signer_ids`.
#[tokio::test]
async fn batch_add_delegated_signers_testnet_acceptance() {
    let (admin_g, admin_signer) = fresh_signer();
    fund_via_friendbot(&admin_g).await;
    let smart_account_strkey = deploy_fresh_smart_account(&admin_g, None).await;
    let smart_account_sc = parse_c_strkey_to_smart_account(&smart_account_strkey)
        .expect("deployed smart-account C-strkey must parse");

    let (policy_deployer_g, policy_deployer_box) = fresh_signer();
    fund_via_friendbot(&policy_deployer_g).await;
    let simple_threshold_policy_strkey =
        deploy_simple_threshold_policy_wasm(&policy_deployer_g, policy_deployer_box.as_ref()).await;
    let simple_threshold_policy_sc =
        parse_c_strkey_to_smart_account(&simple_threshold_policy_strkey)
            .expect("simple-threshold policy C-strkey must parse");

    let admin_sc = parse_g_strkey_to_signer_address(&admin_g).expect("admin G-strkey must parse");
    let rule_manager = fresh_rule_manager();
    let definition = ContextRuleDefinition::new(
        RuleContext::Default,
        "batch-add-deleg".to_owned(), // 15 bytes
        None,
        vec![ContextRuleSignerInput::Delegated { address: admin_sc }],
        vec![ContextRulePolicy::new(
            simple_threshold_policy_sc,
            encode_simple_threshold_params(1),
        )],
    );
    let install_out = rule_manager
        .install_rule(
            smart_account_sc.clone(),
            definition,
            vec![ContextRuleId::new(0)],
            admin_signer.as_ref(),
            None,
            rid(),
            false,
            false,
        )
        .await
        .expect("simple-threshold rule install must succeed");
    let rule_id = install_out.rule_id;

    let (audit_writer, audit_log_path, _audit_dir) = tmp_audit_writer();
    let signers_mgr = fresh_signers_manager(audit_writer, audit_log_path.clone());

    // `batch_add_signers` requires an established audit-log baseline. The
    // exact pre-batch id is not asserted here (OZ's signer-id numbering
    // scheme — per-rule vs. account-global — is not a documented contract
    // this test should pin); only the structural fact that exactly one
    // signer is observed is checked. The actual id is read back and used
    // below for the post-batch ground-truth cross-check.
    let baseline = signers_mgr
        .refresh_signer_baseline(smart_account_sc.clone(), rule_id, Some(&admin_g), rid())
        .await
        .expect("refresh_signer_baseline must succeed");
    assert_eq!(
        baseline.signer_ids.len(),
        1,
        "exactly one signer (the genesis participant) must be observed pre-batch"
    );
    let pre_batch_signer_id = baseline.signer_ids[0];

    let mut batch_signers = Vec::with_capacity(3);
    for _ in 0..3 {
        let (g, _signer) = fresh_signer();
        let scval = build_delegated_signer_scval(&g).expect("delegated signer ScVal must encode");
        let pubkey =
            stellar_strkey::ed25519::PublicKey::from_string(&g).expect("G-strkey must parse");
        batch_signers.push((
            scval,
            stellar_agent_core::audit_log::signer_set::SignerPubkey::Ed25519 { pubkey: pubkey.0 },
        ));
    }

    let new_signer_ids = signers_mgr
        .batch_add_signers(
            smart_account_sc.clone(),
            rule_id,
            batch_signers,
            admin_signer.as_ref(),
            rid(),
        )
        .await
        .expect("batch_add_signers (3 Delegated signers) must succeed in one transaction");
    assert_eq!(
        new_signer_ids.len(),
        3,
        "three new signer ids must be assigned"
    );

    // Cross-check the `rev().take(n).rev()` extraction against ground truth:
    // the returned IDs, plus the pre-batch signer's id, must equal the
    // COMPLETE post-batch on-chain signer-id set from a separate read.
    let post_batch_signers = signers_mgr
        .get_rule_signers(smart_account_sc, rule_id, None)
        .await
        .expect("get_rule_signers after the batch-add must succeed");
    let mut observed_ids: Vec<u32> = post_batch_signers.iter().map(|(id, _)| *id).collect();
    observed_ids.sort_unstable();
    let mut expected_ids = new_signer_ids.clone();
    expected_ids.push(pre_batch_signer_id);
    expected_ids.sort_unstable();
    assert_eq!(
        observed_ids, expected_ids,
        "new_signer_ids plus the pre-existing signer's id must equal the complete post-batch \
         signer-id set"
    );

    // One SaSignerAdded audit row per new signer, each naming one of the
    // returned IDs.
    let entries = read_audit_entries(&audit_log_path);
    let signer_added_ids: Vec<u32> = entries
        .iter()
        .filter_map(|e| match &e.event_kind {
            EventKind::SaSignerAdded {
                rule_id: entry_rule_id,
                signer_id,
                ..
            } if *entry_rule_id == rule_id => Some(*signer_id),
            _ => None,
        })
        .collect();
    let mut sorted_signer_added_ids = signer_added_ids.clone();
    sorted_signer_added_ids.sort_unstable();
    let mut sorted_new_signer_ids = new_signer_ids.clone();
    sorted_new_signer_ids.sort_unstable();
    assert_eq!(
        sorted_signer_added_ids, sorted_new_signer_ids,
        "exactly one SaSignerAdded row per new signer, naming the returned IDs; \
         entries: {entries:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 5: negatives
// ─────────────────────────────────────────────────────────────────────────────

/// `set_signer_weight` / `set_weighted_threshold` against a rule with NO
/// weighted-threshold policy fail with `WeightedThresholdNotInstalled`.
/// `batch_add_signers` against a rule whose ONLY threshold policy is
/// weighted-threshold fails closed with a typed pre-submission refusal and NO
/// on-chain side effect — the exact hardening item (b) constraint this Block
/// documents on `SignersManager::batch_add_signers`.
#[tokio::test]
async fn weighted_threshold_negatives_testnet_acceptance() {
    let tmp = tempfile::tempdir().expect("tempdir must be created");
    let registry_path = tmp.path().join("networks.toml");

    let (bootstrap_g, bootstrap_signer) = fresh_signer();
    fund_via_friendbot(&bootstrap_g).await;
    let smart_account_strkey = deploy_fresh_smart_account(&bootstrap_g, None).await;
    let smart_account_sc = parse_c_strkey_to_smart_account(&smart_account_strkey)
        .expect("deployed smart-account C-strkey must parse");

    let (audit_writer, audit_log_path, _audit_dir) = tmp_audit_writer();
    let signers_mgr = fresh_signers_manager(audit_writer, audit_log_path);
    let admin_auth = vec![ContextRuleId::new(0)];

    // ── set_weighted_threshold / set_signer_weight against rule 0 (no policy) ──
    let set_threshold_err = signers_mgr
        .set_weighted_threshold(
            smart_account_sc.clone(),
            0,
            2,
            &admin_auth,
            bootstrap_signer.as_ref(),
            rid(),
        )
        .await
        .expect_err("set_weighted_threshold against a policy-less rule must fail");
    assert!(
        matches!(
            set_threshold_err,
            SaError::WeightedThresholdNotInstalled { .. }
        ),
        "expected WeightedThresholdNotInstalled; got {set_threshold_err:?}"
    );

    let set_weight_err = signers_mgr
        .set_signer_weight(
            smart_account_sc.clone(),
            0,
            WeightedThresholdSignerInput::Delegated {
                g_strkey: bootstrap_g.clone(),
            },
            2,
            &admin_auth,
            bootstrap_signer.as_ref(),
            rid(),
        )
        .await
        .expect_err("set_signer_weight against a policy-less rule must fail");
    assert!(
        matches!(
            set_weight_err,
            SaError::WeightedThresholdNotInstalled { .. }
        ),
        "expected WeightedThresholdNotInstalled; got {set_weight_err:?}"
    );

    // ── batch_add_signers against a rule whose ONLY policy is weighted ───────
    use stellar_agent_smart_account::deployment::{PolicyDeployArgs, PolicyDeployKind};
    let (policy_deployer_g, policy_deployer) = fresh_deployer_keypair();
    fund_via_friendbot(&policy_deployer_g).await;
    let policy_result = deploy_policy(
        PolicyDeployArgs {
            kind: PolicyDeployKind::WeightedThreshold,
            deployer: policy_deployer,
            network_passphrase: TESTNET_PASSPHRASE.to_owned(),
            rpc_url: TESTNET_RPC_URL.to_owned(),
            timeout: Duration::from_secs(TIMEOUT_SECS),
            fee: DeployResolvedFeePerOp {
                stroops: 1_000_000,
                percentile_label: "explicit".to_owned(),
            },
            dry_run: false,
            registry_path_override: Some(registry_path.clone()),
        },
        None,
    )
    .await
    .expect("weighted-threshold policy deployment must succeed on testnet");
    let weighted_policy_sc_addr = parse_c_strkey_to_smart_account(&policy_result.policy_address)
        .expect("weighted-threshold policy C-strkey must parse");

    let bootstrap_sc =
        parse_g_strkey_to_signer_address(&bootstrap_g).expect("bootstrap G-strkey must parse");
    let weighted_install_param = build_weighted_threshold_install_param(
        &[(
            WeightedThresholdSignerInput::Delegated {
                g_strkey: bootstrap_g.clone(),
            },
            1,
        )],
        1,
    )
    .expect("weighted-threshold install param must build");

    let rule_manager = fresh_rule_manager();
    let definition = ContextRuleDefinition::new(
        RuleContext::Default,
        "wt-only-neg".to_owned(), // 11 bytes
        None,
        vec![ContextRuleSignerInput::Delegated {
            address: bootstrap_sc,
        }],
        vec![ContextRulePolicy::new(
            weighted_policy_sc_addr,
            weighted_install_param,
        )],
    );
    let install_out = rule_manager
        .install_rule(
            smart_account_sc.clone(),
            definition,
            vec![ContextRuleId::new(0)],
            bootstrap_signer.as_ref(),
            None,
            rid(),
            false,
            false,
        )
        .await
        .expect("weighted-only rule install must succeed");
    let weighted_only_rule_id = install_out.rule_id;

    // `refresh_signer_baseline` is the FIRST call that would establish an
    // audit-log baseline for this freshly-installed rule; it identifies the
    // threshold policy via `identify_threshold_policy` (simple-threshold
    // only) internally. On a rule whose ONLY threshold policy is
    // weighted-threshold, this is where hardening item (b)'s constraint
    // surfaces directly: a clear typed error, before any on-chain call.
    let baseline_err = signers_mgr
        .refresh_signer_baseline(
            smart_account_sc.clone(),
            weighted_only_rule_id,
            Some(&bootstrap_g),
            rid(),
        )
        .await
        .expect_err(
            "refresh_signer_baseline against a rule whose ONLY threshold policy is weighted \
             must fail closed",
        );
    assert!(
        matches!(
            baseline_err,
            SaError::ThresholdPolicyNotInstalled { .. }
                | SaError::ThresholdPolicyIdentificationFailed { .. }
        ),
        "expected ThresholdPolicyNotInstalled or ThresholdPolicyIdentificationFailed; \
         got {baseline_err:?}"
    );

    let (new_signer_g, _new_signer) = fresh_signer();
    let new_signer_scval =
        build_delegated_signer_scval(&new_signer_g).expect("new signer ScVal must encode");
    let new_signer_pubkey = stellar_strkey::ed25519::PublicKey::from_string(&new_signer_g)
        .expect("new signer G-strkey must parse");

    // With no baseline ever established (the call above failed before writing
    // one), `batch_add_signers` itself refuses at its OWN first pre-flight
    // check — `SignerSetMissingBaseline` — before it ever reaches
    // `identify_threshold_policy`. Either refusal leaves no on-chain side
    // effect; both are exercised here because a caller could reach either one
    // depending on whether a baseline happens to already exist.
    let batch_add_err = signers_mgr
        .batch_add_signers(
            smart_account_sc.clone(),
            weighted_only_rule_id,
            vec![(
                new_signer_scval,
                stellar_agent_core::audit_log::signer_set::SignerPubkey::Ed25519 {
                    pubkey: new_signer_pubkey.0,
                },
            )],
            bootstrap_signer.as_ref(),
            rid(),
        )
        .await
        .expect_err(
            "batch_add_signers against a rule whose ONLY threshold policy is weighted \
             must fail closed before any on-chain submission",
        );
    assert!(
        matches!(batch_add_err, SaError::SignerSetMissingBaseline { .. }),
        "expected SignerSetMissingBaseline (no baseline was ever established above); \
         got {batch_add_err:?}"
    );

    // Confirm no on-chain side effect: the rule's signer set is unchanged.
    let signers_after_failed_batch = signers_mgr
        .get_rule_signers(smart_account_sc, weighted_only_rule_id, None)
        .await
        .expect("get_rule_signers must succeed after the failed batch-add");
    assert_eq!(
        signers_after_failed_batch.len(),
        1,
        "the weighted-only rule's signer set must be unchanged after the refused batch-add"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 6 (ignored): deploy-c WebAuthn passkey genesis + batch-add three kinds
// ─────────────────────────────────────────────────────────────────────────────

/// RAII guard that shuts down a `BridgeHandle` on drop.
struct BridgeGuard(Option<stellar_agent_webauthn_bridge::BridgeHandle>);

impl Drop for BridgeGuard {
    #[allow(
        clippy::print_stderr,
        reason = "diagnostic output in test RAII guard; non-fatal shutdown error"
    )]
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            let result = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(handle.shutdown())
            });
            if let Err(e) = result {
                eprintln!("stellar-agent test: bridge shutdown error (non-fatal): {e}");
            }
        }
    }
}

/// RAII guard that kills a `chromiumoxide::Browser` subprocess on drop.
struct BrowserGuard(Option<Browser>);

impl BrowserGuard {
    fn new(browser: Browser) -> Self {
        Self(Some(browser))
    }
}

impl Drop for BrowserGuard {
    fn drop(&mut self) {
        if let Some(mut browser) = self.0.take() {
            tokio::task::block_in_place(|| {
                let _ = tokio::runtime::Handle::current().block_on(browser.kill());
            });
        }
    }
}

/// Launches a headless Chromium browser for the WebAuthn registration
/// ceremony. Mirrors `smart_account_rules_webauthn_testnet_acceptance.rs`'s
/// `launch_chromium` exactly (sandbox disabled via the typed `no_sandbox()`
/// builder method — a dash-prefixed `args` string is silently ignored by
/// chromiumoxide; ephemeral `user_data_dir` asserted at launch).
async fn launch_chromium() -> (Browser, chromiumoxide::Handler) {
    let config = BrowserConfig::builder()
        .no_sandbox()
        .build()
        .expect("BrowserConfig must build");
    assert!(
        config.user_data_dir.is_none(),
        "BrowserConfig.user_data_dir must be None (ephemeral)"
    );
    Browser::launch(config)
        .await
        .expect("Chromium must launch; ensure chromium/google-chrome is on PATH")
}

/// Error returned by [`goto_loopback`] when the target URL is rejected.
#[derive(Debug)]
enum GotoError {
    Parse(url::ParseError),
    NoHost,
    NonLoopbackHost { host: String },
    NonHttpScheme { scheme: String },
    Navigation(chromiumoxide::error::CdpError),
}

impl std::fmt::Display for GotoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse(e) => write!(f, "URL parse error: {e}"),
            Self::NoHost => write!(f, "URL has no host component"),
            Self::NonLoopbackHost { host } => {
                write!(f, "goto_loopback rejects non-loopback host: {host:?}")
            }
            Self::NonHttpScheme { scheme } => {
                write!(f, "goto_loopback requires http scheme; got {scheme:?}")
            }
            Self::Navigation(e) => write!(f, "CDP navigation error: {e}"),
        }
    }
}

impl std::error::Error for GotoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Parse(e) => Some(e),
            Self::Navigation(e) => Some(e),
            Self::NoHost | Self::NonLoopbackHost { .. } | Self::NonHttpScheme { .. } => None,
        }
    }
}

/// Navigates `page` to `url`, asserting structural loopback enforcement.
/// Mirrors `smart_account_rules_webauthn_testnet_acceptance.rs`'s
/// `goto_loopback` exactly.
async fn goto_loopback(page: &chromiumoxide::Page, url: &str) -> Result<(), GotoError> {
    let parsed = url::Url::parse(url).map_err(GotoError::Parse)?;
    if parsed.scheme() != "http" {
        return Err(GotoError::NonHttpScheme {
            scheme: parsed.scheme().to_owned(),
        });
    }
    let host = parsed.host_str().ok_or(GotoError::NoHost)?;
    if !is_loopback_http_url(url) {
        return Err(GotoError::NonLoopbackHost {
            host: host.to_owned(),
        });
    }
    page.goto(url).await.map_err(GotoError::Navigation)?;
    Ok(())
}

/// Drives a CDP virtual-authenticator registration ceremony for a single
/// credential and returns `(credential_id_bytes, pubkey_65_bytes)`.
async fn register_one_credential(
    page: &chromiumoxide::Page,
    creds_manager: &CredentialsManager,
    bridge_addr: SocketAddr,
    credential_name: &str,
    audit_log_path: &Path,
) -> (Vec<u8>, Vec<u8>) {
    let reg_handle = creds_manager
        .prepare_registration(credential_name, bridge_addr, None)
        .await
        .expect("prepare_registration must succeed");

    goto_loopback(page, &reg_handle.url)
        .await
        .expect("registration URL must be a loopback http URL");

    let reg_deadline = Instant::now() + Duration::from_secs(60);
    let mut reg_audit = AuditWriter::open(audit_log_path.to_path_buf(), None)
        .expect("registration AuditWriter must open");

    let reg_outcome = creds_manager
        .poll_registration(
            credential_name,
            &reg_handle.nonce,
            reg_deadline,
            Some(&mut reg_audit),
        )
        .await
        .expect("poll_registration must not error");
    let metadata = match reg_outcome {
        AddPasskeyOutcome::Registered { metadata } => metadata,
        other => panic!("registration: expected Registered; got {other:?}"),
    };

    let credential_id_bytes = URL_SAFE_NO_PAD
        .decode(&metadata.credential_id_b64url)
        .expect("credential_id_b64url must decode");
    let pubkey_bytes = URL_SAFE_NO_PAD
        .decode(&metadata.public_key_sec1_b64)
        .expect("public_key_sec1_b64 must decode");
    assert_eq!(
        pubkey_bytes.len(),
        65,
        "public key must be 65 bytes (SEC1 uncompressed P-256)"
    );
    assert_eq!(pubkey_bytes[0], 0x04, "public key must start with 0x04");

    (credential_id_bytes, pubkey_bytes)
}

/// Passkey-genesis `deploy-c` proof + batch-add three signer kinds in one
/// transaction, driven by a real CDP virtual-authenticator ceremony.
///
/// These are two independently-provable claims kept in one `#[ignore]`d test
/// to pay the Chromium-launch cost once:
///
/// 1. A real WebAuthn credential (registered via the bridge/CDP ceremony) can
///    be used as a smart account's SOLE genesis signer via
///    `deploy_smart_account`'s `genesis_signer_scval_override` — mirrors what
///    `deploy-c --signer-webauthn` resolves to. Verified via
///    `get_rule_signers` on the bootstrap rule. This test deliberately does
///    NOT attempt any follow-on mutation authorized by that WebAuthn-only
///    rule: `install_rule`/`add_signer`/`batch_add_signers` authorize via the
///    standard `Signer` trait (a raw ed25519 signing flow), and a WebAuthn
///    credential's assertion is a DIFFERENT authorization path
///    (`CredentialsManager::sign_with_passkey_rule`) already proven
///    end-to-end by `smart_account_rules_webauthn_testnet_acceptance.rs`;
///    combining both paths on the same rule is out of this proof's scope.
/// 2. `batch_add_signers` adds THREE heterogeneous signer kinds (Delegated,
///    External-Ed25519, External-WebAuthn) in one transaction, on a
///    SEPARATE, ordinarily-Delegated-genesis smart account (so the add is
///    authorized the same well-trodden way every other mutator test in this
///    crate uses). The resulting four-signer rule (the Delegated admin
///    genesis signer plus the three batch-added signers) is verified
///    on-chain via `get_rule_signers`.
///
/// The CLI's `--signer-webauthn`/ArgGroup/refusal-guard/credential-name-lookup
/// plumbing is covered separately by offline CLI unit tests
/// (`deploy_c_external_genesis_without_ack_is_refused` and neighbours).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires testnet, chromium, and explicit --ignored flag"]
async fn deploy_c_webauthn_genesis_and_batch_add_testnet_acceptance() {
    let tmp = TempDir::new().expect("tempdir must be created");
    let registry_path = tmp.path().join("networks.toml");
    let passkeys_dir = tmp.path().join("passkeys");
    let approvals_dir = tmp.path().join("approvals");
    std::fs::create_dir_all(&passkeys_dir).expect("passkeys dir must be created");
    std::fs::create_dir_all(&approvals_dir).expect("approvals dir must be created");

    // ── Deploy WebAuthn verifier ──────────────────────────────────────────────
    let (verifier_deployer_g, verifier_deployer) = fresh_deployer_keypair();
    fund_via_friendbot(&verifier_deployer_g).await;
    let verifier_result = deploy_webauthn_verifier(
        WebAuthnVerifierDeployArgs {
            deployer: verifier_deployer,
            network_passphrase: TESTNET_PASSPHRASE.to_owned(),
            rpc_url: TESTNET_RPC_URL.to_owned(),
            timeout: Duration::from_secs(TIMEOUT_SECS),
            fee: DeployResolvedFeePerOp {
                stroops: 1_000_000,
                percentile_label: "explicit".to_owned(),
            },
            dry_run: false,
            registry_path_override: Some(registry_path.clone()),
        },
        None,
    )
    .await
    .expect("WebAuthn verifier deployment must succeed on testnet");
    let verifier_sc_addr = parse_c_strkey_to_smart_account(&verifier_result.verifier_address)
        .expect("verifier C-strkey must parse");

    // ── Start bridge (registration-only; no signing ceremony is needed) ──────
    let approval_path = approvals_dir.join("default.toml");
    let store = Arc::new(tokio::sync::Mutex::new(
        PendingApprovalStore::open(approval_path).expect("approval store must open"),
    ));
    let bridge_bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let bridge_handle =
        stellar_agent_webauthn_bridge::start_bridge_register_only(Arc::clone(&store), bridge_bind)
            .await
            .expect("bridge must start");
    let bridge_addr = bridge_handle.local_addr();
    let _bridge_guard = BridgeGuard(Some(bridge_handle));

    // ── Launch Chromium + virtual authenticator ──────────────────────────────
    let (browser, mut handler) = launch_chromium().await;
    let handler_task = tokio::spawn(async move {
        loop {
            if handler.next().await.is_none() {
                break;
            }
        }
    });
    let mut browser_guard = BrowserGuard::new(browser);
    let page = browser_guard
        .0
        .as_mut()
        .expect("browser must be alive")
        .new_page("about:blank")
        .await
        .expect("new page must open");

    page.execute(EnableParams::default())
        .await
        .expect("WebAuthn domain must enable");
    let auth_options = VirtualAuthenticatorOptions::builder()
        .protocol(AuthenticatorProtocol::Ctap2)
        .transport(AuthenticatorTransport::Internal)
        .has_user_verification(true)
        .is_user_verified(true)
        .has_resident_key(false)
        .automatic_presence_simulation(true)
        .build()
        .expect("VirtualAuthenticatorOptions must build");
    page.execute(AddVirtualAuthenticatorParams::new(auth_options))
        .await
        .expect("addVirtualAuthenticator must succeed");

    let creds_manager = CredentialsManager::new(
        passkeys_dir.clone(),
        "default",
        TEST_RP_ID,
        Some(Arc::clone(&store)),
    );
    let audit_log_path = tmp.path().join("audit").join("default.jsonl");

    // ── Claim 1: WebAuthn credential as sole genesis signer ──────────────────
    let (genesis_credential_id, genesis_pubkey) = register_one_credential(
        &page,
        &creds_manager,
        bridge_addr,
        "genesis",
        &audit_log_path,
    )
    .await;
    let mut genesis_key_data = Vec::with_capacity(65 + genesis_credential_id.len());
    genesis_key_data.extend_from_slice(&genesis_pubkey);
    genesis_key_data.extend_from_slice(&genesis_credential_id);
    let genesis_scval = build_external_signer_scval(verifier_sc_addr, &genesis_key_data)
        .expect("genesis WebAuthn signer ScVal must encode");

    let (genesis_account_deployer_g, _seed) = fresh_reusable_seed();
    let webauthn_genesis_smart_account_strkey =
        deploy_fresh_smart_account(&genesis_account_deployer_g, Some(genesis_scval)).await;
    let webauthn_genesis_smart_account_sc =
        parse_c_strkey_to_smart_account(&webauthn_genesis_smart_account_strkey)
            .expect("deployed smart-account C-strkey must parse");

    let (audit_writer, sm_audit_log_path, _audit_dir) = tmp_audit_writer();
    let signers_mgr = fresh_signers_manager(audit_writer, sm_audit_log_path);
    let genesis_signers = signers_mgr
        .get_rule_signers(webauthn_genesis_smart_account_sc, 0, None)
        .await
        .expect("get_rule_signers on the WebAuthn-genesis bootstrap rule must succeed");
    assert_eq!(
        genesis_signers.len(),
        1,
        "WebAuthn-genesis bootstrap rule must carry exactly the sole WebAuthn signer"
    );
    match &genesis_signers[0].1 {
        stellar_agent_core::audit_log::signer_set::SignerPubkey::External {
            verifier_contract,
            ..
        } => {
            assert_eq!(
                verifier_contract, &verifier_result.verifier_address,
                "genesis signer's verifier_contract must match the deployed WebAuthn verifier"
            );
        }
        other => panic!("expected an External (WebAuthn) genesis signer; got {other:?}"),
    }

    // ── Claim 2: batch_add_signers with three heterogeneous signer kinds ─────
    let (batch_credential_id, batch_pubkey) = register_one_credential(
        &page,
        &creds_manager,
        bridge_addr,
        "batch-member",
        &audit_log_path,
    )
    .await;
    let mut batch_webauthn_key_data = Vec::with_capacity(65 + batch_credential_id.len());
    batch_webauthn_key_data.extend_from_slice(&batch_pubkey);
    batch_webauthn_key_data.extend_from_slice(&batch_credential_id);
    let batch_webauthn_verifier_sc =
        parse_c_strkey_to_smart_account(&verifier_result.verifier_address)
            .expect("verifier C-strkey must parse");
    let batch_webauthn_scval =
        build_external_signer_scval(batch_webauthn_verifier_sc, &batch_webauthn_key_data)
            .expect("batch WebAuthn signer ScVal must encode");

    let (admin_g, admin_signer) = fresh_signer();
    fund_via_friendbot(&admin_g).await;
    let batch_smart_account_strkey = deploy_fresh_smart_account(&admin_g, None).await;
    let batch_smart_account_sc = parse_c_strkey_to_smart_account(&batch_smart_account_strkey)
        .expect("deployed smart-account C-strkey must parse");

    let (policy_deployer_g, policy_deployer_box) = fresh_signer();
    fund_via_friendbot(&policy_deployer_g).await;
    let simple_threshold_policy_strkey =
        deploy_simple_threshold_policy_wasm(&policy_deployer_g, policy_deployer_box.as_ref()).await;
    let simple_threshold_policy_sc =
        parse_c_strkey_to_smart_account(&simple_threshold_policy_strkey)
            .expect("simple-threshold policy C-strkey must parse");

    let admin_sc = parse_g_strkey_to_signer_address(&admin_g).expect("admin G-strkey must parse");
    let rule_manager = fresh_rule_manager();
    let definition = ContextRuleDefinition::new(
        RuleContext::Default,
        "batch-add-3kind".to_owned(), // 16 bytes
        None,
        vec![ContextRuleSignerInput::Delegated { address: admin_sc }],
        vec![ContextRulePolicy::new(
            simple_threshold_policy_sc,
            encode_simple_threshold_params(1),
        )],
    );
    let install_out = rule_manager
        .install_rule(
            batch_smart_account_sc.clone(),
            definition,
            vec![ContextRuleId::new(0)],
            admin_signer.as_ref(),
            None,
            rid(),
            false,
            false,
        )
        .await
        .expect("simple-threshold rule install must succeed");
    let rule_id = install_out.rule_id;

    // `batch_add_signers` requires an established audit-log baseline
    // (`SaError::SignerSetMissingBaseline` otherwise); a freshly-installed
    // rule has none until `refresh_signer_baseline` writes the first
    // `SaSignerSetBaselined` row.
    signers_mgr
        .refresh_signer_baseline(
            batch_smart_account_sc.clone(),
            rule_id,
            Some(&admin_g),
            rid(),
        )
        .await
        .expect("refresh_signer_baseline must succeed");

    let (delegated_g, _delegated_signer) = fresh_signer();
    let delegated_scval =
        build_delegated_signer_scval(&delegated_g).expect("delegated signer ScVal must encode");
    let delegated_pubkey = stellar_strkey::ed25519::PublicKey::from_string(&delegated_g)
        .expect("delegated G-strkey must parse");

    let ed25519_agent_signing_key = SigningKey::generate(&mut OsRng);
    let ed25519_agent_pubkey_bytes: [u8; 32] = ed25519_agent_signing_key.verifying_key().to_bytes();
    let (ed25519_agent_verifier_deployer_g, ed25519_agent_verifier_deployer) =
        fresh_deployer_keypair();
    fund_via_friendbot(&ed25519_agent_verifier_deployer_g).await;
    let ed25519_verifier_result = deploy_ed25519_verifier(
        Ed25519VerifierDeployArgs {
            deployer: ed25519_agent_verifier_deployer,
            network_passphrase: TESTNET_PASSPHRASE.to_owned(),
            rpc_url: TESTNET_RPC_URL.to_owned(),
            timeout: Duration::from_secs(TIMEOUT_SECS),
            fee: DeployResolvedFeePerOp {
                stroops: 1_000_000,
                percentile_label: "explicit".to_owned(),
            },
            dry_run: false,
            registry_path_override: Some(registry_path.clone()),
        },
        None,
    )
    .await
    .expect("ed25519 verifier deployment must succeed on testnet");
    let ed25519_verifier_sc =
        parse_c_strkey_to_smart_account(&ed25519_verifier_result.verifier_address)
            .expect("ed25519 verifier C-strkey must parse");
    let ed25519_agent_scval =
        build_external_signer_scval(ed25519_verifier_sc, &ed25519_agent_pubkey_bytes)
            .expect("ed25519 agent signer ScVal must encode");

    fn first16(bytes: &[u8]) -> [u8; 16] {
        let mut buf = [0u8; 16];
        let n = bytes.len().min(16);
        buf[..n].copy_from_slice(&bytes[..n]);
        buf
    }

    let batch_signers = vec![
        (
            delegated_scval,
            stellar_agent_core::audit_log::signer_set::SignerPubkey::Ed25519 {
                pubkey: delegated_pubkey.0,
            },
        ),
        (
            ed25519_agent_scval,
            stellar_agent_core::audit_log::signer_set::SignerPubkey::External {
                verifier_contract: ed25519_verifier_result.verifier_address.clone(),
                key_data_first16: first16(&ed25519_agent_pubkey_bytes),
            },
        ),
        (
            batch_webauthn_scval,
            stellar_agent_core::audit_log::signer_set::SignerPubkey::External {
                verifier_contract: verifier_result.verifier_address.clone(),
                key_data_first16: first16(&batch_webauthn_key_data),
            },
        ),
    ];

    let new_signer_ids = signers_mgr
        .batch_add_signers(
            batch_smart_account_sc.clone(),
            rule_id,
            batch_signers,
            admin_signer.as_ref(),
            rid(),
        )
        .await
        .expect("batch_add_signers (3 signer kinds) must succeed in one transaction");
    assert_eq!(
        new_signer_ids.len(),
        3,
        "three new signer ids must be assigned"
    );

    let final_signers = signers_mgr
        .get_rule_signers(batch_smart_account_sc, rule_id, None)
        .await
        .expect("get_rule_signers must succeed after the batch-add");
    assert_eq!(
        final_signers.len(),
        4,
        "rule must carry the Delegated admin genesis signer plus the 3 batch-added signers"
    );

    handler_task.abort();
}
