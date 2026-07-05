//! Testnet acceptance test for policy observability and tuning (Package B,
//! GH issue #7).
//!
//! Exercises the full operator-observes/retunes, agent-transacts flow against
//! testnet:
//!
//! 1. Deploy the OZ ed25519 verifier, the simple threshold-policy, and the
//!    spending-limit policy. Deploy a fresh smart account bootstrapped by a
//!    native (Delegated) operator signer. Install a `CallContract(XLM-SAC)`
//!    rule with TWO signers — the operator's Delegated key and a fresh
//!    External-Ed25519 agent key — a threshold-policy(1) (so either signer
//!    alone authorizes) and the spending-limit policy (limit L, period P).
//! 2. `get`: limit == L, period == P, history empty, remaining == L.
//! 3. Agent-signed transfer of `A < L` through the production submit path
//!    (delegation-suite precedent — `Ed25519RuleSigner`), then `get`:
//!    in_window_spent == A, remaining == L − A, history length 1.
//! 4. Retune: operator-signed `set_spending_limit` to `L2 > A` via the
//!    manager call, then `get`: spending_limit == L2 AND history STILL
//!    contains the step-3 entry with in_window_spent == A — the issue-#7
//!    invariant (retune preserves rolling history). Audit row
//!    `SaSpendingLimitRetuned` with old_limit == L, new_limit == L2.
//! 5. Squeeze: operator-signed retune to `L3 <= A`, then a further
//!    agent-signed transfer FAILS with `SpendingLimitExceeded` (3221)
//!    specifically, not `NotAllowed` — proves the preserved history still
//!    counts against the new limit.
//! 6. MCP read tools THROUGH REAL SERVER DISPATCH: `stellar_rules_get` and
//!    `stellar_rules_list` invoked against the real `WalletServer`
//!    (registry → catalogue → matrix → dispatch_gate → handler), plus a
//!    toolset-grant assertion — a toolset pin declaring only `read-rules`
//!    resolves and dispatches `stellar_rules_get` end-to-end through
//!    `check_toolset_action`.
//! 7. Negative: `get` (`identify_spending_limit_policy`) against the
//!    bootstrap rule (no spending-limit policy attached) fails with the
//!    typed `SpendingLimitNotInstalled`, not a decode error.
//!
//! Every step's failure fails the whole test — there is no early return that
//! would let a later assertion be silently skipped.
//!
//! # Gate
//!
//! Compiled only under `--features testnet-integration`:
//!
//! ```text
//! cargo test --features testnet-integration \
//!   --test smart_account_policy_observability_testnet_acceptance
//! ```
//!
//! # Reference cross-check
//!
//! - OZ `packages/accounts/src/policies/spending_limit.rs:314-339` (SHA
//!   `a9c4216`) — `set_spending_limit` mutates only the limit; period is
//!   immutable post-install.
//! - OZ `packages/accounts/src/policies/spending_limit.rs:460-481` — the
//!   rolling-window eviction predicate `compute_spending_window` replicates.

#![cfg(feature = "testnet-integration")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics are acceptable in testnet acceptance tests"
)]

mod common;

use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use common::{TESTNET_FRIENDBOT_URL, TESTNET_PASSPHRASE, TESTNET_RPC_URL, fund_via_friendbot};
use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};
use sha2::{Digest as _, Sha256};
use stellar_agent_core::audit_log::entry::AuditEntry;
use stellar_agent_core::audit_log::schema::EventKind;
use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_core::smart_account::rule_id::ContextRuleId;
use stellar_agent_mcp::server::{
    StellarRulesGetArgs, StellarRulesListArgs, StellarToolsetInvokeArgs, WalletServer,
};
use stellar_agent_network::signing::envelope_signing::attach_signature;
use stellar_agent_network::{
    Signer, SoftwareSigningKey, StellarRpcClient, fetch_account, submit_transaction_and_wait,
};
use stellar_agent_smart_account::deployment::{
    DeployerKeypair, DeploymentArgs, Ed25519VerifierDeployArgs,
    ResolvedFeePerOp as DeployResolvedFeePerOp, SpendingLimitPolicyDeployArgs,
    deploy_ed25519_verifier, deploy_smart_account, deploy_spending_limit_policy,
    derive_smart_account_address,
};
use stellar_agent_smart_account::error::SaError;
use stellar_agent_smart_account::managers::rules::{
    ContextRuleDefinition, ContextRuleManager, ContextRuleManagerConfig, ContextRulePolicy,
    ContextRuleSignerInput, RuleContext, parse_c_strkey_to_smart_account,
    parse_g_strkey_to_signer_address,
};
use stellar_agent_smart_account::managers::signers::{SignersManager, SignersManagerConfig};
use stellar_agent_smart_account::managers::spending_limit_data::compute_spending_window;
use stellar_agent_smart_account::signers::policy_identification::THRESHOLD_POLICY_WASM;
use stellar_agent_smart_account::spending_limit_policy::build_spending_limit_install_param;
use stellar_agent_smart_account::submit::{
    Ed25519RuleSigner, SubmitInvokeArgs, submit_signed_invoke,
};
use stellar_agent_test_support::keyring_mock;
use stellar_baselib::account::{Account as BaselibAccount, AccountBehavior};
use stellar_baselib::transaction::{Transaction, TransactionBehavior};
use stellar_baselib::transaction_builder::{TransactionBuilder, TransactionBuilderBehavior};
use stellar_rpc_client::Client;
use stellar_xdr::{
    AccountId, BytesM, ContractExecutable, ContractIdPreimage, ContractIdPreimageFromAddress,
    CreateContractArgsV2, Hash, HostFunction, Int128Parts, InvokeHostFunctionOp, LedgerKey,
    LedgerKeyContractCode, Limits, Operation, OperationBody, PublicKey as XdrPublicKey, ScAddress,
    ScMap, ScMapEntry, ScSymbol, ScVal, SorobanAuthorizationEntry, Uint256, VecM, WriteXdr,
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

/// Known-answer XLM SAC on testnet (SEP-41 native-asset contract).
///
/// Source: `soroswap-core/public/tokens.json:testnet:assets[0]:contract`;
/// independently verified via `stellar contract id asset --asset native
/// --network testnet`. Matches the constant used in
/// `smart_account_delegation_testnet_acceptance.rs`.
const XLM_SAC_TESTNET: &str = "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC";

/// Initial spending limit `L` (5 XLM, in stroops).
const LIMIT_L: i128 = 50_000_000;

/// Rolling-window period, in ledgers.
const PERIOD_LEDGERS: u32 = 1_000;

/// Step-3 agent transfer amount `A` (1 XLM): strictly under `LIMIT_L`.
const TRANSFER_A: i128 = 10_000_000;

/// Step-4 retuned limit `L2` (8 XLM): strictly above `A`.
const LIMIT_L2: i128 = 80_000_000;

/// Step-5 squeezed limit `L3` (0.5 XLM): at or below `A`, so the preserved
/// history (`A` already spent) alone exceeds `L3` — any further transfer,
/// regardless of amount, must fail.
const LIMIT_L3: i128 = 5_000_000;

/// Step-5 further-transfer amount: any positive value proves the point; uses
/// the same magnitude as `A` to keep the on-chain math easy to eyeball.
const SQUEEZE_TRANSFER_STROOPS: i128 = 10_000_000;

/// XLM funded into the smart account's SAC balance (7 XLM): must exceed
/// `TRANSFER_A + SQUEEZE_TRANSFER_STROOPS` (20_000_000) with margin, so the
/// step-5 over-limit transfer is refused for the intended
/// `SpendingLimitExceeded` reason rather than for insufficient SAC balance —
/// the SAC's own balance check and the spending-limit policy's `enforce` both
/// run during the recording-auth simulate; an under-funded account would
/// surface the wrong failure first. Matches the ratio proven adequate in
/// `smart_account_delegation_testnet_acceptance.rs`.
const SMART_ACCOUNT_FUND_STROOPS: i64 = 70_000_000;

/// Ledger horizon added to the current ledger for the rule's `valid_until`,
/// so `stellar_rules_list`/`stellar_rules_get`'s `expires_in_ledgers` field is
/// exercised with a real positive value. MUST stay strictly below the wallet's
/// own expiring-rule cap (`DEFAULT_SESSION_RULE_HORIZON_LEDGERS` = 1000,
/// managers/rules.rs) or the install is refused client-side with
/// `HorizonExceeded`. 900 ledgers is roughly 75 minutes at ~5 s/ledger —
/// comfortably longer than this suite's live run.
const VALID_UNTIL_HORIZON_LEDGERS: u32 = 900;

// ─────────────────────────────────────────────────────────────────────────────
// Helpers: keys, deployers, managers
// ─────────────────────────────────────────────────────────────────────────────

/// Generates a fresh UUID-v4 request-id string for forensic correlation.
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

/// Generates a fresh deployer keypair wrapped in `DeployerKeypair::SecretEnv`.
fn fresh_deployer_keypair() -> (String, DeployerKeypair) {
    let (g_strkey, signer) = fresh_signer();
    let deployer = DeployerKeypair::SecretEnv {
        var_name: "testnet-policy-observability-acceptance-generated".to_owned(),
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
///
/// Primary and secondary RPC are both set to `TESTNET_RPC_URL` (degrades to
/// single-RPC; acceptable for testnet acceptance).
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
        "policy-observability-acceptance".to_owned(),
        Duration::from_secs(TIMEOUT_SECS),
        CHAIN_ID.to_owned(),
    ))
    .expect("SignersManager::new must succeed")
}

/// Deploys a fresh smart account whose bootstrap rule (rule_id 0) uses
/// `initial_signer_g` as its sole `Delegated` signer with no policies.
/// Returns the deployed C-strkey.
async fn deploy_fresh_smart_account(initial_signer_g: &str) -> String {
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
        genesis_signer_scval_override: None,
    };
    deploy_smart_account(args, None)
        .await
        .expect("smart-account deployment must succeed on testnet")
        .smart_account
}

/// Deploys the OZ ed25519 verifier and the OZ spending-limit policy to a
/// temporary `VerifierRegistry`. Returns `(verifier_address, policy_address)`.
async fn deploy_verifier_and_spending_limit_policy(registry_path: &Path) -> (String, String) {
    let (deployer_g, deployer) = fresh_deployer_keypair();
    fund_via_friendbot(&deployer_g).await;

    let verifier_args = Ed25519VerifierDeployArgs {
        deployer,
        network_passphrase: TESTNET_PASSPHRASE.to_owned(),
        rpc_url: TESTNET_RPC_URL.to_owned(),
        timeout: Duration::from_secs(TIMEOUT_SECS),
        fee: DeployResolvedFeePerOp {
            stroops: 1_000_000,
            percentile_label: "explicit".to_owned(),
        },
        dry_run: false,
        registry_path_override: Some(registry_path.to_path_buf()),
    };
    let verifier_result = deploy_ed25519_verifier(verifier_args, None)
        .await
        .expect("ed25519 verifier deployment must succeed on testnet");

    let (deployer_g2, deployer2) = fresh_deployer_keypair();
    fund_via_friendbot(&deployer_g2).await;

    let policy_args = SpendingLimitPolicyDeployArgs {
        deployer: deployer2,
        network_passphrase: TESTNET_PASSPHRASE.to_owned(),
        rpc_url: TESTNET_RPC_URL.to_owned(),
        timeout: Duration::from_secs(TIMEOUT_SECS),
        fee: DeployResolvedFeePerOp {
            stroops: 1_000_000,
            percentile_label: "explicit".to_owned(),
        },
        dry_run: false,
        registry_path_override: Some(registry_path.to_path_buf()),
    };
    let policy_result = deploy_spending_limit_policy(policy_args, None)
        .await
        .expect("spending-limit policy deployment must succeed on testnet");

    (
        verifier_result.verifier_address,
        policy_result.policy_address,
    )
}

/// Deploys the OZ simple threshold-policy WASM at a deterministic,
/// idempotent address (tolerates `AlreadyExists` on a repeat run). Returns
/// the deployed C-strkey.
///
/// Mirrors `deploy_threshold_policy_wasm` in
/// `smart_account_signers_testnet_acceptance.rs`: there is no first-class
/// `deployment::deploy_threshold_policy` production entry point (only the
/// weighted-threshold policy is deferred to Package C; the simple
/// N-of-M threshold policy this uses already shipped in Package A), so the
/// upload+deploy sequence is inlined here per this crate's established
/// per-file test-helper convention.
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

/// Builds the SEP-41 `transfer(from, to, amount)` `HostFunction::InvokeContract`
/// invocation for a SAC — the ONLY shape the OZ spending-limit policy's
/// `enforce` accepts.
fn transfer_host_function(
    sac: ScAddress,
    from: ScAddress,
    to: ScAddress,
    amount: i128,
) -> HostFunction {
    #[allow(
        clippy::cast_possible_truncation,
        reason = "canonical i128 -> Int128Parts split: hi = high 64 bits, lo = low 64 bits"
    )]
    let amount_parts = Int128Parts {
        hi: (amount >> 64) as i64,
        lo: amount as u64,
    };
    let args: VecM<ScVal> = vec![
        ScVal::Address(from),
        ScVal::Address(to),
        ScVal::I128(amount_parts),
    ]
    .try_into()
    .expect("3-element transfer args vec fits VecM<ScVal>");
    let function_name =
        ScSymbol::try_from("transfer").expect("\"transfer\" fits ScSymbol (<=32 bytes)");
    HostFunction::InvokeContract(stellar_xdr::InvokeContractArgs {
        contract_address: sac,
        function_name,
        args,
    })
}

/// Builds the `InvokeContractArgs` for `fund_sac_balance`'s SAC-transfer
/// callback — plain structural strkey parsing, no network access.
#[allow(
    clippy::result_large_err,
    reason = "SaError is the crate's production error type; this test-only builder \
              surfaces it unchanged rather than introducing a narrower local error type"
)]
fn build_sac_transfer_invoke(
    sac_contract: &str,
    from: &str,
    to: &str,
    amount: i128,
) -> Result<stellar_xdr::InvokeContractArgs, SaError> {
    let contract_address = parse_c_strkey_to_smart_account(sac_contract)?;
    let from_sc = parse_g_strkey_to_signer_address(from)?;
    let to_sc = parse_c_strkey_to_smart_account(to)?;
    let HostFunction::InvokeContract(invoke_args) =
        transfer_host_function(contract_address, from_sc, to_sc, amount)
    else {
        unreachable!("transfer_host_function always returns InvokeContract");
    };
    Ok(invoke_args)
}

/// Fetches an account's current sequence number via the testnet RPC.
async fn fetch_testnet_sequence(
    account_id: String,
) -> Result<i64, Box<dyn std::error::Error + Send + Sync>> {
    let rpc_client = StellarRpcClient::new(TESTNET_RPC_URL)?;
    let account = fetch_account(&rpc_client, &account_id, &[]).await?;
    Ok(account.sequence_number)
}

/// Signs an unsigned envelope XDR with a raw ed25519 seed.
async fn sign_testnet_envelope(
    unsigned_xdr: String,
    funder_seed: Zeroizing<[u8; 32]>,
    network_passphrase: String,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let signer = SoftwareSigningKey::new_from_zeroizing(funder_seed);
    Ok(attach_signature(&unsigned_xdr, &signer, &network_passphrase).await?)
}

/// Submits a signed envelope XDR and waits for confirmation.
async fn submit_testnet_signed_xdr(
    signed_xdr: String,
) -> Result<stellar_agent_network::submit::SubmissionResult, Box<dyn std::error::Error + Send + Sync>>
{
    let rpc_client = StellarRpcClient::new(TESTNET_RPC_URL)?;
    Ok(submit_transaction_and_wait(
        &rpc_client,
        &signed_xdr,
        Duration::from_secs(TIMEOUT_SECS),
        TESTNET_PASSPHRASE,
        Some(stellar_agent_network::submit::SubmissionSignerKind::Software),
    )
    .await?)
}

/// Fetches the current testnet ledger sequence via `getLatestLedger`.
async fn fetch_latest_ledger() -> u32 {
    let rpc_server = Client::new(TESTNET_RPC_URL).expect("rpc client construction must succeed");
    rpc_server
        .get_latest_ledger()
        .await
        .expect("getLatestLedger must succeed")
        .sequence
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers: MCP WalletServer (step 6)
// ─────────────────────────────────────────────────────────────────────────────

/// Seeds the mock keyring with the signing, nonce, and attestation keys
/// `WalletServer::new` requires, regardless of which specific tool is
/// invoked. Mirrors `pay_commit_testnet_acceptance.rs`'s `seed_keyring`.
fn seed_keyring(profile: &Profile, seed: &Zeroizing<[u8; 32]>, attestation_key: &[u8; 32]) {
    let signer_ref = &profile.mcp_signer_default;
    let s_strkey = stellar_strkey::ed25519::PrivateKey::from_payload(seed.as_ref())
        .expect("32-byte seed encodes as S-strkey")
        .as_unredacted()
        .to_string();
    keyring_core::Entry::new(&signer_ref.service, &signer_ref.account)
        .expect("signer keyring entry")
        .set_password(&s_strkey)
        .expect("set signing key");

    let nonce_ref = &profile.mcp_nonce_key_alias;
    let nonce_key_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x42u8; 32]);
    keyring_core::Entry::new(&nonce_ref.service, &nonce_ref.account)
        .expect("nonce keyring entry")
        .set_password(&nonce_key_b64)
        .expect("set nonce key");

    let attest_ref = &profile.attestation_key_id;
    let attest_key_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(attestation_key);
    keyring_core::Entry::new(&attest_ref.service, &attest_ref.account)
        .expect("attestation keyring entry")
        .set_password(&attest_key_b64)
        .expect("set attestation key");
}

/// Extracts the JSON body of an MCP tool result.
fn result_json(result: &rmcp::model::CallToolResult) -> serde_json::Value {
    let text = result
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.as_str())
        .expect("tool result must carry text content");
    serde_json::from_str(text).expect("tool result text must be valid JSON")
}

/// Writes a toolset pin file declaring only the `read-rules` capability.
fn write_read_rules_toolset_pin(toolsets_root: &Path, toolset_name: &str, publisher_g: &str) {
    let toolset_dir = toolsets_root.join(toolset_name);
    std::fs::create_dir_all(&toolset_dir).expect("create toolset dir");
    let pin_json = serde_json::json!({
        "package": toolset_name,
        "version": "1.0.0",
        "shasum": "a".repeat(64),
        "publisher": publisher_g,
        "installed_at": "2026-07-05T00:00:00Z",
        "capabilities": ["read-rules"],
        "allowed_tools": []
    });
    let pin_path = toolset_dir.join(".stellar-agent-toolset-pin.json");
    std::fs::write(
        &pin_path,
        serde_json::to_string_pretty(&pin_json).expect("serialise pin"),
    )
    .expect("write pin");
}

// ─────────────────────────────────────────────────────────────────────────────
// Main flow: steps 1-7
// ─────────────────────────────────────────────────────────────────────────────

/// Full policy-observability-and-tuning flow: setup, read, transact, retune,
/// squeeze, read through real MCP dispatch, negative identification.
#[tokio::test]
async fn policy_observability_full_flow_testnet_acceptance() {
    let tmp = tempfile::tempdir().expect("tempdir must be created");
    let registry_path = tmp.path().join("networks.toml");

    // ── Step 1: deploy substrate ─────────────────────────────────────────────
    let (verifier_address, spending_limit_policy_address) =
        deploy_verifier_and_spending_limit_policy(&registry_path).await;
    let verifier_sc_addr =
        parse_c_strkey_to_smart_account(&verifier_address).expect("verifier C-strkey must parse");
    let spending_limit_policy_sc_addr =
        parse_c_strkey_to_smart_account(&spending_limit_policy_address)
            .expect("spending-limit policy C-strkey must parse");
    let xlm_sac_scaddr =
        parse_c_strkey_to_smart_account(XLM_SAC_TESTNET).expect("XLM SAC C-strkey must parse");

    let (deployer_for_threshold_g, deployer_for_threshold_box) = fresh_signer();
    fund_via_friendbot(&deployer_for_threshold_g).await;
    let threshold_policy_strkey = deploy_threshold_policy_wasm(
        &deployer_for_threshold_g,
        deployer_for_threshold_box.as_ref(),
    )
    .await;
    let threshold_policy_sc_addr = parse_c_strkey_to_smart_account(&threshold_policy_strkey)
        .expect("threshold-policy C-strkey must parse");

    let (operator_g, operator_signer_box) = fresh_signer();
    fund_via_friendbot(&operator_g).await;
    let smart_account_strkey = deploy_fresh_smart_account(&operator_g).await;
    let smart_account_sc = parse_c_strkey_to_smart_account(&smart_account_strkey)
        .expect("deployed smart-account C-strkey must parse");
    let operator_signer_sc =
        parse_g_strkey_to_signer_address(&operator_g).expect("operator G-strkey must parse");

    let agent_signing_key = SigningKey::generate(&mut OsRng);
    let agent_pubkey_bytes: [u8; 32] = agent_signing_key.verifying_key().to_bytes();
    let agent_seed: Zeroizing<[u8; 32]> = Zeroizing::new(agent_signing_key.to_bytes());
    let agent_signer_box: Box<dyn Signer + Send + Sync> =
        Box::new(SoftwareSigningKey::new_from_zeroizing(agent_seed));

    let rule_manager = fresh_rule_manager();

    let current_ledger_before_install = fetch_latest_ledger().await;
    let valid_until = current_ledger_before_install.saturating_add(VALID_UNTIL_HORIZON_LEDGERS);

    let install_param =
        build_spending_limit_install_param(LIMIT_L, PERIOD_LEDGERS).expect("install param builds");
    let call_contract_definition = ContextRuleDefinition::new(
        RuleContext::CallContract {
            contract: xlm_sac_scaddr.clone(),
        },
        "policy-obs".to_owned(), // 10 bytes; OZ MAX_NAME_SIZE = 20
        Some(valid_until),
        vec![
            ContextRuleSignerInput::Delegated {
                address: operator_signer_sc.clone(),
            },
            ContextRuleSignerInput::External {
                verifier: verifier_sc_addr.clone(),
                pubkey_data: agent_pubkey_bytes.to_vec(),
            },
        ],
        vec![
            ContextRulePolicy::new(threshold_policy_sc_addr, encode_simple_threshold_params(1)),
            ContextRulePolicy::new(spending_limit_policy_sc_addr.clone(), install_param),
        ],
    );
    let install_out = rule_manager
        .install_rule(
            smart_account_sc.clone(),
            call_contract_definition,
            vec![ContextRuleId::new(0)], // bootstrap rule authorises the install
            operator_signer_box.as_ref(),
            None,
            rid(),
            false, // accept_mutable_verifier
            false, // accept_unknown_verifier
        )
        .await
        .expect("CallContract rule install (threshold(1) + spending-limit) must succeed");
    let rule_id = install_out.rule_id;
    assert!(
        rule_id != 0,
        "installed rule_id must differ from the bootstrap rule; got {rule_id}"
    );

    let _fund_result = stellar_agent_test_support::testnet_helpers::fund_sac_balance(
        "policy-observability-acceptance",
        TESTNET_RPC_URL,
        TESTNET_PASSPHRASE,
        TESTNET_FRIENDBOT_URL,
        XLM_SAC_TESTNET,
        &smart_account_strkey,
        SMART_ACCOUNT_FUND_STROOPS.into(),
        build_sac_transfer_invoke,
        |account_id| fetch_testnet_sequence(account_id.to_owned()),
        |unsigned_xdr, funder_seed, network_passphrase| {
            sign_testnet_envelope(unsigned_xdr, funder_seed, network_passphrase.to_owned())
        },
        submit_testnet_signed_xdr,
    )
    .await
    .unwrap_or_else(|e| panic!("SAC funding of the smart account must succeed on testnet: {e}"));

    let (recipient_g, _recipient_signer) = fresh_signer();
    fund_via_friendbot(&recipient_g).await;
    let recipient_scaddr =
        parse_g_strkey_to_signer_address(&recipient_g).expect("recipient G-strkey must parse");

    // ── Step 2: `get` before any spend — limit, period, empty history, full remaining ──
    let (audit_writer, audit_log_path, _audit_dir) = tmp_audit_writer();
    let signers_mgr = fresh_signers_manager(audit_writer.clone(), audit_log_path.clone());

    let identified_policy = signers_mgr
        .identify_spending_limit_policy(smart_account_sc.clone(), rule_id, Some(&operator_g), rid())
        .await
        .expect("identify_spending_limit_policy must succeed amid a threshold policy too");
    assert_eq!(
        identified_policy, spending_limit_policy_sc_addr,
        "identification must pick the spending-limit policy specifically, not the threshold policy"
    );

    let (data_initial, as_of_ledger_initial) = signers_mgr
        .get_spending_limit_data(
            identified_policy.clone(),
            rule_id,
            smart_account_sc.clone(),
            Some(&operator_g),
            rid(),
        )
        .await
        .expect("get_spending_limit_data must succeed");
    assert_eq!(
        data_initial.spending_limit, LIMIT_L,
        "initial spending_limit must equal L"
    );
    assert_eq!(
        data_initial.period_ledgers, PERIOD_LEDGERS,
        "period_ledgers must equal P"
    );
    assert!(
        data_initial.spending_history.is_empty(),
        "spend history must be empty before any transfer; got {:?}",
        data_initial.spending_history
    );
    let window_initial = compute_spending_window(&data_initial, as_of_ledger_initial);
    assert_eq!(
        window_initial.in_window_spent, 0,
        "in_window_spent must be 0 before any transfer"
    );
    assert_eq!(
        window_initial.remaining, LIMIT_L,
        "remaining must equal L before any transfer"
    );

    // ── Step 3: agent-signed transfer of A (under the limit) — MUST succeed ──
    let rule_ids = vec![ContextRuleId::new(rule_id)];
    let transfer_a_result = submit_signed_invoke(
        SubmitInvokeArgs::builder()
            .target_contract(XLM_SAC_TESTNET)
            .auth_address(smart_account_strkey.as_str())
            .auth_rule_ids(&rule_ids)
            .host_function(transfer_host_function(
                xlm_sac_scaddr.clone(),
                smart_account_sc.clone(),
                recipient_scaddr.clone(),
                TRANSFER_A,
            ))
            .signer(operator_signer_box.as_ref())
            .ed25519_rule_signer(Ed25519RuleSigner {
                signer: agent_signer_box.as_ref(),
                verifier: verifier_sc_addr.clone(),
            })
            .primary_rpc_url(TESTNET_RPC_URL)
            .network_passphrase(TESTNET_PASSPHRASE)
            .chain_id(CHAIN_ID)
            .timeout(Duration::from_secs(TIMEOUT_SECS))
            .op_label("policy_observability_agent_transfer_a")
            .emit_observability_logs(true)
            .build(),
    )
    .await
    .expect("agent-signed transfer of A under the limit must succeed on testnet");
    assert!(
        transfer_a_result.ledger > 0,
        "the within-limit transfer must confirm on-chain; got ledger={}",
        transfer_a_result.ledger
    );

    let (data_after_a, as_of_ledger_after_a) = signers_mgr
        .get_spending_limit_data(
            identified_policy.clone(),
            rule_id,
            smart_account_sc.clone(),
            Some(&operator_g),
            rid(),
        )
        .await
        .expect("get_spending_limit_data after transfer A must succeed");
    let window_after_a = compute_spending_window(&data_after_a, as_of_ledger_after_a);
    assert_eq!(
        window_after_a.in_window_spent, TRANSFER_A,
        "in_window_spent must equal A after the transfer"
    );
    assert_eq!(
        window_after_a.remaining,
        LIMIT_L - TRANSFER_A,
        "remaining must equal L - A after the transfer"
    );
    assert_eq!(
        data_after_a.spending_history.len(),
        1,
        "spend history must have exactly one entry after the transfer; got {:?}",
        data_after_a.spending_history
    );

    // ── Step 4: retune to L2 (operator-signed) — history MUST be preserved ──
    // The retune is AUTHORIZED by the genesis admin rule (id 0), never by the
    // CallContract rule being retuned: `execute` on the smart account is an
    // auth context the CallContract(token) rule refuses on-chain
    // (UnvalidatedContext, 3002). The target rule enters only as the
    // storage-keying argument.
    let admin_auth = vec![ContextRuleId::new(0)];
    signers_mgr
        .set_spending_limit(
            smart_account_sc.clone(),
            rule_id,
            &admin_auth,
            LIMIT_L2,
            operator_signer_box.as_ref(),
            rid(),
        )
        .await
        .expect("operator-signed set_spending_limit to L2 must succeed");

    let (data_after_retune, as_of_ledger_after_retune) = signers_mgr
        .get_spending_limit_data(
            identified_policy.clone(),
            rule_id,
            smart_account_sc.clone(),
            Some(&operator_g),
            rid(),
        )
        .await
        .expect("get_spending_limit_data after retune must succeed");
    assert_eq!(
        data_after_retune.spending_limit, LIMIT_L2,
        "spending_limit must equal L2 after the retune"
    );
    assert_eq!(
        data_after_retune.spending_history.len(),
        1,
        "the issue-#7 invariant: retune must NOT reset spend history; got {:?}",
        data_after_retune.spending_history
    );
    let window_after_retune =
        compute_spending_window(&data_after_retune, as_of_ledger_after_retune);
    assert_eq!(
        window_after_retune.in_window_spent, TRANSFER_A,
        "in_window_spent must still equal A after the retune (history preserved)"
    );

    // Audit row: SaSpendingLimitRetuned with old_limit == L, new_limit == L2.
    let entries = read_audit_entries(&audit_log_path);
    let retune_entry = entries.iter().find_map(|e| match &e.event_kind {
        EventKind::SaSpendingLimitRetuned {
            rule_id: entry_rule_id,
            old_limit,
            new_limit,
            ..
        } if *entry_rule_id == rule_id => Some((*old_limit, *new_limit)),
        _ => None,
    });
    assert_eq!(
        retune_entry,
        Some((LIMIT_L, LIMIT_L2)),
        "SaSpendingLimitRetuned audit row with old_limit=L, new_limit=L2 must be emitted; \
         entries: {entries:?}"
    );

    // ── Step 5: squeeze to L3 (<= A) — further transfer MUST fail ────────────
    signers_mgr
        .set_spending_limit(
            smart_account_sc.clone(),
            rule_id,
            &admin_auth,
            LIMIT_L3,
            operator_signer_box.as_ref(),
            rid(),
        )
        .await
        .expect("operator-signed set_spending_limit to L3 (squeeze) must succeed");

    let rule_ids_squeeze = vec![ContextRuleId::new(rule_id)];
    let squeeze_err = submit_signed_invoke(
        SubmitInvokeArgs::builder()
            .target_contract(XLM_SAC_TESTNET)
            .auth_address(smart_account_strkey.as_str())
            .auth_rule_ids(&rule_ids_squeeze)
            .host_function(transfer_host_function(
                xlm_sac_scaddr.clone(),
                smart_account_sc.clone(),
                recipient_scaddr.clone(),
                SQUEEZE_TRANSFER_STROOPS,
            ))
            .signer(operator_signer_box.as_ref())
            .ed25519_rule_signer(Ed25519RuleSigner {
                signer: agent_signer_box.as_ref(),
                verifier: verifier_sc_addr.clone(),
            })
            .primary_rpc_url(TESTNET_RPC_URL)
            .network_passphrase(TESTNET_PASSPHRASE)
            .chain_id(CHAIN_ID)
            .timeout(Duration::from_secs(TIMEOUT_SECS))
            .op_label("policy_observability_squeeze_transfer")
            .emit_observability_logs(true)
            .build(),
    )
    .await
    .expect_err(
        "a transfer after the squeeze must fail: the preserved history (A) already exceeds L3",
    );

    match squeeze_err {
        SaError::DeploymentFailed {
            phase: "simulate",
            ref redacted_reason,
        } => {
            assert!(
                redacted_reason.contains("[OZ:SpendingLimitExceeded]"),
                "expected SpendingLimitExceeded (3221); got: {redacted_reason}"
            );
            assert!(
                !redacted_reason.contains("[OZ:NotAllowed]"),
                "must not be misclassified as NotAllowed (3223): {redacted_reason}"
            );
        }
        other => panic!(
            "expected DeploymentFailed {{ phase: \"simulate\" }} carrying \
             SpendingLimitExceeded; got {other:?}"
        ),
    }

    // ── Step 6: MCP read tools THROUGH REAL SERVER DISPATCH ──────────────────
    keyring_mock::install().expect("mock keyring store init");
    let attestation_key = [0x37u8; 32];
    let approval_dir = TempDir::new().expect("approval temp dir");
    let toolsets_dir = TempDir::new().expect("toolsets temp dir");

    let mut mcp_profile = Profile::builder_testnet(
        "stellar-agent",
        &operator_g,
        "stellar-agent-nonce",
        &operator_g,
    )
    .with_noop_engine()
    .build();
    mcp_profile.rpc_url = TESTNET_RPC_URL.to_owned();
    // The MCP signing key seeded here is unused by the read-only rules tools;
    // WalletServer::new still requires it to exist in the keyring.
    let (_mcp_signer_g, mcp_signer_seed) = {
        let signing_key = SigningKey::generate(&mut OsRng);
        let seed = Zeroizing::new(signing_key.to_bytes());
        (
            stellar_strkey::ed25519::PublicKey(signing_key.verifying_key().to_bytes()).to_string(),
            seed,
        )
    };
    seed_keyring(&mcp_profile, &mcp_signer_seed, &attestation_key);

    let mut server = WalletServer::new(mcp_profile).expect("WalletServer::new");
    server.set_approval_dir_for_test(approval_dir.path().to_path_buf());
    server.set_toolsets_root_for_test(toolsets_dir.path().to_path_buf());

    let get_result = server
        .call_stellar_rules_get(StellarRulesGetArgs {
            chain_id: CHAIN_ID.to_owned(),
            smart_account: smart_account_strkey.clone(),
            rule_id,
        })
        .await
        .expect("stellar_rules_get dispatch must succeed");
    let get_json = result_json(&get_result);
    assert_ne!(
        get_result.is_error,
        Some(true),
        "stellar_rules_get must not be an error result: {get_json}"
    );
    // i128 budget fields ride the wire as JSON numbers — the established
    // MCP i128 shape (blend_lend `qty`, dex_trade `qty_in`, vault
    // `amounts_desired`) and the CLI envelope's shape alike. The test
    // constants fit i64, so `as_i64` is lossless here.
    assert_eq!(
        get_json["data"]["spending_limit"]["spending_limit"]
            .as_i64()
            .map(i128::from),
        Some(LIMIT_L3),
        "MCP get budget block spending_limit must match step-5 state: {get_json}"
    );
    assert_eq!(
        get_json["data"]["spending_limit"]["in_window_spent"]
            .as_i64()
            .map(i128::from),
        Some(TRANSFER_A),
        "MCP get budget block in_window_spent must match step-5 state: {get_json}"
    );
    assert_eq!(
        get_json["data"]["spending_limit"]["remaining_budget"].as_i64(),
        Some(0),
        "MCP get budget block remaining_budget must be 0 after the squeeze: {get_json}"
    );
    assert_eq!(
        get_json["data"]["expires_in_ledgers"]
            .as_u64()
            .map(|v| v > 0),
        Some(true),
        "MCP get expires_in_ledgers must be a positive value: {get_json}"
    );
    let policies = get_json["data"]["policies"]
        .as_array()
        .expect("policies must be an array");
    assert_eq!(
        policies.len(),
        2,
        "both attached policies must be reported: {get_json}"
    );
    assert!(
        policies
            .iter()
            .any(|p| p["identified_kind"].as_str() == Some("spending-limit")),
        "one policy must identify as spending-limit: {get_json}"
    );
    assert!(
        policies
            .iter()
            .any(|p| p["identified_kind"].as_str() == Some("threshold")),
        "one policy must identify as threshold: {get_json}"
    );

    let list_result = server
        .call_stellar_rules_list(StellarRulesListArgs {
            chain_id: CHAIN_ID.to_owned(),
            smart_account: smart_account_strkey.clone(),
        })
        .await
        .expect("stellar_rules_list dispatch must succeed");
    let list_json = result_json(&list_result);
    assert_ne!(
        list_result.is_error,
        Some(true),
        "stellar_rules_list must not error: {list_json}"
    );
    let rules = list_json["data"]["rules"]
        .as_array()
        .expect("rules must be an array");
    let listed_rule = rules
        .iter()
        .find(|r| r["rule_id"].as_u64() == Some(u64::from(rule_id)))
        .expect("installed rule must appear in the list view");
    assert!(
        listed_rule["valid_until"].as_u64().is_some(),
        "list view must carry the valid_until field: {listed_rule}"
    );

    // Toolset-grant assertion: a toolset declaring ONLY read-rules resolves
    // and dispatches stellar_rules_get end-to-end through check_toolset_action.
    write_read_rules_toolset_pin(toolsets_dir.path(), "policy-obs-read-rules", &operator_g);
    let toolset_invoke_result = server
        .call_stellar_toolset_invoke(StellarToolsetInvokeArgs {
            toolset: "policy-obs-read-rules".to_owned(),
            action: "stellar_rules_get".to_owned(),
            chain_id: Some(CHAIN_ID.to_owned()),
            args: serde_json::json!({
                "chain_id": CHAIN_ID,
                "smart_account": &smart_account_strkey,
                "rule_id": rule_id,
            }),
        })
        .await
        .expect("read-rules toolset must resolve and dispatch stellar_rules_get");
    let toolset_json = result_json(&toolset_invoke_result);
    assert_ne!(
        toolset_invoke_result.is_error,
        Some(true),
        "toolset-routed stellar_rules_get must not error: {toolset_json}"
    );
    assert_eq!(
        toolset_json["data"]["spending_limit"]["spending_limit"]
            .as_i64()
            .map(i128::from),
        Some(LIMIT_L3),
        "toolset-routed dispatch must reach the same state: {toolset_json}"
    );

    // ── Step 7: negative — bootstrap rule has no spending-limit policy ───────
    let negative_err = signers_mgr
        .identify_spending_limit_policy(smart_account_sc.clone(), 0, Some(&operator_g), rid())
        .await
        .expect_err("bootstrap rule (no policies) must fail identification, not decode");
    match negative_err {
        SaError::SpendingLimitNotInstalled {
            rule_id: err_rule_id,
            ..
        } => {
            assert_eq!(
                err_rule_id, 0,
                "SpendingLimitNotInstalled must name the bootstrap rule"
            );
        }
        other => panic!("expected SaError::SpendingLimitNotInstalled; got {other:?}"),
    }
}
