//! Testnet acceptance tests for per-rule caps fail-CLOSED enforcement.
//!
//! # Coverage
//!
//! | Fixture | Description |
//! |---------|-------------|
//! | [`h1_16th_signer_refused`] | Deploy SA; install rule with `OZ_MAX_SIGNERS = 15` signers; attempt to add 16th via the release binary — must exit non-zero with `validation.context_rule_caps_exceeded` in the JSON envelope BEFORE the `add_signer` submit |
//! | [`h2_6th_policy_refused`] | Deploy SA; install rule with 5 policies; attempt to add 6th via the release binary — must exit non-zero with `validation.context_rule_caps_exceeded { kind: "policy", attempted: 6, max: 5 }` BEFORE simulate |
//!
//! # Gating
//!
//! Feature flags: `testnet-integration` + `deploy-cli`. Run with:
//!
//! ```text
//! cargo build --release -p stellar-agent-cli
//! cargo test --features "testnet-integration,deploy-cli" --test wallet_caps_testnet_acceptance
//! ```
//!
//! `deploy-cli` is required for `THRESHOLD_POLICY_WASM` (used by `h2_6th_policy_refused` setup).
//! Tests require live testnet access and Friendbot funding. They are excluded
//! from default `cargo test` runs.
//!
//! If the release binary is not built, the signer-cap and policy-cap tests log a
//! skip message and return without failing.
//!
//! # Reference cross-check
//!
//! - OZ `packages/accounts/src/smart_account/mod.rs:526` SHA `3f81125`:
//!   `pub const MAX_SIGNERS: u32 = 15`.
//! - OZ `packages/accounts/src/smart_account/mod.rs:558` SHA `3f81125`:
//!   `TooManySigners = 3010` (on-chain fallback panic if CLI check bypassed).
//! - OZ `packages/accounts/src/smart_account/storage.rs:155-174` SHA `3f81125`:
//!   `ContextRule` struct + `signer_ids: Vec<u32>` field layout decoded by
//!   `decode_signer_count_from_scval`.
//!
//! # Implements
//!
//! Context rule caps enforcement: signer and policy count limits are checked
//! fail-closed before any simulate or submit operation.

#![cfg(feature = "testnet-integration")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::use_debug,
    clippy::print_stderr,
    reason = "test-only; panics and diagnostic output are acceptable in testnet acceptance tests"
)]

use std::time::Duration;

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use sha2::{Digest as _, Sha256};
use stellar_agent_core::smart_account::rule_id::ContextRuleId;
use stellar_agent_network::signing::envelope_signing::attach_signature;
use stellar_agent_network::{StellarRpcClient, fetch_account, submit_transaction_and_wait};
use stellar_agent_smart_account::bindings::ContextRuleType;
use stellar_agent_smart_account::deployment::{
    DeployerKeypair, DeploymentArgs, ResolvedFeePerOp, deploy_smart_account,
    derive_smart_account_address,
};
use stellar_agent_smart_account::managers::rules::{
    ContextRuleDefinition, ContextRuleManager, ContextRuleManagerConfig, ContextRulePolicy,
    ContextRuleSignerInput, OZ_MAX_POLICIES, decode_policy_count_from_scval,
    decode_signer_count_from_scval, parse_c_strkey_to_smart_account,
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
use zeroize::Zeroizing;

// ── Network constants ─────────────────────────────────────────────────────────

const TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";
const TESTNET_FRIENDBOT_URL: &str = "https://friendbot.stellar.org";
const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";
const CHAIN_ID: &str = "stellar:testnet";
const FEE_STROOPS: u32 = 1_000_000;
const TIMEOUT_SECS: u64 = 120;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn fresh_signer() -> (
    String,
    String,
    Box<dyn stellar_agent_network::Signer + Send + Sync>,
) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let g_strkey = format!(
        "{}",
        stellar_strkey::ed25519::PublicKey(verifying_key.to_bytes())
    );
    // S-strkey for passing to the binary via --signer-secret-env.
    // `stellar_strkey::ed25519::PrivateKey` wraps the raw 32-byte seed.
    // `.to_string()` is called explicitly to convert the `heapless::String<56>`
    // returned by `stellar_strkey`'s Display impl into a `std::string::String`.
    let s_strkey = format!(
        "{}",
        stellar_strkey::ed25519::PrivateKey(signing_key.to_bytes()).as_unredacted()
    );
    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(signing_key.to_bytes());
    let signer: Box<dyn stellar_agent_network::Signer + Send + Sync> =
        Box::new(stellar_agent_network::SoftwareSigningKey::new_from_zeroizing(seed));
    (g_strkey, s_strkey, signer)
}

fn fresh_deployer() -> (String, DeployerKeypair) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let g_strkey = format!(
        "{}",
        stellar_strkey::ed25519::PublicKey(verifying_key.to_bytes())
    );
    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(signing_key.to_bytes());
    let signer: Box<dyn stellar_agent_network::Signer + Send + Sync> =
        Box::new(stellar_agent_network::SoftwareSigningKey::new_from_zeroizing(seed));
    (
        g_strkey,
        DeployerKeypair::SecretEnv {
            var_name: "testnet-caps-acceptance".to_owned(),
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

/// Locates the workspace-root-relative release binary path.
///
/// `CARGO_MANIFEST_DIR` for this test crate is
/// `crates/stellar-agent-smart-account`; walking two levels up reaches the
/// workspace root.
fn release_binary() -> std::path::PathBuf {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .expect("crates/")
        .parent()
        .expect("workspace root");
    workspace_root.join("target/release/stellar-agent")
}

// ── 16th signer refused ───────────────────────────────────────────────────────

/// Deploy a fresh smart account, install a context rule with exactly
/// `OZ_MAX_SIGNERS = 15` delegated signers, then invoke the release binary to
/// add a 16th signer — the CLI must exit non-zero and the stdout JSON envelope
/// must carry `validation.context_rule_caps_exceeded`.
///
/// # Design
///
/// The test exercises the production CLI binary, not library internals, so
/// that any future regression that reorders or drops the cap-check in `add_run`
/// is caught end-to-end. The substrate setup (deploy + install 15-signer rule +
/// `decode_signer_count_from_scval` assertion) remains as a precondition guard:
/// if the substrate is wrong, the test fails early with a clear message before
/// the binary is invoked.
///
/// # Steps
///
/// 1. Generate and fund the operator signer.
/// 2. Deploy a fresh smart account with that signer as the initial signer.
/// 3. Generate 15 fresh signer G-strkeys; install a 15-signer rule (rule_id 1).
/// 4. Fetch the installed rule; assert `decode_signer_count_from_scval == 15`
///    (precondition guard — verifies the substrate before invoking the binary).
/// 5. Spawn `target/release/stellar-agent wallet signers add` with the 16th
///    signer's G-strkey, passing the operator S-strkey via
///    `--signer-secret-env`.
/// 6. Assert exit code is non-zero.
/// 7. Assert the stdout JSON envelope has `ok: false` and
///    `error.code == "validation.context_rule_caps_exceeded"`.
///
/// # Graceful skip
///
/// If the release binary is not present, the test logs a skip message and
/// returns without failing. The binary smoke gate enforces that the binary is
/// built before sealing.
///
/// # Reference cross-check
///
/// - OZ `storage.rs:155-174` SHA `3f81125`: `ContextRule.signer_ids: Vec<u32>`
///   is the field decoded by `decode_signer_count_from_scval`.
/// - OZ `mod.rs:526` SHA `3f81125`: `MAX_SIGNERS = 15`.
/// - OZ `mod.rs:558` SHA `3f81125`: `TooManySigners = 3010` (on-chain fallback).
///
/// # Implements
///
/// Context rule signer cap: the 16th signer is refused before simulate/submit.
#[tokio::test]
async fn h1_16th_signer_refused() {
    // ── Locate the release binary ─────────────────────────────────────────────
    let binary = release_binary();
    if !binary.exists() {
        eprintln!(
            "SKIP: release binary not found at {}. \
             Run `cargo build --release -p stellar-agent-cli` first.",
            binary.display()
        );
        // Not a hard failure: the binary smoke gate is enforced separately.
        // Return gracefully so the full testnet acceptance run does not
        // gate-fail on a missing pre-built binary.
        return;
    }
    eprintln!("h1: using binary: {}", binary.display());

    // ── Step 1: Generate and fund the primary operator signer ────────────────
    let (operator_g, operator_s_strkey, operator_signer) = fresh_signer();
    fund_via_friendbot(&operator_g).await;

    // ── Step 2: Deploy a fresh smart account ─────────────────────────────────
    let smart_account_strkey = deploy_fresh_smart_account(&operator_g).await;
    let smart_account = parse_c_strkey_to_smart_account(&smart_account_strkey)
        .expect("C-strkey parsed at deployment must re-parse");

    eprintln!("h1: smart_account = {smart_account_strkey}");

    // ── Step 3: Generate 15 fresh signer G-strkeys for the context rule ───────
    // These do NOT need to be funded — they are identifiers for the rule, not
    // sources of fee payment.
    let mut signers: Vec<ContextRuleSignerInput> = Vec::with_capacity(15);
    for _ in 0..15_u32 {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let g_strkey = format!(
            "{}",
            stellar_strkey::ed25519::PublicKey(verifying_key.to_bytes())
        );
        let sc_addr = parse_g_strkey_to_signer_address(&g_strkey)
            .expect("fresh G-strkey must parse to ScAddress");
        signers.push(ContextRuleSignerInput::Delegated { address: sc_addr });
    }
    assert_eq!(signers.len(), 15, "must have exactly 15 signers");

    // ── Step 4: Install the 15-signer context rule ───────────────────────────
    // install_rule is invoked with `None` for the audit writer; the cap-check
    // failure path never reaches audit-log emission, so no writer is needed.
    let rule_manager = fresh_rule_manager();

    let definition = ContextRuleDefinition::new(
        ContextRuleType::Default,
        "h1-cap-test-rule".to_owned(),
        None, // permanent
        signers,
        vec![], // no policies
    );

    let auth_rule_ids = vec![ContextRuleId::new(0)]; // bootstrap rule authorises this install

    let install_output = rule_manager
        .install_rule(
            smart_account.clone(),
            definition,
            auth_rule_ids,
            operator_signer.as_ref(),
            None,
            "h1-install-request-id".to_owned(),
            false, // accept_mutable_verifier
            false, // accept_unknown_verifier
        )
        .await
        .expect("install_rule with 15 signers must succeed on testnet");

    let rule_id = install_output.rule_id;
    eprintln!("h1: installed 15-signer rule: rule_id = {rule_id}");

    // ── Step 5: Precondition guard — decode and assert signer count = 15 ──────
    // This guard verifies the substrate is correct before invoking the binary.
    // If the decode fails here, the rule installation was malformed — a
    // substrate problem, not a cap-check problem.
    let current_scval = rule_manager
        .get_rule(smart_account.clone(), rule_id, &operator_g)
        .await
        .expect("get_rule must succeed")
        .expect("rule must be present (just installed)");

    let current_signer_count = decode_signer_count_from_scval(&current_scval)
        .expect("decode_signer_count_from_scval must succeed on the freshly-installed rule");

    assert_eq!(
        current_signer_count, 15,
        "h1: precondition guard: installed rule must have exactly 15 signers; \
         got {current_signer_count}"
    );
    eprintln!("h1: precondition guard passed: signer_count = {current_signer_count}");

    // ── Step 6: Generate the 16th signer G-strkey ────────────────────────────
    let sixteenth_signing_key = SigningKey::generate(&mut OsRng);
    let sixteenth_verifying_key = sixteenth_signing_key.verifying_key();
    let sixteenth_signer_g = format!(
        "{}",
        stellar_strkey::ed25519::PublicKey(sixteenth_verifying_key.to_bytes())
    );

    // ── Step 7: Set the operator S-strkey env var and invoke the binary ───────
    // The env var name is chosen to be unlikely to collide with ambient env.
    // The S-strkey is an ephemeral testnet-only keypair generated above; it
    // does not appear as a literal in this source file (no bare S-strkey).
    let signer_env_var = "H1_CAPS_TEST_OPERATOR_SKEY";
    let rule_id_str = rule_id.to_string();

    eprintln!(
        "h1: invoking binary: wallet signers add --account {} --rule-id {} \
         --new-signer {} --network testnet --rpc-url {} --signer-secret-env {}",
        smart_account_strkey, rule_id_str, sixteenth_signer_g, TESTNET_RPC_URL, signer_env_var
    );

    let output = std::process::Command::new(&binary)
        .args([
            "wallet",
            "signers",
            "add",
            "--account",
            &smart_account_strkey,
            "--rule-id",
            &rule_id_str,
            "--new-signer",
            &sixteenth_signer_g,
            "--network",
            "testnet",
            "--rpc-url",
            TESTNET_RPC_URL,
            "--signer-secret-env",
            signer_env_var,
        ])
        .env(signer_env_var, &operator_s_strkey)
        .output()
        .expect("spawn wallet signers add");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    eprintln!("h1: exit code: {}", output.status.code().unwrap_or(-1));
    eprintln!(
        "h1: stderr (first 512 chars): {}",
        stderr.chars().take(512).collect::<String>()
    );
    eprintln!("h1: stdout: {stdout}");

    // ── Step 8: Assert exit code is non-zero ─────────────────────────────────
    // The cap check must fire BEFORE any simulate/submit cycle; the binary must
    // refuse and exit with a non-zero status.
    assert_ne!(
        output.status.code().unwrap_or(0),
        0,
        "wallet signers add must exit non-zero when adding the 16th signer; \
         stdout: {stdout}"
    );

    // ── Step 9: Assert the JSON envelope carries the typed cap error ──────────
    let envelope: serde_json::Value =
        serde_json::from_str(&stdout).expect("h1: stdout must be valid JSON");

    assert_eq!(
        envelope["ok"],
        serde_json::Value::Bool(false),
        "h1: envelope.ok must be false; got: {envelope}"
    );

    assert_eq!(
        envelope["error"]["code"],
        serde_json::Value::String("validation.context_rule_caps_exceeded".to_owned()),
        "h1: error.code must be 'validation.context_rule_caps_exceeded'; got: {envelope}"
    );

    // Assert the error message names the kind and attempted count.
    let error_message = envelope["error"]["message"].as_str().unwrap_or("");
    assert!(
        error_message.contains("Signer"),
        "h1: error.message must name kind=Signer; got: {error_message}"
    );
    assert!(
        error_message.contains("16"),
        "h1: error.message must name attempted=16; got: {error_message}"
    );
    assert!(
        error_message.contains("15"),
        "h1: error.message must name max=15; got: {error_message}"
    );
}

// ── Policy-cap helpers ────────────────────────────────────────────────────────

/// Encodes `SimpleThresholdAccountParams { threshold: N }` as a Soroban ScVal.
///
/// `#[contracttype]` struct encoding: `ScVal::Map(ScMap([("threshold", U32(N))]))`.
/// Per OZ `packages/accounts/src/policies/simple_threshold.rs:96-102` SHA
/// `3f81125` — `SimpleThresholdAccountParams { threshold: u32 }`.
fn encode_threshold_params_h2(threshold: u32) -> ScVal {
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
/// The deployed contract address is deterministic: it is derived from
/// `sha256("oz-threshold-policy-v0.7.1-{salt_suffix}")` and the deployer's
/// G-strkey. Distinct `salt_suffix` values produce distinct contract addresses
/// even when the same deployer and the same WASM are used, which is required
/// for the 5-policy rule (5 distinct policy contracts) where the on-chain
/// `ScMap<Address, Val>` key uniqueness constraint (enforced by the Soroban
/// host — rs-stellar-xdr `scval_validations.rs`, `validate_scmap`) would
/// reject a map with duplicate `Address` keys.
///
/// # Idempotence
///
/// WASM upload is gated by an on-chain existence check (idempotent across runs).
/// Contract creation is idempotent: an `AlreadyExists` / `ContractAlreadyExists`
/// error is treated as success; the deterministic address is returned
/// regardless.
///
/// # Reference cross-check
///
/// - OZ `storage.rs:632-638` SHA `3f81125`: `add_context_rule` takes
///   `policies: &Map<Address, Val>` — a Soroban Map, whose keys are unique
///   by construction. The wallet's off-chain `ScVal::Map` encoding for the
///   policies argument therefore MUST NOT contain duplicate `Address` keys.
/// - `rs-stellar-xdr/src/curr/scval_validations.rs:58-75`: the Soroban host
///   validates every `ScVal::Map` for strict ascending key order; duplicate
///   keys fail with `Error::Invalid` at the simulate phase.
/// - OZ `storage.rs:1119-1121` SHA `3f81125`: `add_policy` also rejects
///   duplicate addresses via `DuplicatePolicy` panic, making a second
///   `add_policy(same_addr)` call on any rule impossible.
async fn deploy_threshold_policy_with_salt(
    deployer_g: &str,
    signer: &(dyn stellar_agent_network::Signer + Send + Sync),
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

// ── Policy-cap helpers (continued) ───────────────────────────────────────────

/// Deploys 5 distinct threshold-policy contracts for the policy-cap test setup.
///
/// Each contract is deployed with salt suffix `"h2-salt-N"` (N = 1..=5), producing
/// 5 distinct contract addresses from the same WASM.  This is required because
/// the `policies` argument to OZ `add_context_rule` is typed
/// `Map<Address, Val>` (OZ `storage.rs:632-638` SHA `3f81125`), whose keys
/// must be unique. The wallet's off-chain encoding as `ScVal::Map` is validated
/// by the Soroban host for strict ascending key order with no duplicates
/// (`scval_validations.rs:58-75`); passing 5 entries with the same `Address`
/// key would fail at the simulate phase with `Error::Invalid`.
///
/// The 5 deployments share the same WASM bytes (upload is idempotent) but
/// produce distinct on-chain contract addresses.
async fn deploy_five_distinct_threshold_policies_h2(
    deployer_g: &str,
    signer: &(dyn stellar_agent_network::Signer + Send + Sync),
) -> Vec<String> {
    let mut addrs = Vec::with_capacity(5);
    for n in 1_u32..=5 {
        let suffix = format!("h2-salt-{n}");
        let addr = deploy_threshold_policy_with_salt(deployer_g, signer, &suffix).await;
        addrs.push(addr);
    }
    addrs
}

// ── 6th policy refused ────────────────────────────────────────────────────────

/// Deploy a fresh smart account, install a context rule with exactly
/// `OZ_MAX_POLICIES = 5` policies, then invoke the release binary to add a
/// 6th policy — the CLI must exit non-zero and the stdout JSON envelope must
/// carry `validation.context_rule_caps_exceeded` with
/// `kind = "policy"`, `attempted = 6`, `max = 5`.
///
/// # Design
///
/// Mirrors the `h1_16th_signer_refused` pattern: the test exercises the production CLI binary
/// end-to-end. A substrate setup (deploy + install 5-policy rule +
/// `decode_policy_count_from_scval` assertion) acts as a precondition guard.
///
/// The `--install-param` passed to the binary is `ScVal::Void` (encoded as
/// standard base64 XDR), which is the simplest syntactically-valid install
/// param. The cap check fires BEFORE simulate, so the policy's on-chain
/// installer is never invoked.
///
/// # Why 5 DISTINCT policy contracts are required
///
/// The `policies` argument to OZ `add_context_rule` is typed
/// `Map<Address, Val>` (OZ `storage.rs:632-638` SHA `3f81125`). The wallet
/// encodes this off-chain as `ScVal::Map` (rules.rs `build_add_context_rule_args`).
/// The Soroban host validates every `ScVal::Map` for strict ascending key order
/// with no duplicate keys (rs-stellar-xdr `scval_validations.rs`, `validate_scmap`).
/// Passing 5 entries with the same `Address` key would fail at the simulate
/// phase with `Error::Invalid` — the rule would never be installed and the
/// test's precondition guard at step 5 would never pass.
/// Additionally, OZ `storage.rs:1119-1121` (`add_policy`) rejects any subsequent
/// `add_policy(same_addr)` call with `DuplicatePolicy`.
///
/// # Steps
///
/// 1. Generate and fund the operator signer.
/// 2. Deploy a fresh smart account.
/// 3. Deploy 5 DISTINCT threshold-policy contracts (salts `h2-salt-1..h2-salt-5`).
/// 4. Install a 5-policy rule with the 5 distinct addresses.
/// 5. Fetch the installed rule; assert `decode_policy_count_from_scval == 5`.
/// 6. Spawn the binary with `wallet rules add-policy` for the 6th policy.
/// 7. Assert exit code is non-zero.
/// 8. Assert the JSON envelope carries `validation.context_rule_caps_exceeded`.
///
/// # Reference cross-check
///
/// - OZ `mod.rs:524` SHA `3f81125`: `pub const MAX_POLICIES: u32 = 5`.
/// - OZ `mod.rs:560` SHA `3f81125`: `TooManyPolicies = 3011` (on-chain fallback).
/// - OZ `storage.rs:171` SHA `3f81125`: `ContextRuleEntry.policy_ids: Vec<u32>`.
/// - OZ `storage.rs:632-638` SHA `3f81125`: `add_context_rule` takes
///   `policies: &Map<Address, Val>` — Soroban Map with unique Address keys.
/// - `scval_validations.rs:58-75`: Soroban host rejects `ScVal::Map` with
///   duplicate keys.
/// - OZ `storage.rs:1119-1121` SHA `3f81125`: `add_policy` panics with
///   `DuplicatePolicy` when the same address is already registered in the rule.
///
/// # Implements
///
/// Context rule policy cap: the 6th policy is refused before simulate/submit.
#[tokio::test]
async fn h2_6th_policy_refused() {
    // ── Locate the release binary ─────────────────────────────────────────────
    let binary = release_binary();
    if !binary.exists() {
        eprintln!(
            "SKIP: release binary not found at {}. \
             Run `cargo build --release -p stellar-agent-cli` first.",
            binary.display()
        );
        return;
    }
    eprintln!("h2: using binary: {}", binary.display());

    // ── Step 1: Generate and fund the operator signer ────────────────────────
    let (operator_g, operator_s_strkey, operator_signer) = fresh_signer();
    fund_via_friendbot(&operator_g).await;

    // ── Step 2: Deploy a fresh smart account ─────────────────────────────────
    let smart_account_strkey = deploy_fresh_smart_account(&operator_g).await;
    let smart_account = parse_c_strkey_to_smart_account(&smart_account_strkey)
        .expect("C-strkey parsed at deployment must re-parse");

    eprintln!("h2: smart_account = {smart_account_strkey}");

    // ── Step 3: Deploy 5 distinct threshold-policy contracts ─────────────────
    // Each contract is deployed with a unique salt suffix (h2-salt-1..h2-salt-5)
    // so the resulting addresses are distinct. This is required because the
    // `policies` arg to OZ `add_context_rule` is `Map<Address, Val>`; the
    // wallet's ScVal::Map encoding is validated by the Soroban host for strict
    // ascending key order with no duplicate keys (scval_validations.rs:58-75).
    // Using 5 entries with the same Address key would fail at simulate.
    let policy_strkeys =
        deploy_five_distinct_threshold_policies_h2(&operator_g, operator_signer.as_ref()).await;
    assert_eq!(
        policy_strkeys.len(),
        5,
        "h2: must have deployed exactly 5 distinct policy contracts"
    );
    // Sanity: all 5 addresses must be distinct.
    let mut dedup_check = policy_strkeys.clone();
    dedup_check.sort_unstable();
    dedup_check.dedup();
    assert_eq!(
        dedup_check.len(),
        5,
        "h2: all 5 deployed policy addresses must be distinct"
    );
    eprintln!("h2: deployed 5 distinct threshold-policy contracts");

    // The first policy is used as the "6th add-policy" attempt target later.
    let sixth_policy_strkey = policy_strkeys[0].clone();

    // ── Step 4: Install a 5-policy rule with 5 DISTINCT addresses ────────────
    // Using distinct addresses satisfies the Soroban ScVal::Map uniqueness
    // constraint (scval_validations.rs:58-75) and the on-chain Map<Address, Val>
    // semantics of the `policies` argument to `add_context_rule`
    // (OZ storage.rs:632-638 SHA `3f81125`).
    let threshold_params = encode_threshold_params_h2(1);
    let policies: Vec<ContextRulePolicy> = policy_strkeys
        .iter()
        .map(|strkey| {
            let addr = parse_c_strkey_to_smart_account(strkey).expect("policy C-strkey must parse");
            ContextRulePolicy::new(addr, threshold_params.clone())
        })
        .collect();

    let signer_addr = parse_g_strkey_to_signer_address(&operator_g)
        .expect("operator G-strkey must parse to ScAddress");

    let rule_manager = fresh_rule_manager();
    let definition = ContextRuleDefinition::new(
        ContextRuleType::Default,
        "h2-cap-test-rule".to_owned(),
        None,
        vec![ContextRuleSignerInput::Delegated {
            address: signer_addr,
        }],
        policies,
    );

    let install_output = rule_manager
        .install_rule(
            smart_account.clone(),
            definition,
            vec![ContextRuleId::new(0)],
            operator_signer.as_ref(),
            None,
            "h2-install-request-id".to_owned(),
            false, // accept_mutable_verifier
            false, // accept_unknown_verifier
        )
        .await
        .expect("h2: install_rule with 5 policies must succeed on testnet");

    let rule_id = install_output.rule_id;
    eprintln!("h2: installed 5-policy rule: rule_id = {rule_id}");

    // ── Step 5: Precondition guard — decode and assert policy count = 5 ───────
    let current_scval = rule_manager
        .get_rule(smart_account.clone(), rule_id, &operator_g)
        .await
        .expect("h2: get_rule must succeed")
        .expect("h2: rule must be present (just installed)");

    let current_policy_count = decode_policy_count_from_scval(&current_scval)
        .expect("decode_policy_count_from_scval must succeed");

    assert_eq!(
        current_policy_count, 5,
        "h2: precondition guard: installed rule must have exactly 5 policies; \
         got {current_policy_count}"
    );
    eprintln!("h2: precondition guard passed: policy_count = {current_policy_count}");
    assert_eq!(OZ_MAX_POLICIES, 5, "OZ_MAX_POLICIES constant must be 5");

    // ── Step 6: Encode ScVal::Void as the install-param for the 6th policy ────
    // The cap check fires BEFORE simulate, so the param type does not matter.
    let void_b64 = stellar_xdr::ScVal::Void
        .to_xdr_base64(stellar_xdr::Limits::none())
        .expect("ScVal::Void to base64 must succeed");

    // ── Step 7: Spawn the binary and attempt the 6th policy add ──────────────
    let signer_env_var = "H2_CAPS_TEST_OPERATOR_SKEY";
    let rule_id_str = rule_id.to_string();

    // The 6th policy target is the first of the 5 deployed contracts.  All 5 of
    // those addresses are already installed in the rule, so ANY of them would
    // trigger DuplicatePolicy at the on-chain layer.  However, the CLI cap check
    // fires BEFORE simulate (policy_count == 5 == OZ_MAX_POLICIES), so the binary
    // exits with the typed cap error before reaching the on-chain layer.
    eprintln!(
        "h2: invoking binary: wallet rules add-policy --account {} --rule-id {} \
         --policy-address {} --install-param <void> --network testnet --rpc-url {} \
         --signer-secret-env {}",
        smart_account_strkey, rule_id_str, sixth_policy_strkey, TESTNET_RPC_URL, signer_env_var
    );

    let output = std::process::Command::new(&binary)
        .args([
            "wallet",
            "rules",
            "add-policy",
            "--account",
            &smart_account_strkey,
            "--rule-id",
            &rule_id_str,
            "--policy-address",
            &sixth_policy_strkey,
            "--install-param",
            &void_b64,
            "--network",
            "testnet",
            "--rpc-url",
            TESTNET_RPC_URL,
            "--signer-secret-env",
            signer_env_var,
        ])
        .env(signer_env_var, &operator_s_strkey)
        .output()
        .expect("spawn wallet rules add-policy");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    eprintln!("h2: exit code: {}", output.status.code().unwrap_or(-1));
    eprintln!(
        "h2: stderr (first 512 chars): {}",
        stderr.chars().take(512).collect::<String>()
    );
    eprintln!("h2: stdout: {stdout}");

    // ── Step 8: Assert exit code is non-zero ─────────────────────────────────
    assert_ne!(
        output.status.code().unwrap_or(0),
        0,
        "wallet rules add-policy must exit non-zero when adding the 6th policy; \
         stdout: {stdout}"
    );

    // ── Step 9: Assert the JSON envelope carries the typed cap error ──────────
    let envelope: serde_json::Value =
        serde_json::from_str(&stdout).expect("h2: stdout must be valid JSON");

    assert_eq!(
        envelope["ok"],
        serde_json::Value::Bool(false),
        "h2: envelope.ok must be false; got: {envelope}"
    );

    assert_eq!(
        envelope["error"]["code"],
        serde_json::Value::String("validation.context_rule_caps_exceeded".to_owned()),
        "h2: error.code must be 'validation.context_rule_caps_exceeded'; got: {envelope}"
    );

    let error_message = envelope["error"]["message"].as_str().unwrap_or("");
    assert!(
        error_message.contains("Policy"),
        "h2: error.message must name kind=Policy; got: {error_message}"
    );
    assert!(
        error_message.contains("6"),
        "h2: error.message must name attempted=6; got: {error_message}"
    );
    assert!(
        error_message.contains("5"),
        "h2: error.message must name max=5; got: {error_message}"
    );
}
