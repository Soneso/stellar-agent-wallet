//! Testnet acceptance tests for `wallet sa migrate-verifier`.
//!
//! # Test: dry-run plan construction
//!
//! **`d1_migrate_verifier_dry_run_constructs_plan_without_submitting`**
//!
//! Creates a fresh smart account on testnet and calls `MigrationPlanner::build`
//! against a freshly deployed OZ WebAuthn verifier.  Asserts all three pre-flight
//! gates pass and `affected_rules` is empty (no External signers on a fresh account).
//! No transactions are submitted.
//!
//! # Test: dry-run identifies External signer
//!
//! **`d2_migrate_verifier_dry_run_identifies_one_external_signer`**
//!
//! Deploys a fresh smart account, installs a context rule with one External signer
//! pointing to the OZ WebAuthn verifier, then calls `MigrationPlanner::build`.
//! Asserts one affected rule with one signer step is detected.  No transactions
//! are submitted.
//!
//! # Test: on-chain submit
//!
//! **`d3_migrate_verifier_on_chain_submit`**
//!
//! Deploys a fresh smart account, two OZ WebAuthn verifier instances (same WASM,
//! different addresses), and a threshold-policy.  Installs a context rule with
//! one External signer pointing to verifier-A.  Calls `MigrationPlan::submit` to
//! execute the remove+add pair on-chain (verifier-A → verifier-B).  Asserts the
//! submit result has no failure, the audit log contains one `SaVerifierMigrated`
//! row, and the post-migration on-chain `ContextRule` satisfies seven decoded
//! invariants: External verifier address, pubkey preservation, policies list
//! preservation, Delegated signer address preservation, policy_ids
//! preservation, and Delegated signer on-chain id invariance across the
//! remove+add pair.
//!
//! # Gating
//!
//! Compiled only under `--features testnet-integration`:
//!
//! ```text
//! cargo test --features testnet-integration --test wallet_sa_migrate_verifier_testnet_acceptance
//! ```
//!

#![cfg(feature = "testnet-integration")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::use_debug,
    clippy::print_stderr,
    reason = "test-only; panics and diagnostic output are acceptable in testnet acceptance tests"
)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use sha2::{Digest as _, Sha256};
use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_core::constants::SIMULATE_SENTINEL_G;
use stellar_agent_core::smart_account::rule_id::ContextRuleId;
use stellar_agent_network::signing::envelope_signing::attach_signature;
use stellar_agent_network::{
    Signer, SoftwareSigningKey, StellarRpcClient, fetch_account, submit_transaction_and_wait,
};
use stellar_agent_smart_account::bindings::ContextRuleType;
use stellar_agent_smart_account::deployment::{
    DeployerKeypair, DeploymentArgs, ResolvedFeePerOp, WebAuthnVerifierDeployArgs,
    deploy_smart_account, deploy_webauthn_verifier, derive_smart_account_address,
};
use stellar_agent_smart_account::managers::migration::MigrationPlanner;
use stellar_agent_smart_account::managers::rules::{
    ContextRuleDefinition, ContextRuleManager, ContextRuleManagerConfig, ContextRulePolicy,
    ContextRuleSignerInput, parse_c_strkey_to_smart_account, parse_g_strkey_to_signer_address,
};
use stellar_agent_smart_account::managers::signers::{SignersManager, SignersManagerConfig};
use stellar_agent_smart_account::signers::policy_identification::THRESHOLD_POLICY_WASM;
use stellar_agent_smart_account::verifier_allowlist::{VERIFIER_ALLOWLIST, VerifierAuditStatus};
use stellar_agent_smart_account::{DecodedOnChainSigner, decode_signer_scval_full};
use stellar_agent_test_support::verifier_registry::fresh_verifier_registry_tempdir;
use stellar_baselib::account::{Account as BaselibAccount, AccountBehavior};
use stellar_baselib::transaction::{Transaction, TransactionBehavior};
use stellar_baselib::transaction_builder::{TransactionBuilder, TransactionBuilderBehavior};
use stellar_rpc_client::Client;
use stellar_xdr::{
    AccountId, BytesM, ContractExecutable, ContractIdPreimage, ContractIdPreimageFromAddress,
    CreateContractArgsV2, Hash, HostFunction, InvokeContractArgs, InvokeHostFunctionOp, LedgerKey,
    LedgerKeyContractCode, Limits, Operation, OperationBody, PublicKey as XdrPublicKey, ScAddress,
    ScMap, ScMapEntry, ScSymbol, ScVal, SorobanAuthorizationEntry, Uint256, VecM, WriteXdr,
};
use zeroize::Zeroizing;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";
const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";
const TESTNET_FRIENDBOT_URL: &str = "https://friendbot.stellar.org";
const CHAIN_ID: &str = "stellar:testnet";
const TIMEOUT_SECS: u64 = 90;
const FEE_STROOPS: u32 = 1_000_000;

/// OpenZeppelin WebAuthn verifier v0.7.1 wasm hash — the only `VERIFIER_ALLOWLIST` entry.
///
/// SHA-256 verified at `vendor/oz-webauthn-verifier/v0.7.1/PROVENANCE.md`.
const OZ_WEBAUTHN_VERIFIER_HASH: [u8; 32] = [
    0x67, 0x80, 0x06, 0x90, 0x9b, 0x50, 0xc6, 0xc3, 0x65, 0xc0, 0x33, 0xf1, 0x37, 0x19, 0x7e, 0x91,
    0x0d, 0x83, 0x96, 0xa2, 0xc6, 0x8e, 0x92, 0x81, 0x32, 0x7a, 0x2e, 0xd7, 0xdb, 0xf4, 0xb2, 0x7a,
];

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Generates a fresh ed25519 keypair and returns
/// `(g_strkey, DeployerKeypair::SecretEnv { signer })`.
///
/// Uses an ephemeral in-memory key so Friendbot can fund a net-new address.
/// A shared well-known deployer is NOT used here because Friendbot
/// returns HTTP 400 for already-funded accounts.
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
            var_name: "d-migrate-verifier-deployer".to_owned(),
            signer,
        },
    )
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

/// Funds a G-strkey via testnet Friendbot and waits for ledger settlement.
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
    // Short wait for ledger settlement.
    tokio::time::sleep(Duration::from_secs(3)).await;
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

/// Encodes `SimpleThresholdAccountParams { threshold: N }` as a Soroban ScVal.
///
/// `#[contracttype]` struct encoding: `ScVal::Map(ScMap([("threshold", U32(N))]))`
/// per soroban-sdk-macros `derive_type_struct` — each named field maps to
/// `ScMapEntry { key: ScVal::Symbol(field_name), val: <field IntoVal> }`,
/// entries sorted by key.
///
/// Encodes the threshold-policy `SimpleThresholdAccountParams { threshold: u32 }`
/// single-field struct.
fn encode_simple_threshold_params(threshold: u32) -> ScVal {
    let entry = ScMapEntry {
        key: ScVal::Symbol(ScSymbol::try_from("threshold").expect("'threshold' fits ScSymbol")),
        val: ScVal::U32(threshold),
    };
    let map: VecM<ScMapEntry> = vec![entry].try_into().expect("single-entry VecM");
    ScVal::Map(Some(ScMap(map)))
}

/// Deploys the vendored OZ threshold-policy WASM to testnet.
///
/// Uses the two-tx split pattern from `deploy_webauthn_verifier_body` at
/// `deployment/deploy_webauthn_verifier.rs:395-530`:
/// upload-if-absent + `CreateContractV2`.
///
/// Returns the deployed threshold-policy C-strkey.
///
/// # Construction notes
///
/// - `CreateContractV2` with `ContractIdPreimageFromAddress`.
/// - Deterministic salt: `SHA256("oz-threshold-policy-v0.7.1-" || network_passphrase)` —
///   pins the salt to the WASM version and network, matching the same convention used in
///   `deploy_webauthn_verifier_body`.
/// - No `__constructor` args for the threshold-policy contract: only `enforce`,
///   `install`, `uninstall`, `get_threshold`, `set_threshold` are exported.
async fn deploy_threshold_policy_wasm(
    deployer_g: &str,
    signer: &(dyn Signer + Send + Sync),
) -> String {
    // Compute wasm SHA-256 for LedgerKey construction and idempotency check.
    let wasm_hash_bytes: [u8; 32] = Sha256::digest(THRESHOLD_POLICY_WASM).into();

    // Deterministic salt: SHA256("oz-threshold-policy-v0.7.1-" || network_passphrase).
    let salt_input = format!("oz-threshold-policy-v0.7.1-{TESTNET_PASSPHRASE}");
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

/// Decoded fields from an on-chain `ContextRule`, produced by
/// [`fetch_rule_decoded`].
///
/// Carries all six components needed to assert post-migration invariants:
///
/// - `external_signers` — every `Signer::External(Address, Bytes)` found in
///   the rule's `signers` list, returned as [`DecodedOnChainSigner::External`]
///   variants from the shared decoder.
/// - `external_signer_ids` — on-chain `signer_ids` entries that correspond
///   positionally to `external_signers` (extracted during the single walk of
///   `signers_scvals`; positionally aligned with `signer_ids`).
/// - `delegated_signers` — every `Signer::Delegated(Address)` found in the
///   rule's `signers` list, returned as `ScAddress` values.
/// - `delegated_signer_ids` — on-chain `signer_ids` entries that correspond
///   positionally to `delegated_signers` (same walk; positionally aligned with
///   `signer_ids`).
/// - `policies` — every contract address in the rule's `policies` list,
///   returned as `ScAddress` values (`Vec<Address>` in the on-chain wire format).
/// - `policy_ids` — positionally aligned with `policies`; the on-chain
///   `Vec<u32>` IDs. Carried so a post-migration regression that re-ordered or
///   re-numbered policy IDs is caught by an independent assertion.
struct DecodedContextRule {
    /// External signers in the on-chain rule.
    ///
    /// Each entry is a `DecodedOnChainSigner::External` variant from the
    /// shared [`decode_signer_scval_full`] decoder.  Carries full `key_data`
    /// (not truncated) so callers can assert byte-exact equality against the
    /// original `pubkey_data`.
    ///
    /// Decodes the on-chain `Signer::External(Address, Bytes)` contracttype.
    external_signers: Vec<DecodedOnChainSigner>,
    /// On-chain `signer_ids` entries for each External signer (positionally
    /// aligned with `external_signers`).
    ///
    /// Decodes `ContextRule.signer_ids: Vec<u32>`.
    /// Extracted during the single signer walk by pairing the signer's position
    /// in `signers_scvals` with the corresponding `signer_ids[i]` entry.
    external_signer_ids: Vec<u32>,
    /// Delegated signer addresses in the on-chain rule.
    ///
    /// Decodes the on-chain `Signer::Delegated(Address)` contracttype.
    delegated_signers: Vec<ScAddress>,
    /// On-chain `signer_ids` entries for each Delegated signer (positionally
    /// aligned with `delegated_signers`).
    ///
    /// Decodes `ContextRule.signer_ids: Vec<u32>`.
    /// A regression where `remove_signer`/`add_signer` renumber `signer_ids`
    /// (or a future change re-orders the vec on add) could flip the Delegated
    /// signer's id without changing its address — invisible to the address-level
    /// `delegated_signers` assertion alone.
    delegated_signer_ids: Vec<u32>,
    /// Policy contract addresses in the on-chain rule.
    ///
    /// Decodes `ContextRule.policies: Vec<Address>`.
    policies: Vec<ScAddress>,
    /// Policy IDs in the on-chain rule (positionally aligned with `policies`).
    ///
    /// Decodes `ContextRule.policy_ids: Vec<u32>`.
    /// `MigrationPlan::submit` only edits the signer list; a regression that
    /// re-ordered or re-numbered `policy_ids` would not be caught by the
    /// `policies` address-equality assertion alone.
    policy_ids: Vec<u32>,
}

/// Fetches the on-chain `ContextRule` for `rule_id` via a read-only
/// `simulateTransaction` call and returns all decoded components:
/// External signers + their signer IDs, Delegated signer addresses + their
/// signer IDs, policy addresses, and policy IDs.
///
/// Works at any point in time — pre-migration, post-migration, or outside
/// any migration context.  When used to capture a baseline before
/// `plan.submit(...)`, the returned `delegated_signer_ids` serve as the
/// reference for the signer-id invariant assertion.
///
/// # Call-site preconditions
///
/// The smart account at `smart_account_addr` must be deployed on the
/// configured testnet RPC endpoint and `rule_id` must reference an installed
/// `ContextRule`; otherwise simulation fails and the helper panics per the
/// `# Panics` section.  RPC reachability at `TESTNET_RPC_URL` is also assumed.
///
/// # Implementation
///
/// Uses `stellar_rpc_client::Client::simulate_transaction` directly (the same
/// approach as the production `simulate_read_only` free function at
/// `crates/stellar-agent-smart-account/src/managers/signers.rs:2912`).
/// Builds a `get_context_rule(rule_id)` invocation using
/// [`SIMULATE_SENTINEL_G`] as the source account (sequence = "0", no
/// `fetch_account` round-trip).
///
/// # ScVal decoding
///
/// `get_context_rule` returns a `ContextRule` `#[contracttype]` struct encoded
/// as `ScVal::Map` with Symbol-keyed entries sorted lexicographically:
/// `context_type`, `id`, `name`, `policies`, `policy_ids`, `signer_ids`,
/// `signers`, `valid_until`.
///
/// ## `signers` and `signer_ids` field decoding
///
/// The `signers` field is `ScVal::Vec(Some([signer_0, signer_1, ...]))`.
/// The `signer_ids` field is `ScVal::Vec(Some([id_0, id_1, ...]))`, positionally
/// aligned with `signers` per `ContextRule.signer_ids: Vec<u32>`.
///
/// Both vecs are decoded in the map-scan pass first, then walked in parallel
/// so each signer at index `i` is paired with `signer_ids[i]`.  Per-signer
/// ScVal decoding delegates to the shared [`decode_signer_scval_full`] helper
/// in `crates/stellar-agent-smart-account/src/managers/signers.rs`, which
/// walks the on-chain `Signer` contracttype:
/// - `Delegated(Address)` → `DecodedOnChainSigner::Delegated { pubkey, signer_address }`
/// - `External(Address, Bytes)` → `DecodedOnChainSigner::External { verifier_strkey, verifier_address, key_data }`
///
/// The paired id is routed to `delegated_signer_ids` or `external_signer_ids`
/// matching the decoded variant.  The production `decode_signer_scval` projects
/// `key_data` to a 16-byte truncation at its call site; this helper retains the
/// full blob so the post-migration test can assert byte-exact equality against
/// the original `pubkey_data`.  Both share a single decode path: a future
/// change to the `Signer` enum encoding requires updating only
/// `decode_signer_scval_full`.
///
/// ## `policies` field decoding
///
/// The `policies` field is `ScVal::Vec(Some([addr_0, addr_1, ...]))`.
/// Each element is an `ScVal::Address` — `ContextRule.policies: Vec<Address>`.
///
/// # Panics
///
/// Panics (via `expect`/`panic!`) on any simulation or decode error — this is
/// an integration-test helper; panics produce clear failure messages.
async fn fetch_rule_decoded(smart_account_addr: &ScAddress, rule_id: u32) -> DecodedContextRule {
    // ── Build the get_context_rule invoke ─────────────────────────────────────

    let function_name =
        ScSymbol::try_from("get_context_rule").expect("'get_context_rule' must fit ScSymbol");

    let args: VecM<ScVal> = vec![ScVal::U32(rule_id)]
        .try_into()
        .expect("single-arg VecM must succeed");

    let invoke = InvokeContractArgs {
        contract_address: smart_account_addr.clone(),
        function_name,
        args,
    };

    let op = Operation {
        source_account: None,
        body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
            host_function: HostFunction::InvokeContract(invoke),
            auth: VecM::default(),
        }),
    };

    // Use SIMULATE_SENTINEL_G (sequence=0) — no account fetch needed for
    // read-only simulation.
    let mut source_account = BaselibAccount::new(SIMULATE_SENTINEL_G, "0")
        .expect("SIMULATE_SENTINEL_G BaselibAccount::new must succeed");

    let mut tx_builder = TransactionBuilder::new(&mut source_account, TESTNET_PASSPHRASE, None);
    tx_builder.fee(FEE_STROOPS);
    tx_builder.add_operation(op);
    let tx_for_simulate = tx_builder.build_for_simulation();

    let server = Client::new(TESTNET_RPC_URL).expect("Server::new must succeed");

    let sim_envelope = tx_for_simulate
        .to_envelope()
        .expect("to_envelope must succeed");

    let sim = server
        .simulate_transaction_envelope(&sim_envelope, None)
        .await
        .expect("get_context_rule simulation must succeed");

    assert!(
        sim.error.is_none(),
        "get_context_rule simulation must not return an error; got: {:?}",
        sim.error
    );

    let return_val = sim
        .results()
        .expect("results decode")
        .into_iter()
        .next()
        .expect("get_context_rule simulation must return a result entry")
        .xdr;

    // ── Decode ScVal::Map → signers + policies fields ─────────────────────────

    let map = match return_val {
        ScVal::Map(Some(m)) => m,
        other => panic!("get_context_rule must return ScVal::Map; got {other:?}"),
    };

    let mut signers_scvals: Vec<ScVal> = Vec::new();
    let mut signer_ids_scvals: Vec<ScVal> = Vec::new();
    let mut policies_scvals: Vec<ScVal> = Vec::new();
    let mut policy_ids_scvals: Vec<ScVal> = Vec::new();

    // ScMap entries are key-ordered (sorted lexicographically by ScSymbol); we
    // match by name, not by index, so ordering is irrelevant + future OZ field
    // additions / reorderings are non-breaking.
    for entry in map.iter() {
        let key_str = match &entry.key {
            ScVal::Symbol(s) => std::str::from_utf8(s.as_slice()).unwrap_or("").to_owned(),
            _ => continue,
        };
        match key_str.as_str() {
            "signers" => {
                if let ScVal::Vec(Some(v)) = &entry.val {
                    signers_scvals = v.iter().cloned().collect();
                }
            }
            "signer_ids" => {
                // `ContextRule.signer_ids: Vec<u32>`, positionally aligned with
                // `signers`.
                if let ScVal::Vec(Some(v)) = &entry.val {
                    signer_ids_scvals = v.iter().cloned().collect();
                }
            }
            "policies" => {
                if let ScVal::Vec(Some(v)) = &entry.val {
                    policies_scvals = v.iter().cloned().collect();
                }
            }
            "policy_ids" => {
                if let ScVal::Vec(Some(v)) = &entry.val {
                    policy_ids_scvals = v.iter().cloned().collect();
                }
            }
            _ => {}
        }
    }

    // Decode the raw `signer_ids` vec to `Vec<u32>` before walking signers,
    // so the per-signer index lookup below is O(1).
    //
    // `ContextRule.signer_ids: Vec<u32>`.
    let signer_ids_decoded: Vec<u32> = signer_ids_scvals
        .iter()
        .map(|sv| match sv {
            ScVal::U32(id) => *id,
            other => panic!("signer_ids entry must be ScVal::U32; got {other:?}"),
        })
        .collect();

    assert_eq!(
        signer_ids_decoded.len(),
        signers_scvals.len(),
        "signer_ids and signers vecs must have equal length; \
         got signer_ids={} signers={}",
        signer_ids_decoded.len(),
        signers_scvals.len(),
    );

    // ── Walk signers, collect External and Delegated variants ─────────────────
    //
    // Per-signer ScVal decoding delegates to the shared `decode_signer_scval_full`
    // helper in `crates/stellar-agent-smart-account/src/managers/signers.rs`
    // (gated under `feature = "test-helpers"`).  The production
    // `decode_signer_scval` projects the result to `SignerPubkey` at the call
    // site; this helper retains the full `key_data` for byte-exact assertions.

    let mut external: Vec<DecodedOnChainSigner> = Vec::new();
    let mut external_ids: Vec<u32> = Vec::new();
    let mut delegated: Vec<ScAddress> = Vec::new();
    let mut delegated_ids: Vec<u32> = Vec::new();

    for (sv, &signer_id) in signers_scvals.iter().zip(signer_ids_decoded.iter()) {
        let Some(decoded_signer) = decode_signer_scval_full(sv) else {
            // Unknown or malformed variant — skip silently (future OZ extension).
            continue;
        };
        match decoded_signer {
            DecodedOnChainSigner::Delegated {
                ref signer_address, ..
            } => {
                delegated.push(signer_address.clone());
                delegated_ids.push(signer_id);
            }
            DecodedOnChainSigner::External { .. } => {
                external_ids.push(signer_id);
                external.push(decoded_signer);
            }
        }
    }

    // ── Decode policies field → Vec<ScAddress> ────────────────────────────────
    //
    // `ContextRule.policies: Vec<Address>`.
    // Each element is encoded as `ScVal::Address`.

    let mut policies: Vec<ScAddress> = Vec::new();
    for sv in &policies_scvals {
        if let ScVal::Address(addr) = sv {
            policies.push(addr.clone());
        } else {
            panic!("policies entry must be ScVal::Address; got {sv:?}");
        }
    }

    // ── Decode policy_ids field → Vec<u32> ────────────────────────────────────
    //
    // `ContextRule.policy_ids: Vec<u32>`.
    // Each element is encoded as `ScVal::U32`.

    let mut policy_ids: Vec<u32> = Vec::new();
    for sv in &policy_ids_scvals {
        if let ScVal::U32(id) = sv {
            policy_ids.push(*id);
        } else {
            panic!("policy_ids entry must be ScVal::U32; got {sv:?}");
        }
    }

    DecodedContextRule {
        external_signers: external,
        external_signer_ids: external_ids,
        delegated_signers: delegated,
        delegated_signer_ids: delegated_ids,
        policies,
        policy_ids,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Dry-run plan construction against live testnet
// ─────────────────────────────────────────────────────────────────────────────

/// `MigrationPlanner::build` passes all three pre-flight gates and returns
/// an empty plan for a fresh smart account with no External signers.
///
/// # Pre-flight gates exercised
///
/// 1. Destination hash in `VERIFIER_ALLOWLIST` → passes (OZ v0.7.1 Audited entry).
/// 2. Destination audit status `Audited` → passes.
/// 3. Destination contract immutable → passes (OZ vendored WASM has no Admin key).
///
/// # Dry-run invariant
///
/// `MigrationPlanner::build` issues ONLY read-only `simulateTransaction` calls
/// (`get_context_rules_count`, `get_context_rule`, `getLedgerEntries` for WASM hash
/// + contract instance). No write transactions are submitted.
///
#[tokio::test(flavor = "multi_thread")]
async fn d1_migrate_verifier_dry_run_constructs_plan_without_submitting() {
    // ── 1. Deploy a fresh smart account on testnet ────────────────────────────

    // Generate ephemeral signer + deployer keypairs.  Both are funded via
    // Friendbot (fresh addresses guaranteed by OsRng, so Friendbot returns 200).
    let signer_signing_key = SigningKey::generate(&mut OsRng);
    let signer_pk_bytes: [u8; 32] = signer_signing_key.verifying_key().to_bytes();
    let signer_g = format!("{}", stellar_strkey::ed25519::PublicKey(signer_pk_bytes));
    fund_via_friendbot(&signer_g).await;

    let (deployer_g, deployer_kp) = fresh_deployer();
    fund_via_friendbot(&deployer_g).await;

    let mut salt = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut OsRng, &mut salt);

    let deploy_result = deploy_smart_account(
        DeploymentArgs {
            deployer: deployer_kp,
            initial_signer: signer_g.clone(),
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
    .expect("deploy_smart_account must succeed on testnet");

    let smart_account_strkey = deploy_result.smart_account;
    let smart_account_addr: ScAddress = parse_c_strkey_to_smart_account(&smart_account_strkey)
        .expect("parse deployed smart account C-strkey");

    eprintln!("smart account deployed at {}", &smart_account_strkey[..8]);

    // ── 2. Deploy the OZ WebAuthn verifier (destination for plan) ─────────────

    // Use a fresh ephemeral deployer for the WebAuthn verifier deployment too.
    let (wa_deployer_g, wa_deployer_kp) = fresh_deployer();
    fund_via_friendbot(&wa_deployer_g).await;

    let (_d1_registry_dir, d1_registry_path) = fresh_verifier_registry_tempdir("D-1");

    let wa_deploy_args = WebAuthnVerifierDeployArgs {
        deployer: wa_deployer_kp,
        network_passphrase: TESTNET_PASSPHRASE.to_owned(),
        rpc_url: TESTNET_RPC_URL.to_owned(),
        timeout: Duration::from_secs(TIMEOUT_SECS),
        fee: ResolvedFeePerOp {
            stroops: FEE_STROOPS,
            percentile_label: "explicit".to_owned(),
        },
        dry_run: false,
        registry_path_override: Some(d1_registry_path),
    };
    let wa_deploy_result = deploy_webauthn_verifier(wa_deploy_args, None)
        .await
        .expect("deploy_webauthn_verifier must succeed");
    let to_verifier_strkey = wa_deploy_result.verifier_address;
    let to_verifier_addr: ScAddress =
        parse_c_strkey_to_smart_account(&to_verifier_strkey).expect("parse verifier C-strkey");

    eprintln!(
        "WebAuthn verifier at {} (status={})",
        &to_verifier_strkey[..8],
        wa_deploy_result.status,
    );

    // ── 3. Build SignersManager ───────────────────────────────────────────────

    let tmp_dir = tempfile::tempdir().expect("tempdir");
    let audit_log_path = tmp_dir.path().join("audit.jsonl");
    let audit_writer = Arc::new(Mutex::new(
        AuditWriter::open(audit_log_path.clone(), None).expect("AuditWriter::open"),
    ));
    let manager = SignersManager::new(SignersManagerConfig::new(
        TESTNET_RPC_URL.to_owned(),
        TESTNET_RPC_URL.to_owned(),
        audit_writer,
        audit_log_path,
        TESTNET_PASSPHRASE.to_owned(),
        "d1-test".to_owned(),
        Duration::from_secs(TIMEOUT_SECS),
        CHAIN_ID.to_owned(),
    ))
    .expect("SignersManager::new must succeed");

    // ── 4. Execute the dry-run plan ───────────────────────────────────────────

    let request_id = uuid::Uuid::new_v4().to_string();
    let planner = MigrationPlanner::new(&manager);

    let plan = planner
        .build(
            smart_account_addr,
            OZ_WEBAUTHN_VERIFIER_HASH,
            to_verifier_addr,
            &request_id,
        )
        .await
        .expect(
            "MigrationPlanner::build must succeed: destination is Audited + Immutable in VERIFIER_ALLOWLIST",
        );

    // ── 5. Assertions ─────────────────────────────────────────────────────────

    // Assertion 1: from_hash preserved.
    assert_eq!(
        plan.from_hash, OZ_WEBAUTHN_VERIFIER_HASH,
        "plan.from_hash must match the caller-supplied from_hash"
    );

    // Assertion 2: to_hash found in VERIFIER_ALLOWLIST (pre-flight 1 passed).
    let in_allowlist = VERIFIER_ALLOWLIST
        .iter()
        .any(|e| e.wasm_hash == plan.to_hash);
    assert!(
        in_allowlist,
        "plan.to_hash ({}) must be in VERIFIER_ALLOWLIST",
        hex::encode(plan.to_hash)
    );

    // Assertion 3: destination_audit_status is Audited (pre-flight 2 passed).
    assert!(
        matches!(
            plan.destination_audit_status,
            VerifierAuditStatus::Audited { .. }
        ),
        "destination_audit_status must be Audited; got: {:?}",
        plan.destination_audit_status
    );

    // Assertion 4: affected_rules is empty (fresh account has only a Delegated signer).
    assert!(
        plan.affected_rules.is_empty(),
        "fresh account bootstrap rule has a Delegated signer, not External; \
         affected_rules must be empty"
    );

    // Assertion 5: total_transaction_count == 0 (no affected rules).
    assert_eq!(
        plan.total_transaction_count(),
        0,
        "total_transaction_count must be 0 for empty affected_rules"
    );

    // Assertion 6: warnings is empty (0 txs → no inter-tx hazard; threshold is > 2, not >= 2).
    assert!(
        plan.warnings.is_empty(),
        "warnings must be empty for a fresh account with 0 affected rules; got: {:?}",
        plan.warnings
    );

    eprintln!(
        "d1 PASS: plan built — affected_rules={}, total_tx={}, \
         from_first8={}, to_first8={}, destination_audit_status={}",
        plan.affected_rules.len(),
        plan.total_transaction_count(),
        plan.from_hash_first8(),
        plan.to_hash_first8(),
        plan.destination_audit_status,
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Dry-run plan with one External signer
// ─────────────────────────────────────────────────────────────────────────────

/// `MigrationPlanner::build` identifies one affected context rule containing
/// one External signer referencing the OZ WebAuthn verifier.
///
/// Deploys a fresh smart account, then installs a new context rule (rule_id=1)
/// with one `External` signer pointing to a freshly-deployed OZ WebAuthn verifier
/// contract and a threshold-policy (required for `refresh_signer_baseline`).
/// Calls `MigrationPlanner::build` with
/// `from_hash = OZ_WEBAUTHN_VERIFIER_HASH` and asserts that the planner detects
/// the new rule as having one affected External signer.
///
/// The bootstrap rule (rule_id=0) uses only a `Delegated` signer and is therefore
/// excluded from `affected_rules`.
///
/// # Setup summary
///
/// 1. Deploy fresh smart account with bootstrap signer S1.
/// 2. Fund and deploy OZ WebAuthn verifier (this becomes the External verifier address).
/// 3. Deploy threshold-policy WASM (required so `refresh_signer_baseline` can route
///    through `identify_threshold_policy`).
/// 4. Install a new context rule via `ContextRuleManager::install_rule` with:
///    - One `ContextRuleSignerInput::External { verifier: verifier_addr, pubkey_data }`.
///    - One `ContextRulePolicy` with the threshold-policy contract.
/// 5. Establish baseline for the new rule via `SignersManager::refresh_signer_baseline`.
/// 6. Run `MigrationPlanner::build` — planner scans all rules, fetches each rule via
///    `get_context_rule`, reads each External signer's verifier wasm hash, and
///    adds matching signers to `affected_rules`.
///
/// # Assertions
///
/// 1. `plan.affected_rules.len() == 1` — the new rule has one affected External signer.
/// 2. `plan.affected_rules[0].signer_steps.len() == 1`.
/// 3. `plan.total_transaction_count() == 2` (1 rule × 1 signer × 2 steps).
/// 4. `remove_host_function` invokes `remove_signer` on the smart-account address.
/// 5. `add_host_function` invokes `add_signer` on the smart-account address.
/// 6. `plan.warnings.is_empty()` (total_tx == 2, threshold for warning is > 2).
/// 7. No transaction is submitted to testnet (dry-run invariant).
///
#[tokio::test(flavor = "multi_thread")]
async fn d2_migrate_verifier_dry_run_identifies_one_external_signer() {
    // ── 1. Deploy a fresh smart account on testnet ────────────────────────────

    let (signer_g, signer_box) = fresh_signer();
    fund_via_friendbot(&signer_g).await;

    let (deployer_g, deployer_kp) = fresh_deployer();
    fund_via_friendbot(&deployer_g).await;

    let mut salt = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut OsRng, &mut salt);

    let deploy_result = deploy_smart_account(
        DeploymentArgs {
            deployer: deployer_kp,
            initial_signer: signer_g.clone(),
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
    .expect("deploy_smart_account must succeed on testnet");

    let smart_account_strkey = deploy_result.smart_account.clone();
    let smart_account_addr: ScAddress = parse_c_strkey_to_smart_account(&smart_account_strkey)
        .expect("parse deployed smart account C-strkey");

    eprintln!("smart account deployed at {}", &smart_account_strkey[..8]);

    // ── 2. Deploy the OZ WebAuthn verifier (External signer verifier) ─────────

    let (wa_deployer_g, wa_deployer_kp) = fresh_deployer();
    fund_via_friendbot(&wa_deployer_g).await;

    let (_d2_registry_dir, d2_registry_path) = fresh_verifier_registry_tempdir("D-2");

    let wa_deploy_result = deploy_webauthn_verifier(
        WebAuthnVerifierDeployArgs {
            deployer: wa_deployer_kp,
            network_passphrase: TESTNET_PASSPHRASE.to_owned(),
            rpc_url: TESTNET_RPC_URL.to_owned(),
            timeout: Duration::from_secs(TIMEOUT_SECS),
            fee: ResolvedFeePerOp {
                stroops: FEE_STROOPS,
                percentile_label: "explicit".to_owned(),
            },
            dry_run: false,
            registry_path_override: Some(d2_registry_path),
        },
        None,
    )
    .await
    .expect("deploy_webauthn_verifier must succeed");

    let verifier_strkey = wa_deploy_result.verifier_address.clone();
    let verifier_addr: ScAddress =
        parse_c_strkey_to_smart_account(&verifier_strkey).expect("parse verifier C-strkey");

    eprintln!(
        "verifier deployed at {} (status={})",
        &verifier_strkey[..8],
        wa_deploy_result.status,
    );

    // ── 3. Deploy threshold-policy WASM ──────────────────────────────────────
    //
    // Required so `refresh_signer_baseline` and `verify_signer_set_against_chain`
    // can route threshold reading through `identify_threshold_policy`.
    // The bootstrap rule (rule_id=0) has no threshold-policy;
    // the new rule installed in step 4 uses the threshold-policy explicitly.

    let (tp_deployer_g, tp_deployer_signer) = fresh_signer();
    fund_via_friendbot(&tp_deployer_g).await;

    let policy_strkey =
        deploy_threshold_policy_wasm(&tp_deployer_g, tp_deployer_signer.as_ref()).await;
    let policy_addr =
        parse_c_strkey_to_smart_account(&policy_strkey).expect("threshold-policy C-strkey");

    eprintln!("threshold-policy at {}", &policy_strkey[..8]);

    // ── 4. Install a new rule with one External signer + threshold policy ─────
    //
    // `ContextRuleSignerInput::External { verifier, pubkey_data }` encodes the
    // on-chain `Signer::External(Address, Bytes)` contracttype:
    //   ScVal::Vec([Symbol("External"), Address(verifier), Bytes(pubkey_data)])
    //
    // Bootstrap rule (rule_id=0) authorises the install; signer_g signs the auth-entry.

    // The OZ WebAuthn verifier's `batch_canonicalize_key` calls `extract_from_bytes(0..65)`
    // and panics with `KeyDataInvalid` (error 3119) if key_data is shorter than 65 bytes.
    // A synthetic 65-byte blob is valid for install purposes; actual P-256 curve membership
    // is not checked at install time.
    let mut pubkey_data = [0u8; 65];
    rand_core::RngCore::fill_bytes(&mut OsRng, &mut pubkey_data);

    let threshold_params = encode_simple_threshold_params(1); // 1-of-2 rule

    // Defensive: install with Delegated co-signer + External so a future refactor
    // that calls `plan.submit()` does not return contract error 3016 (UnauthorizedSigner)
    // because the operator G-key is not in the rule's signer set.
    let operator_signer_address = parse_g_strkey_to_signer_address(&signer_g)
        .expect("operator G-strkey must parse to ScAddress");

    let definition = ContextRuleDefinition::new(
        ContextRuleType::Default,
        "d2-external-rule".to_owned(),
        None,
        vec![
            ContextRuleSignerInput::Delegated {
                address: operator_signer_address,
            },
            ContextRuleSignerInput::External {
                verifier: verifier_addr.clone(),
                pubkey_data: pubkey_data.to_vec(),
            },
        ],
        vec![ContextRulePolicy::new(policy_addr, threshold_params)],
    );

    let rule_manager = fresh_rule_manager();
    let install_out = rule_manager
        .install_rule(
            smart_account_addr.clone(),
            definition,
            vec![ContextRuleId::new(0)], // bootstrap rule authorises the install
            signer_box.as_ref(),
            None,
            uuid::Uuid::new_v4().to_string(),
            false, // accept_mutable_verifier
            false, // accept_unknown_verifier
        )
        .await
        .expect("install_rule must succeed");
    let new_rule_id = install_out.rule_id;

    eprintln!("External signer rule installed as rule_id={new_rule_id}");

    // ── 5. Build SignersManager + establish baseline for new rule ────────────
    //
    // `refresh_signer_baseline` requires a threshold-policy in the rule's
    // `policies` list.  The new rule has the threshold-policy installed, so
    // this call succeeds.  The bootstrap rule (rule_id=0) is NOT used here
    // because it has no threshold-policy.

    let tmp_dir = tempfile::tempdir().expect("tempdir");
    let audit_log_path = tmp_dir.path().join("audit.jsonl");
    let audit_writer = Arc::new(Mutex::new(
        AuditWriter::open(audit_log_path.clone(), None).expect("AuditWriter::open"),
    ));
    let manager = SignersManager::new(SignersManagerConfig::new(
        TESTNET_RPC_URL.to_owned(),
        TESTNET_RPC_URL.to_owned(),
        audit_writer,
        audit_log_path,
        TESTNET_PASSPHRASE.to_owned(),
        "d2-test".to_owned(),
        Duration::from_secs(TIMEOUT_SECS),
        CHAIN_ID.to_owned(),
    ))
    .expect("SignersManager::new must succeed");

    let baseline_rid = uuid::Uuid::new_v4().to_string();
    let baseline = manager
        .refresh_signer_baseline(
            smart_account_addr.clone(),
            new_rule_id,
            Some(&signer_g),
            baseline_rid,
        )
        .await
        .expect("refresh_signer_baseline must succeed on newly installed rule");

    eprintln!(
        "baseline established — signer_count={}, threshold={}",
        baseline.signer_count, baseline.threshold
    );

    assert_eq!(
        baseline.signer_count, 2,
        "new rule must have signer_count=2 (Delegated co-signer + External); got {}",
        baseline.signer_count
    );
    assert_eq!(
        baseline.threshold, 1,
        "new rule must have threshold=1 (1-of-2); got {}",
        baseline.threshold
    );

    // ── 6. Execute the dry-run plan ───────────────────────────────────────────

    let planner = MigrationPlanner::new(&manager);
    let plan_request_id = uuid::Uuid::new_v4().to_string();

    let plan = planner
        .build(
            smart_account_addr.clone(),
            OZ_WEBAUTHN_VERIFIER_HASH,
            verifier_addr.clone(),
            &plan_request_id,
        )
        .await
        .expect(
            "MigrationPlanner::build must succeed: verifier is Audited + Immutable in VERIFIER_ALLOWLIST",
        );

    // ── 7. Assertions ─────────────────────────────────────────────────────────

    // Assertion 1: exactly one affected rule (new rule has one External signer).
    assert_eq!(
        plan.affected_rules.len(),
        1,
        "expected 1 affected rule (new rule has External signer with OZ verifier); got {}",
        plan.affected_rules.len()
    );

    let rule = &plan.affected_rules[0];

    // Assertion 2: new rule with one signer step.
    assert_eq!(
        rule.rule_id, new_rule_id,
        "affected rule must be rule_id {new_rule_id}"
    );
    assert_eq!(
        rule.signer_steps.len(),
        1,
        "rule {new_rule_id} must have exactly 1 signer step (one External signer installed)"
    );

    // Assertion 3: total transaction count == 2 (1 rule × 1 signer × 2 ops).
    assert_eq!(
        plan.total_transaction_count(),
        2,
        "total_transaction_count must be 2 for 1 rule × 1 affected External signer"
    );

    // Assertion 4: remove_host_function targets the smart account.
    let step = &rule.signer_steps[0];
    match &step.remove_host_function {
        stellar_xdr::HostFunction::InvokeContract(args) => {
            assert_eq!(
                args.function_name.as_slice(),
                b"remove_signer",
                "remove_host_function must call 'remove_signer'"
            );
            assert_eq!(
                args.contract_address, smart_account_addr,
                "remove_host_function must target the smart account"
            );
        }
        _ => panic!("remove_host_function must be InvokeContract"),
    }

    // Assertion 5: add_host_function targets the smart account.
    match &step.add_host_function {
        stellar_xdr::HostFunction::InvokeContract(args) => {
            assert_eq!(
                args.function_name.as_slice(),
                b"add_signer",
                "add_host_function must call 'add_signer'"
            );
            assert_eq!(
                args.contract_address, smart_account_addr,
                "add_host_function must target the smart account"
            );
        }
        _ => panic!("add_host_function must be InvokeContract"),
    }

    // Assertion 6: warnings is empty (total_tx == 2; threshold for warning is > 2).
    assert!(
        plan.warnings.is_empty(),
        "warnings must be empty for a 2-tx plan (threshold is > 2, not >= 2); got: {:?}",
        plan.warnings
    );

    eprintln!(
        "d2 PASS: plan built — affected_rules={}, total_tx={}, \
         from_first8={}, to_first8={}, rule_id={}, signer_steps={}",
        plan.affected_rules.len(),
        plan.total_transaction_count(),
        plan.from_hash_first8(),
        plan.to_hash_first8(),
        rule.rule_id,
        rule.signer_steps.len(),
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// On-chain verifier migration submit end-to-end
// ─────────────────────────────────────────────────────────────────────────────

/// `MigrationPlan::submit` migrates one External signer from verifier-A to
/// verifier-B on testnet, completing the two-transaction (remove + add) pair
/// and emitting one `SaVerifierMigrated` audit row.
///
/// # Test strategy (same-wasm degenerate)
///
/// Both verifier-A and verifier-B are deployments of the same OZ WebAuthn WASM
/// (same hash, different contract addresses derived from different deployer/salt
/// combinations). This exercises the full on-chain submission path without
/// requiring a second audited WASM.
///
/// Migration steps:
/// 1. Deploy fresh smart account with bootstrap signer S1.
/// 2. Deploy verifier-A (OZ WebAuthn v0.7.1, first deployer).
/// 3. Deploy verifier-B (OZ WebAuthn v0.7.1, second deployer — different address).
/// 4. Deploy threshold-policy WASM (required so `refresh_signer_baseline` routes
///    through `identify_threshold_policy`).
/// 5. Install a context rule with one External signer pointing to verifier-A.
/// 6. Establish baseline via `SignersManager::refresh_signer_baseline`.
/// 7. Build migration plan via `MigrationPlanner::build`.
/// 8. Submit migration via `MigrationPlan::submit`.
///
/// # Assertions
///
/// 1. `result.failed_step_index.is_none()` — submit completed without error.
/// 2. `result.successful_steps.len() == 1` — exactly one signer-step pair.
/// 3. `result.total_steps_attempted == 1`.
/// 4. Audit log contains exactly 1 `SaVerifierMigrated` row with
///    `tool == "sa.verifier_migrated"`.
/// 5. Post-migration on-chain `ContextRule` contains exactly 1 External signer.
/// 6. That External signer's `verifier` address equals `verifier_b_addr`.
/// 7. That External signer's `pubkey_data` is preserved (byte-exact).
/// 8. `policies` list contains exactly 1 entry equal to `policy_addr`.
/// 9. `delegated_signers` list contains exactly 1 entry equal to `operator_signer_address`.
/// 10. `policy_ids` contains exactly 1 entry (positional invariant with `policies`).
/// 11. Delegated signer's on-chain `signer_id` (from `ContextRule.signer_ids`) is
///     equal pre- and post-migration.
///
/// # On-chain behavior cross-check
///
/// - `remove_signer` clears the `External` signer with verifier-A address.
/// - `add_signer` installs a new `External` signer with verifier-B address
///   and same key data.
/// - `ContextRule.policies: Vec<Address>` — policies list must be unchanged
///   after migration (assertion 8).
/// - `Signer::Delegated(Address)` — Delegated co-signer address must be
///   unchanged after migration (assertion 9).
/// - `ContextRule.signer_ids: Vec<u32>` — positionally aligned with `signers`;
///   Delegated signer's id must be unchanged after migration (assertion 11).
/// - CAP-46 invariant: each of the two calls is a separate `InvokeHostFunctionOp`
///   in its own transaction.
#[tokio::test(flavor = "multi_thread")]
async fn d3_migrate_verifier_on_chain_submit() {
    // ── 1. Deploy a fresh smart account on testnet ────────────────────────────

    let (signer_g, signer_box) = fresh_signer();
    fund_via_friendbot(&signer_g).await;

    let (deployer_g, deployer_kp) = fresh_deployer();
    fund_via_friendbot(&deployer_g).await;

    let mut salt = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut OsRng, &mut salt);

    let deploy_result = deploy_smart_account(
        DeploymentArgs {
            deployer: deployer_kp,
            initial_signer: signer_g.clone(),
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
    .expect("deploy_smart_account must succeed on testnet");

    let smart_account_strkey = deploy_result.smart_account.clone();
    let smart_account_addr: ScAddress = parse_c_strkey_to_smart_account(&smart_account_strkey)
        .expect("parse deployed smart account C-strkey");

    eprintln!("smart account at {}", &smart_account_strkey[..8]);

    // ── 2. Deploy verifier-A (OZ WebAuthn WASM, first deployer) ─────────────

    let (va_deployer_g, va_deployer_kp) = fresh_deployer();
    fund_via_friendbot(&va_deployer_g).await;

    // This test deploys two verifier contracts under different deployers; without
    // separate registries the per-network idempotency shortcut at
    // `deploy_webauthn_verifier.rs:308-337` would return verifier-A's address
    // for the verifier-B call, defeating the `assert_ne!` below.
    let (_va_registry_dir, va_registry_path) = fresh_verifier_registry_tempdir("D-3 verifier-A");

    let va_result = deploy_webauthn_verifier(
        WebAuthnVerifierDeployArgs {
            deployer: va_deployer_kp,
            network_passphrase: TESTNET_PASSPHRASE.to_owned(),
            rpc_url: TESTNET_RPC_URL.to_owned(),
            timeout: Duration::from_secs(TIMEOUT_SECS),
            fee: ResolvedFeePerOp {
                stroops: FEE_STROOPS,
                percentile_label: "explicit".to_owned(),
            },
            dry_run: false,
            registry_path_override: Some(va_registry_path),
        },
        None,
    )
    .await
    .expect("deploy_webauthn_verifier (verifier-A) must succeed");

    let verifier_a_strkey = va_result.verifier_address.clone();
    let verifier_a_addr: ScAddress =
        parse_c_strkey_to_smart_account(&verifier_a_strkey).expect("parse verifier-A C-strkey");

    eprintln!(
        "verifier-A at {} (status={})",
        &verifier_a_strkey[..8],
        va_result.status,
    );

    // ── 3. Deploy verifier-B (same WASM, different deployer → different address) ──

    let (vb_deployer_g, vb_deployer_kp) = fresh_deployer();
    fund_via_friendbot(&vb_deployer_g).await;

    let (_vb_registry_dir, vb_registry_path) = fresh_verifier_registry_tempdir("D-3 verifier-B");

    let vb_result = deploy_webauthn_verifier(
        WebAuthnVerifierDeployArgs {
            deployer: vb_deployer_kp,
            network_passphrase: TESTNET_PASSPHRASE.to_owned(),
            rpc_url: TESTNET_RPC_URL.to_owned(),
            timeout: Duration::from_secs(TIMEOUT_SECS),
            fee: ResolvedFeePerOp {
                stroops: FEE_STROOPS,
                percentile_label: "explicit".to_owned(),
            },
            dry_run: false,
            registry_path_override: Some(vb_registry_path),
        },
        None,
    )
    .await
    .expect("deploy_webauthn_verifier (verifier-B) must succeed");

    let verifier_b_strkey = vb_result.verifier_address.clone();
    let verifier_b_addr: ScAddress =
        parse_c_strkey_to_smart_account(&verifier_b_strkey).expect("parse verifier-B C-strkey");

    assert_ne!(
        verifier_a_strkey, verifier_b_strkey,
        "verifier-A and verifier-B must have different addresses (different deployers)"
    );

    eprintln!(
        "verifier-B at {} (status={})",
        &verifier_b_strkey[..8],
        vb_result.status,
    );

    // ── 4. Deploy threshold-policy WASM ──────────────────────────────────────

    let (tp_deployer_g, tp_deployer_signer) = fresh_signer();
    fund_via_friendbot(&tp_deployer_g).await;

    let policy_strkey =
        deploy_threshold_policy_wasm(&tp_deployer_g, tp_deployer_signer.as_ref()).await;
    let policy_addr =
        parse_c_strkey_to_smart_account(&policy_strkey).expect("threshold-policy C-strkey");

    eprintln!("threshold-policy at {}", &policy_strkey[..8]);

    // ── 5. Install context rule with External(verifier-A) + Delegated(operator) ──
    //
    // Rule shape: 1-of-2 (threshold=1).  The Delegated co-signer (operator G-key)
    // is required so `plan.submit(signer_box, ...)` can authorise the
    // `remove_signer` and `add_signer` migration transactions on rule_id=N
    // without a WebAuthn passkey ceremony.  OZ smart-account `__check_auth`
    // requires that the signer used be present in the rule being modified;
    // an External-only rule would return contract error 3016 (UnauthorizedSigner)
    // on every migration step because the operator G-key is not in
    // the rule's signer set.  Production operators typically configure
    // a Delegated co-signer alongside External signers for exactly this
    // recovery / migration scenario, so this rule shape is also more
    // realistic than External-only.  The migration semantics are unaffected:
    // `MigrationPlan` only iterates External signers matching `from_hash`,
    // so the Delegated co-signer is left in place across the migration.
    //
    // 65-byte synthetic pubkey blob valid for OZ WebAuthn key install.
    let mut pubkey_data = [0u8; 65];
    rand_core::RngCore::fill_bytes(&mut OsRng, &mut pubkey_data);

    let threshold_params = encode_simple_threshold_params(1); // 1-of-2 rule

    let operator_signer_address = parse_g_strkey_to_signer_address(&signer_g)
        .expect("operator G-strkey must parse to ScAddress");

    let definition = ContextRuleDefinition::new(
        ContextRuleType::Default,
        "d3-external-rule".to_owned(),
        None,
        vec![
            ContextRuleSignerInput::Delegated {
                // Clone so `operator_signer_address` remains available for
                // the post-migration Delegated address preservation assertion.
                address: operator_signer_address.clone(),
            },
            ContextRuleSignerInput::External {
                verifier: verifier_a_addr.clone(),
                pubkey_data: pubkey_data.to_vec(),
            },
        ],
        vec![ContextRulePolicy::new(
            policy_addr.clone(),
            threshold_params,
        )],
    );

    let rule_manager = fresh_rule_manager();
    let install_out = rule_manager
        .install_rule(
            smart_account_addr.clone(),
            definition,
            vec![ContextRuleId::new(0)],
            signer_box.as_ref(),
            None,
            uuid::Uuid::new_v4().to_string(),
            false, // accept_mutable_verifier
            false, // accept_unknown_verifier
        )
        .await
        .expect("install_rule must succeed on testnet");
    let new_rule_id = install_out.rule_id;

    eprintln!("External signer rule installed as rule_id={new_rule_id}");

    // ── 6. Build SignersManager + establish baseline for new rule ────────────

    let tmp_dir = tempfile::tempdir().expect("tempdir");
    let audit_log_path = tmp_dir.path().join("audit.jsonl");
    let audit_writer = Arc::new(Mutex::new(
        AuditWriter::open(audit_log_path.clone(), None).expect("AuditWriter::open"),
    ));
    let manager = SignersManager::new(SignersManagerConfig::new(
        TESTNET_RPC_URL.to_owned(),
        TESTNET_RPC_URL.to_owned(),
        audit_writer,
        audit_log_path.clone(),
        TESTNET_PASSPHRASE.to_owned(),
        "d3-test".to_owned(),
        Duration::from_secs(TIMEOUT_SECS),
        CHAIN_ID.to_owned(),
    ))
    .expect("SignersManager::new must succeed");

    let baseline_rid = uuid::Uuid::new_v4().to_string();
    let baseline = manager
        .refresh_signer_baseline(
            smart_account_addr.clone(),
            new_rule_id,
            Some(&signer_g),
            baseline_rid,
        )
        .await
        .expect("refresh_signer_baseline must succeed");

    eprintln!(
        "baseline established — signer_count={}, threshold={}",
        baseline.signer_count, baseline.threshold
    );

    assert_eq!(
        baseline.signer_count, 2,
        "new rule must have signer_count=2 (Delegated co-signer + External); got {}",
        baseline.signer_count
    );
    assert_eq!(
        baseline.threshold, 1,
        "new rule must have threshold=1 (1-of-2); got {}",
        baseline.threshold
    );

    // ── 7. Build migration plan ───────────────────────────────────────────────

    let planner = MigrationPlanner::new(&manager);
    let plan_request_id = uuid::Uuid::new_v4().to_string();

    let plan = planner
        .build(
            smart_account_addr.clone(),
            OZ_WEBAUTHN_VERIFIER_HASH,
            verifier_b_addr.clone(),
            &plan_request_id,
        )
        .await
        .expect("MigrationPlanner::build must succeed — verifier-B is Audited + Immutable");

    // Pre-submit assertions.
    assert_eq!(
        plan.affected_rules.len(),
        1,
        "expected 1 affected rule before submit; got {}",
        plan.affected_rules.len()
    );
    assert_eq!(
        plan.total_transaction_count(),
        2,
        "expected 2 transactions (1 rule × 1 signer × 2 ops); got {}",
        plan.total_transaction_count()
    );

    eprintln!(
        "plan built — affected_rules={}, total_tx={}, rule_id={}",
        plan.affected_rules.len(),
        plan.total_transaction_count(),
        plan.affected_rules[0].rule_id,
    );

    // ── 7b. Capture pre-migration decoded state ───────────────────────────────
    //
    // Assertion 11 requires comparing the Delegated signer's on-chain
    // `signer_id` before and after the remove+add pair to verify the id is
    // invariant across the migration.  Capture the decoded rule now, before
    // `plan.submit(...)` mutates the on-chain state.
    //
    // `ContextRule.signer_ids: Vec<u32>` is positionally aligned with `signers`;
    // a regression where `remove_signer`/`add_signer` renumber `signer_ids`
    // could flip the Delegated signer's id without changing its address —
    // invisible to the address-level assertion 9 alone.
    let pre_migration = fetch_rule_decoded(&smart_account_addr, new_rule_id).await;

    assert_eq!(
        pre_migration.delegated_signers.len(),
        1,
        "pre-migration ContextRule must contain exactly 1 Delegated signer; \
         got {} — rule shape changed before submit",
        pre_migration.delegated_signers.len()
    );
    assert_eq!(
        pre_migration.delegated_signer_ids.len(),
        1,
        "pre-migration delegated_signer_ids must have len=1 \
         (positionally aligned with delegated_signers); got {}",
        pre_migration.delegated_signer_ids.len()
    );

    eprintln!(
        "pre-migration baseline — delegated_signer_id={}",
        pre_migration.delegated_signer_ids[0],
    );

    // ── 8. Submit migration ───────────────────────────────────────────────────

    let submit_request_id = uuid::Uuid::new_v4().to_string();
    let result = plan
        .submit(signer_box.as_ref(), &manager, &submit_request_id)
        .await;

    // ── 9. Assertions ─────────────────────────────────────────────────────────

    // Assertion 1: no failure.
    assert!(
        result.failed_step_index.is_none(),
        "failed_step_index must be None (submit must complete without error); \
         got {:?}, error: {:?}",
        result.failed_step_index,
        result.failed_step_error,
    );

    // Assertion 2: exactly one successful signer step.
    assert_eq!(
        result.successful_steps.len(),
        1,
        "successful_steps must have 1 entry (1 rule × 1 signer); got {}",
        result.successful_steps.len()
    );

    // Assertion 3: total_steps_attempted == 1.
    assert_eq!(
        result.total_steps_attempted, 1,
        "total_steps_attempted must be 1; got {}",
        result.total_steps_attempted
    );

    let step = &result.successful_steps[0];
    assert_eq!(step.rule_id, new_rule_id, "step.rule_id mismatch");
    assert_eq!(
        step.remove_tx_hash.len(),
        64,
        "remove_tx_hash must be a 64-char transaction hash"
    );
    assert!(
        step.remove_tx_hash.chars().all(|c| c.is_ascii_hexdigit()),
        "remove_tx_hash must be hex"
    );
    assert_eq!(
        step.add_tx_hash.len(),
        64,
        "add_tx_hash must be a 64-char transaction hash"
    );
    assert!(
        step.add_tx_hash.chars().all(|c| c.is_ascii_hexdigit()),
        "add_tx_hash must be hex"
    );

    eprintln!(
        "submit complete — successful_steps={}, failed_step_index={:?}",
        result.successful_steps.len(),
        result.failed_step_index,
    );

    // ── 9a. Post-submit signer-set verification ──────────────────────────────
    //
    // Re-fetch the rule's signer set and assert the Delegated co-signer is
    // preserved, the threshold is unchanged, and the signer-count remained 2.
    // Catches a regression where remove_signer succeeds but add_signer writes
    // the wrong signer; real tx hashes only prove confirmation, not signer-set
    // correctness.
    let post_baseline_rid = uuid::Uuid::new_v4().to_string();
    let post_baseline = manager
        .refresh_signer_baseline(
            smart_account_addr.clone(),
            new_rule_id,
            Some(&signer_g),
            post_baseline_rid,
        )
        .await
        .expect("post-submit refresh_signer_baseline must succeed");

    assert_eq!(
        post_baseline.signer_count, 2,
        "post-migration signer_count must remain 2 (Delegated invariant + new External); got {}",
        post_baseline.signer_count
    );
    assert_eq!(
        post_baseline.threshold, 1,
        "post-migration threshold must remain 1; got {}",
        post_baseline.threshold
    );

    eprintln!(
        "post-migration baseline — signer_count={}, threshold={}",
        post_baseline.signer_count, post_baseline.threshold,
    );

    // Assertion 4: audit log contains exactly 1 SaVerifierMigrated row.
    //
    // The `AuditWriter` holds the file lock for its lifetime; the manager's
    // writer Arc is the only writer. We read the JSONL file directly (read-only
    // access does not require the exclusive lock).
    //
    // `tmp_dir` is still alive (holds the directory); the file exists.
    {
        use std::io::BufRead as _;
        let file = std::fs::File::open(&audit_log_path).expect("audit.jsonl must be readable");
        let reader = std::io::BufReader::new(file);
        let entries: Vec<serde_json::Value> = reader
            .lines()
            .map(|l| {
                let line = l.expect("audit line must be valid UTF-8");
                serde_json::from_str(&line).expect("audit line must be valid JSON")
            })
            .collect();

        // Count SaVerifierMigrated rows.
        // `refresh_signer_baseline` emits SaSignerSetBaselined, not SaVerifierMigrated.
        // Only the submit step (one per successful signer-step pair) emits SaVerifierMigrated.
        let migrated_rows: Vec<&serde_json::Value> = entries
            .iter()
            .filter(|e| {
                e.get("tool")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("")
                    == "sa.verifier_migrated"
            })
            .collect();

        assert_eq!(
            migrated_rows.len(),
            1,
            "audit log must contain exactly 1 SaVerifierMigrated row; \
             found {} in {} total entries",
            migrated_rows.len(),
            entries.len()
        );
        let expected_redacted_add_hash = stellar_agent_network::redact_tx_hash(&step.add_tx_hash);
        assert_eq!(
            migrated_rows[0]
                .get("tx_hash_redacted")
                .and_then(serde_json::Value::as_str),
            Some(expected_redacted_add_hash.as_str()),
            "SaVerifierMigrated tx_hash_redacted must match redacted add_signer tx hash"
        );

        eprintln!(
            "audit log OK — {} SaVerifierMigrated row(s) in {} total entries",
            migrated_rows.len(),
            entries.len()
        );
    }

    // ── Post-migration on-chain ContextRule decode + invariant verification ──────
    //
    // Fetch the on-chain `ContextRule` for `rule_id = new_rule_id` and assert:
    //   5. Exactly one External signer is present.
    //   6. That External signer's `verifier` address equals `verifier_b_addr`.
    //   7. That External signer's `pubkey_data` is preserved (equals original).
    //   8. `policies` list is preserved: exactly 1 entry == `policy_addr`.
    //   9. `delegated_signers` list is preserved: exactly 1 entry == `operator_signer_address`.
    //
    // Assertions 5–7: catch a wrong-destination regression where
    // `MigrationPlan::submit` builds the `add_signer` host-function with
    // `verifier_a_addr` instead of `verifier_b_addr`.
    //
    // Assertion 8: `MigrationPlan::submit` only removes + adds External
    // signers; it must NOT touch the rule's `policies` list.  A regression in
    // `add_signer` that accidentally re-wrote `policies` would pass assertions 5–7.
    //
    // Assertion 9: catch a regression where `add_signer` silently replaced
    // the Delegated signer with a different Delegated address.  Such a regression
    // would still produce `signer_count == 2` + `threshold == 1` (from the
    // `refresh_signer_baseline` assertions above) and could pass the External
    // address check (assertion 6), making it invisible without an explicit address
    // equality check on the Delegated signer.
    //
    // Assertion 11 compares `decoded` with `pre_migration` (captured in step 7b above).
    let decoded = fetch_rule_decoded(&smart_account_addr, new_rule_id).await;

    // Assertion 5: exactly one External signer in the post-migration rule.
    // Cardinality also verified for `external_signer_ids` (positionally aligned with
    // `external_signers` per `ContextRule.signer_ids: Vec<u32>`).
    assert_eq!(
        decoded.external_signers.len(),
        1,
        "post-migration ContextRule must contain exactly 1 External signer; \
         got {} (verifier migration may have left 0 or added a duplicate)",
        decoded.external_signers.len()
    );
    assert_eq!(
        decoded.external_signer_ids.len(),
        decoded.external_signers.len(),
        "external_signer_ids must have same length as external_signers \
         (positional alignment invariant); got ids={} signers={}",
        decoded.external_signer_ids.len(),
        decoded.external_signers.len()
    );

    // Destructure the single External signer so assertions 6 and 7 can access
    // the typed fields directly.
    let (ext_verifier_strkey, ext_key_data) = match &decoded.external_signers[0] {
        DecodedOnChainSigner::External {
            verifier_strkey,
            key_data,
            ..
        } => (verifier_strkey.as_str(), key_data.as_slice()),
        DecodedOnChainSigner::Delegated { .. } => panic!(
            "external_signers[0] must be External variant; \
             got Delegated — signer-set decode routing bug"
        ),
    };

    // Assertion 6: that External signer's verifier address equals verifier_b_addr.
    //
    // The expected C-strkey is `verifier_b_strkey` (derived from vb_result).
    // A wrong-destination regression would produce `verifier_a_strkey` here instead.
    assert_eq!(
        ext_verifier_strkey,
        verifier_b_strkey,
        "post-migration External signer must reference verifier-B ({}); \
         got verifier={} — add_signer wrote the wrong verifier address",
        &verifier_b_strkey[..8],
        &ext_verifier_strkey[..8],
    );

    // Assertion 7: pubkey_data is preserved across the migration.
    //
    // `pubkey_data` is the 65-byte synthetic blob constructed at step 5.
    // `MigrationPlan::submit` must carry the original key data into the
    // `add_signer` call unchanged.
    assert_eq!(
        ext_key_data,
        pubkey_data.as_ref(),
        "External signer pubkey_data must be preserved across migration; \
         expected first8={}, got first8={}",
        hex::encode(&pubkey_data[..8]),
        hex::encode(&ext_key_data[..8]),
    );

    // Assertion 8: policies list preservation.
    //
    // `MigrationPlan::submit` only modifies the `signers` list (remove + add External
    // signer).  The `policies` list must be unchanged: still exactly 1 entry pointing
    // at the threshold-policy deployed in step 4.
    //
    // `ContextRule.policies: Vec<Address>`.
    assert_eq!(
        decoded.policies.len(),
        1,
        "post-migration ContextRule must contain exactly 1 policy \
         (policies list must be preserved by MigrationPlan::submit); got {}",
        decoded.policies.len()
    );
    assert_eq!(
        decoded.policies[0], policy_addr,
        "post-migration policy[0] must equal the threshold-policy address \
         installed in step 4 — MigrationPlan::submit must not touch the policies list",
    );

    // Assertion 9: Delegated signer address preservation.
    //
    // The Delegated(operator) co-signer installed at step 5 must be present and
    // unchanged after migration.  MigrationPlan only iterates External signers
    // matching `from_hash`; the Delegated signer is left in place.
    // A regression replacing the Delegated address with a different key would
    // still produce `signer_count == 2` in the baseline check above but fail here.
    //
    // `Signer::Delegated(Address)`.
    assert_eq!(
        decoded.delegated_signers.len(),
        1,
        "post-migration ContextRule must contain exactly 1 Delegated signer; \
         got {} — MigrationPlan::submit must not remove or duplicate the Delegated co-signer",
        decoded.delegated_signers.len()
    );
    assert_eq!(
        decoded.delegated_signers[0], operator_signer_address,
        "post-migration Delegated signer must equal the operator address \
         (signer_g) installed in step 5 — add_signer must not replace the Delegated address",
    );

    // Assertion 10: policy_ids preservation.
    //
    // `MigrationPlan::submit` must not touch `policy_ids` (positionally aligned
    // with `policies`).  A regression that re-numbered or re-ordered policy_ids
    // would not be caught by assertion 8's address-equality check alone.
    //
    // `ContextRule.policy_ids: Vec<u32>`.
    assert_eq!(
        decoded.policy_ids.len(),
        1,
        "post-migration ContextRule must contain exactly 1 policy_id \
         (positional invariant with policies); got {}",
        decoded.policy_ids.len()
    );

    // Assertion 11: Delegated signer-id invariance across the
    // remove+add pair.
    //
    // `ContextRule.signer_ids: Vec<u32>` is positionally aligned with `signers`.
    // `MigrationPlan` only adds/removes External signers; the Delegated
    // co-signer's entry in `signer_ids` must be unchanged.
    //
    // A regression where `remove_signer` / `add_signer` renumber `signer_ids`
    // (or a future change re-orders the vec on add) would flip the Delegated
    // signer's id without changing its address — invisible to assertion 9 alone.
    //
    // Cardinality safety-net: `decoded.delegated_signer_ids.len()` must equal
    // `decoded.delegated_signers.len()` (enforced inside
    // `fetch_rule_decoded` via the signer_ids/signers length
    // assert).  If this post-migration cardinality check fires, it means the
    // Delegated signer was duplicated or removed in the signer_ids list even
    // though the address-level assertion 9 passed.
    assert_eq!(
        decoded.delegated_signer_ids.len(),
        1,
        "post-migration delegated_signer_ids must have len=1 \
         (positionally aligned with delegated_signers); got {} — \
         signer_ids cardinality changed across migration",
        decoded.delegated_signer_ids.len()
    );
    assert_eq!(
        decoded.delegated_signer_ids[0], pre_migration.delegated_signer_ids[0],
        "Delegated signer on-chain id must be invariant across the migration \
         (pre={} post={}) — remove_signer/add_signer must not renumber signer_ids \
         for the unchanged Delegated signer",
        pre_migration.delegated_signer_ids[0], decoded.delegated_signer_ids[0],
    );

    eprintln!(
        "post-migration on-chain ContextRule verified — \
         external_signers={}, verifier_first8={}, pubkey_data_first8={}, \
         delegated_signers={} delegated_first8={}, delegated_signer_id={}, \
         policies={} policy_first8={}, policy_ids={}",
        decoded.external_signers.len(),
        &ext_verifier_strkey[..8],
        hex::encode(&ext_key_data[..8]),
        decoded.delegated_signers.len(),
        &signer_g[..8],
        decoded.delegated_signer_ids[0],
        decoded.policies.len(),
        &policy_strkey[..8],
        decoded.policy_ids.len(),
    );

    eprintln!(
        "d3 PASS: migration complete — verifier address changed from {} to {}; \
         remove+add pair confirmed on-chain; 1 SaVerifierMigrated audit row; \
         on-chain ContextRule verifier-B address + Delegated invariant + \
         policies preservation + Delegated signer-id invariance verified",
        &verifier_a_strkey[..8],
        &verifier_b_strkey[..8],
    );
}
