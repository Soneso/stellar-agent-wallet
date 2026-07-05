//! Testnet acceptance test for bounded agent delegation (Package A).
//!
//! Exercises the full operator-delegates-to-agent flow against testnet:
//!
//! 1. Deploy the OZ ed25519 verifier and the OZ spending-limit policy (both
//!    per-network singletons) via `deployment::deploy_ed25519_verifier` /
//!    `deployment::deploy_spending_limit_policy`.
//! 2. Target = the native-asset SEP-41 SAC on testnet; the bounded operation
//!    is `transfer(smart_account, recipient, amount)` — the only invocation
//!    shape the OZ spending-limit policy's `enforce` accepts
//!    (`spending_limit.rs:222-292`, SHA `a9c4216`).
//! 3. Deploy a fresh smart account and install a `CallContract(token)`
//!    context rule whose only signer is a fresh External-Ed25519 key (the
//!    recommended agent-signer shape — see [`Ed25519RuleSigner`]).
//! 4. Attach the spending-limit policy to that rule via the typed
//!    `add_policy` path (`build_spending_limit_install_param`).
//! 5. Drive an agent-signed transfer under the limit through the production
//!    `submit_signed_invoke` entry point with
//!    `ed25519_rule_signer: Some(Ed25519RuleSigner { .. })` — the same call
//!    shape a real agent-facing caller uses. Assert on-chain confirmation and
//!    an exact recipient balance delta.
//! 6. Drive a second transfer that pushes cumulative spend over the limit;
//!    assert the failure carries the policy's `SpendingLimitExceeded` (3221)
//!    discriminant specifically, not `NotAllowed` (3223).
//! 7. Drive a self-call on the smart account itself (a different contract
//!    context than the rule's token scope) under the same rule; assert the
//!    on-chain rejection is a `CallContract` scope mismatch
//!    (`UnvalidatedContext`, 3002) — the same signer is refused outside the
//!    contract the rule scopes it to.
//! 8. Install a `CreateContract(wasm_hash)` rule (proves the Leg-1 encoder
//!    round-trips through real on-chain storage) and exercise its auth
//!    context simulate-only: a genuine `CreateContractV2` deploy-by-the-
//!    smart-account host function is simulated (no sign/submit) and the
//!    RPC-derived auth requirement's wasm hash is asserted against the
//!    installed rule's `wasm_hash`.
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
//!   --test smart_account_delegation_testnet_acceptance
//! ```
//!
//! # Reference cross-check
//!
//! - OZ `packages/accounts/src/smart_account/storage.rs:272-324` (SHA
//!   `a9c4216`) — `get_validated_context_by_id`: context-type mismatch
//!   (`UnvalidatedContext`, 3002) is checked before policy enforcement, so a
//!   scope-violating call fails for the scope reason specifically.
//! - OZ `packages/accounts/src/policies/spending_limit.rs:222-292,376-381`
//!   (SHA `a9c4216`) — `enforce` (only SEP-41 `transfer` accepted;
//!   `SpendingLimitExceeded` on over-cap) and `install`
//!   (`OnlyCallContractAllowed` / `InvalidLimitOrPeriod`).

#![cfg(feature = "testnet-integration")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics are acceptable in integration tests"
)]

mod common;

use std::error::Error;
use std::path::Path;
use std::time::Duration;

use common::{TESTNET_FRIENDBOT_URL, TESTNET_PASSPHRASE, TESTNET_RPC_URL, fund_via_friendbot};
use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};
use stellar_agent_core::StellarAmount;
use stellar_agent_core::smart_account::rule_id::ContextRuleId;
use stellar_agent_network::submit::{
    SubmissionResult, SubmissionSignerKind, submit_transaction_and_wait,
};
use stellar_agent_network::{
    Signer, SoftwareSigningKey, StellarRpcClient, fetch_account,
    signing::envelope_signing::attach_signature,
};
use stellar_agent_smart_account::deployment::{
    DeployerKeypair, DeploymentArgs, Ed25519VerifierDeployArgs,
    ResolvedFeePerOp as DeployResolvedFeePerOp, SpendingLimitPolicyDeployArgs,
    deploy_ed25519_verifier, deploy_smart_account, deploy_spending_limit_policy,
};
use stellar_agent_smart_account::ed25519_verifier::ED25519_VERIFIER_WASM_SHA256;
use stellar_agent_smart_account::error::SaError;
use stellar_agent_smart_account::managers::rules::{
    ContextRuleDefinition, ContextRuleManager, ContextRuleManagerConfig, ContextRuleSignerInput,
    RuleContext, decode_context_type_from_scval, parse_c_strkey_to_smart_account,
    parse_g_strkey_to_signer_address,
};
use stellar_agent_smart_account::spending_limit_policy::build_spending_limit_install_param;
use stellar_agent_smart_account::submit::{
    Ed25519RuleSigner, SubmitInvokeArgs, submit_signed_invoke,
};
use stellar_agent_test_support::testnet_helpers::fund_sac_balance;
use stellar_baselib::account::{Account as BaselibAccount, AccountBehavior};
use stellar_baselib::transaction::{Transaction, TransactionBehavior};
use stellar_baselib::transaction_builder::{TransactionBuilder, TransactionBuilderBehavior};
use stellar_rpc_client::Client;
use stellar_xdr::{
    ContractExecutable, ContractIdPreimage, ContractIdPreimageFromAddress, CreateContractArgsV2,
    Hash, HostFunction, Int128Parts, InvokeContractArgs, InvokeHostFunctionOp, Operation,
    OperationBody, ScAddress, ScString, ScSymbol, ScVal, SorobanAuthorizedFunction,
    SorobanCredentials, StringM, Uint256, VecM,
};
use uuid::Uuid;
use zeroize::Zeroizing;

const CHAIN_ID: &str = "stellar:testnet";
const TIMEOUT_SECS: u64 = 120;

/// Known-answer XLM SAC on testnet (SEP-41 native-asset contract).
///
/// Source: `soroswap-core/public/tokens.json:testnet:assets[0]:contract`;
/// independently verified via `stellar contract id asset --asset native
/// --network testnet`. Also a known-answer test in `stellar-agent-dex/src/sac.rs`.
const XLM_SAC_TESTNET: &str = "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC";

/// Spending limit installed on the CallContract rule (5 XLM, in stroops).
const SPENDING_LIMIT_STROOPS: i128 = 50_000_000;

/// Rolling-window length for the spending limit, in ledgers.
const SPENDING_PERIOD_LEDGERS: u32 = 1_000;

/// First transfer amount (1 XLM): strictly under the limit.
const FIRST_TRANSFER_STROOPS: i128 = 10_000_000;

/// Second transfer amount (4.5 XLM): pushes cumulative spend
/// (`FIRST_TRANSFER_STROOPS + SECOND_TRANSFER_STROOPS = 55_000_000`) over the
/// 50_000_000-stroop limit.
const SECOND_TRANSFER_STROOPS: i128 = 45_000_000;

/// XLM funded into the smart account's SAC balance (7 XLM): must exceed
/// `FIRST_TRANSFER_STROOPS + SECOND_TRANSFER_STROOPS` (55_000_000) with
/// margin, so the step-6 over-limit transfer is refused for the intended
/// `SpendingLimitExceeded` reason rather than for insufficient SAC balance
/// (the SAC's own balance check and the spending-limit policy's `enforce`
/// both run during the recording-auth simulate; an under-funded account
/// would surface the wrong failure first).
const SMART_ACCOUNT_FUND_STROOPS: i128 = 70_000_000;

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
        var_name: "testnet-delegation-acceptance-generated".to_owned(),
        signer,
    };
    (g_strkey, deployer)
}

/// Constructs a `ContextRuleManager` against testnet.
fn fresh_rule_manager() -> ContextRuleManager {
    ContextRuleManager::new(ContextRuleManagerConfig::new(
        TESTNET_RPC_URL.to_owned(),
        TESTNET_PASSPHRASE.to_owned(),
        Duration::from_secs(TIMEOUT_SECS),
        CHAIN_ID.to_owned(),
    ))
    .expect("ContextRuleManager construction must succeed")
}

/// Deploys a fresh smart account whose constructor-rule signer is
/// `initial_signer_g`. Returns the deployed C-strkey.
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
async fn deploy_verifier_and_policy(registry_path: &Path) -> (String, String) {
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

    // A second Friendbot-funded deployer for the policy deploy — keeps the
    // two deploys independent rather than threading a re-fetched sequence
    // number through this helper.
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

/// Builds the SEP-41 `transfer(from, to, amount)` `HostFunction::InvokeContract`
/// invocation for a SAC — the ONLY shape the OZ spending-limit policy's
/// `enforce` accepts (`spending_limit.rs:222-292`, SHA `a9c4216`).
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
    HostFunction::InvokeContract(InvokeContractArgs {
        contract_address: sac,
        function_name,
        args,
    })
}

/// Builds the `InvokeContractArgs` for [`fund_sac_balance`]'s SAC-transfer
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
) -> Result<InvokeContractArgs, SaError> {
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
async fn fetch_testnet_sequence(account_id: String) -> Result<i64, Box<dyn Error + Send + Sync>> {
    let rpc_client = StellarRpcClient::new(TESTNET_RPC_URL)?;
    let account = fetch_account(&rpc_client, &account_id, &[]).await?;
    Ok(account.sequence_number)
}

/// Signs an unsigned envelope XDR with a raw ed25519 seed.
async fn sign_testnet_envelope(
    unsigned_xdr: String,
    funder_seed: Zeroizing<[u8; 32]>,
    network_passphrase: String,
) -> Result<String, Box<dyn Error + Send + Sync>> {
    let signer = SoftwareSigningKey::new_from_zeroizing(funder_seed);
    Ok(attach_signature(&unsigned_xdr, &signer, &network_passphrase).await?)
}

/// Submits a signed envelope XDR and waits for confirmation.
async fn submit_testnet_signed_xdr(
    signed_xdr: String,
) -> Result<SubmissionResult, Box<dyn Error + Send + Sync>> {
    let rpc_client = StellarRpcClient::new(TESTNET_RPC_URL)?;
    Ok(submit_transaction_and_wait(
        &rpc_client,
        &signed_xdr,
        Duration::from_secs(TIMEOUT_SECS),
        TESTNET_PASSPHRASE,
        Some(SubmissionSignerKind::Software),
    )
    .await?)
}

/// Returns the classic native (XLM) balance of `g_strkey`, in exact stroops.
///
/// Reads the ledger-derived `AccountView.balances` (not Horizon); native SAC
/// balance for a G-account IS the classic XLM balance.
async fn xlm_stroops_balance(g_strkey: &str) -> i64 {
    let rpc_client = StellarRpcClient::new(TESTNET_RPC_URL).expect("testnet RPC URL must be valid");
    let account = fetch_account(&rpc_client, g_strkey, &[])
        .await
        .expect("fetch_account must succeed");
    let native = account
        .balances
        .iter()
        .find(|b| b.asset.asset_type == "native")
        .expect("account must have a native balance entry");
    StellarAmount::parse_with_unit(&format!("{} XLM", native.balance))
        .expect("native balance decimal string must parse as a StellarAmount")
        .as_stroops()
}

/// Full bounded-agent-delegation flow: deploy substrate, scope an agent
/// signer to one token contract under a spending cap, prove it can transfer
/// within budget, prove it cannot exceed the budget or step outside its
/// scope, and prove the CreateContract-rule encoder round-trips through a
/// real on-chain auth requirement.
#[tokio::test]
async fn agent_delegation_full_flow_testnet_acceptance() {
    let tmp = tempfile::tempdir().expect("tempdir must be created");
    let registry_path = tmp.path().join("networks.toml");

    // ── Step 1: deploy the ed25519 verifier + spending-limit policy ─────────
    let (verifier_address, policy_address) = deploy_verifier_and_policy(&registry_path).await;
    let verifier_sc_addr =
        parse_c_strkey_to_smart_account(&verifier_address).expect("verifier C-strkey must parse");
    let policy_sc_addr =
        parse_c_strkey_to_smart_account(&policy_address).expect("policy C-strkey must parse");
    let xlm_sac_scaddr =
        parse_c_strkey_to_smart_account(XLM_SAC_TESTNET).expect("XLM SAC C-strkey must parse");

    // ── Step 3 (part 1): deploy a fresh smart account ───────────────────────
    let (bootstrap_signer_g, bootstrap_signer_box) = fresh_signer();
    fund_via_friendbot(&bootstrap_signer_g).await;
    let smart_account_strkey = deploy_fresh_smart_account(&bootstrap_signer_g).await;
    let smart_account_sc = parse_c_strkey_to_smart_account(&smart_account_strkey)
        .expect("deployed smart-account C-strkey must parse");
    let bootstrap_signer_sc = parse_g_strkey_to_signer_address(&bootstrap_signer_g)
        .expect("bootstrap signer G-strkey must parse");

    // ── Step 3 (part 2): fresh External-Ed25519 agent signer ────────────────
    let agent_signing_key = SigningKey::generate(&mut OsRng);
    let agent_pubkey_bytes: [u8; 32] = agent_signing_key.verifying_key().to_bytes();
    let agent_seed: Zeroizing<[u8; 32]> = Zeroizing::new(agent_signing_key.to_bytes());
    let agent_signer_box: Box<dyn Signer + Send + Sync> =
        Box::new(SoftwareSigningKey::new_from_zeroizing(agent_seed));

    let manager = fresh_rule_manager();

    // ── Step 3 (part 3): install the CallContract(token) rule ───────────────
    let call_contract_definition = ContextRuleDefinition::new(
        RuleContext::CallContract {
            contract: xlm_sac_scaddr.clone(),
        },
        "delegation-agent".to_owned(), // 16 bytes; OZ MAX_NAME_SIZE = 20
        None,
        vec![ContextRuleSignerInput::External {
            verifier: verifier_sc_addr.clone(),
            pubkey_data: agent_pubkey_bytes.to_vec(),
        }],
        vec![],
    );
    let install_out = manager
        .install_rule(
            smart_account_sc.clone(),
            call_contract_definition,
            vec![ContextRuleId::new(0)], // bootstrap rule authorises the install
            bootstrap_signer_box.as_ref(),
            None,
            rid(),
            false, // accept_mutable_verifier
            false, // accept_unknown_verifier
        )
        .await
        .expect("CallContract rule install with the External-Ed25519 signer must succeed");
    let rule_id = install_out.rule_id;
    assert!(
        rule_id != 0,
        "installed rule_id must differ from the bootstrap rule; got {rule_id}"
    );

    // Round-trip proof: the on-chain rule decodes to the exact RuleContext
    // it was installed with (Leg-1 encoder end-to-end, on real chain state).
    let rule_scval = manager
        .get_rule(smart_account_sc.clone(), rule_id, &bootstrap_signer_g)
        .await
        .expect("get_rule must succeed")
        .expect("the newly installed CallContract rule must exist");
    let decoded_context =
        decode_context_type_from_scval(&rule_scval).expect("context-type decode must succeed");
    assert_eq!(
        decoded_context,
        RuleContext::CallContract {
            contract: xlm_sac_scaddr.clone()
        },
        "the on-chain rule's decoded context type must match what was installed"
    );

    // ── Step 4: attach the spending-limit policy ────────────────────────────
    let install_param =
        build_spending_limit_install_param(SPENDING_LIMIT_STROOPS, SPENDING_PERIOD_LEDGERS)
            .expect("spending-limit install param must build");
    manager
        .add_policy(
            smart_account_sc.clone(),
            rule_id,
            policy_sc_addr,
            install_param,
            vec![ContextRuleId::new(0)], // bootstrap rule authorises add_policy
            bootstrap_signer_box.as_ref(),
            None,
            rid(),
        )
        .await
        .expect("attaching the spending-limit policy must succeed on testnet");

    // ── Fund the smart account's SAC balance so step 5 can actually settle ──
    let _fund_result = fund_sac_balance(
        "delegation-acceptance",
        TESTNET_RPC_URL,
        TESTNET_PASSPHRASE,
        TESTNET_FRIENDBOT_URL,
        XLM_SAC_TESTNET,
        &smart_account_strkey,
        SMART_ACCOUNT_FUND_STROOPS,
        build_sac_transfer_invoke,
        |account_id| fetch_testnet_sequence(account_id.to_owned()),
        |unsigned_xdr, funder_seed, network_passphrase| {
            sign_testnet_envelope(unsigned_xdr, funder_seed, network_passphrase.to_owned())
        },
        submit_testnet_signed_xdr,
    )
    .await
    .unwrap_or_else(|e| panic!("SAC funding of the smart account must succeed on testnet: {e}"));

    // A funded recipient G-account (native-asset SAC destinations must exist
    // as classic accounts).
    let (recipient_g, _recipient_signer) = fresh_signer();
    fund_via_friendbot(&recipient_g).await;
    let recipient_scaddr =
        parse_g_strkey_to_signer_address(&recipient_g).expect("recipient G-strkey must parse");

    // ── Step 5: agent-signed transfer UNDER the limit — MUST succeed ────────
    let balance_before = xlm_stroops_balance(&recipient_g).await;
    let rule_ids_ok = vec![ContextRuleId::new(rule_id)];
    let ok_result = submit_signed_invoke(
        SubmitInvokeArgs::builder()
            .target_contract(XLM_SAC_TESTNET)
            .auth_address(smart_account_strkey.as_str())
            .auth_rule_ids(&rule_ids_ok)
            .host_function(transfer_host_function(
                xlm_sac_scaddr.clone(),
                smart_account_sc.clone(),
                recipient_scaddr.clone(),
                FIRST_TRANSFER_STROOPS,
            ))
            .signer(bootstrap_signer_box.as_ref())
            .ed25519_rule_signer(Ed25519RuleSigner {
                signer: agent_signer_box.as_ref(),
                verifier: verifier_sc_addr.clone(),
            })
            .primary_rpc_url(TESTNET_RPC_URL)
            .network_passphrase(TESTNET_PASSPHRASE)
            .chain_id(CHAIN_ID)
            .timeout(Duration::from_secs(TIMEOUT_SECS))
            .op_label("delegation_agent_transfer_within_limit")
            .emit_observability_logs(true)
            .build(),
    )
    .await
    .expect("agent-signed transfer under the spending limit must succeed on testnet");
    assert!(
        ok_result.ledger > 0,
        "the within-limit transfer must confirm on-chain; got ledger={}",
        ok_result.ledger
    );

    let balance_after = xlm_stroops_balance(&recipient_g).await;
    #[allow(
        clippy::cast_possible_truncation,
        reason = "stroop amounts here are far below i64::MAX; the truncation warning is inert"
    )]
    let expected_delta = FIRST_TRANSFER_STROOPS as i64;
    assert_eq!(
        balance_after - balance_before,
        expected_delta,
        "recipient balance delta must equal the transferred amount exactly"
    );

    // ── Step 6: second transfer OVER the limit — MUST fail with SpendingLimitExceeded ──
    let rule_ids_over = vec![ContextRuleId::new(rule_id)];
    let over_err = submit_signed_invoke(
        SubmitInvokeArgs::builder()
            .target_contract(XLM_SAC_TESTNET)
            .auth_address(smart_account_strkey.as_str())
            .auth_rule_ids(&rule_ids_over)
            .host_function(transfer_host_function(
                xlm_sac_scaddr.clone(),
                smart_account_sc.clone(),
                recipient_scaddr.clone(),
                SECOND_TRANSFER_STROOPS,
            ))
            .signer(bootstrap_signer_box.as_ref())
            .ed25519_rule_signer(Ed25519RuleSigner {
                signer: agent_signer_box.as_ref(),
                verifier: verifier_sc_addr.clone(),
            })
            .primary_rpc_url(TESTNET_RPC_URL)
            .network_passphrase(TESTNET_PASSPHRASE)
            .chain_id(CHAIN_ID)
            .timeout(Duration::from_secs(TIMEOUT_SECS))
            .op_label("delegation_agent_transfer_over_limit")
            .emit_observability_logs(true)
            .build(),
    )
    .await
    .expect_err("a transfer that pushes cumulative spend over the limit must fail on-chain");

    match over_err {
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

    // ── Step 7: scope proof — same signer, DIFFERENT contract — MUST fail ───
    //
    // The "different contract" is the smart account itself: a self-call
    // (`update_context_rule_name`) has `context.contract == smart_account`,
    // which does not match this rule's `CallContract(xlm_sac)` context type.
    // Using a self-call rather than a second external SAC keeps this proof
    // fully self-contained — no dependency on a second token contract's
    // deployed state or ABI on testnet, only on the smart account this test
    // already deployed and controls.
    let harmless_rename_scval = ScVal::String(ScString(
        StringM::try_from("x").expect("single-char name fits StringM"),
    ));
    let rename_args: VecM<ScVal> = vec![ScVal::U32(0), harmless_rename_scval]
        .try_into()
        .expect("2-element rename args vec fits VecM<ScVal>");
    let rename_function_name = ScSymbol::try_from("update_context_rule_name")
        .expect("\"update_context_rule_name\" fits ScSymbol (<=32 bytes)");
    let self_call_host_function = HostFunction::InvokeContract(InvokeContractArgs {
        contract_address: smart_account_sc.clone(),
        function_name: rename_function_name,
        args: rename_args,
    });

    let rule_ids_scope = vec![ContextRuleId::new(rule_id)];
    let scope_err = submit_signed_invoke(
        SubmitInvokeArgs::builder()
            .target_contract(smart_account_strkey.as_str())
            .auth_rule_ids(&rule_ids_scope)
            .host_function(self_call_host_function)
            .signer(bootstrap_signer_box.as_ref())
            .ed25519_rule_signer(Ed25519RuleSigner {
                signer: agent_signer_box.as_ref(),
                verifier: verifier_sc_addr.clone(),
            })
            .primary_rpc_url(TESTNET_RPC_URL)
            .network_passphrase(TESTNET_PASSPHRASE)
            .chain_id(CHAIN_ID)
            .timeout(Duration::from_secs(TIMEOUT_SECS))
            .op_label("delegation_agent_scope_violation")
            .emit_observability_logs(true)
            .build(),
    )
    .await
    .expect_err("a call to a contract outside the rule's CallContract scope must fail on-chain");

    match scope_err {
        SaError::DeploymentFailed {
            phase: "simulate",
            ref redacted_reason,
        } => {
            assert!(
                redacted_reason.contains("[OZ:UnvalidatedContext]"),
                "expected UnvalidatedContext (3002, CallContract scope mismatch); got: {redacted_reason}"
            );
        }
        other => panic!(
            "expected DeploymentFailed {{ phase: \"simulate\" }} carrying \
             UnvalidatedContext; got {other:?}"
        ),
    }

    // ── Step 8: CreateContract-rule variant — install + simulate-only proof ──
    let wasm_hash_bytes: [u8; 32] = {
        let bytes = hex::decode(ED25519_VERIFIER_WASM_SHA256)
            .expect("ED25519_VERIFIER_WASM_SHA256 const must be valid hex");
        bytes
            .try_into()
            .expect("ED25519_VERIFIER_WASM_SHA256 must decode to exactly 32 bytes")
    };

    let create_contract_definition = ContextRuleDefinition::new(
        RuleContext::CreateContract {
            wasm_hash: wasm_hash_bytes,
        },
        "delegation-cc".to_owned(), // 13 bytes; OZ MAX_NAME_SIZE = 20
        None,
        vec![ContextRuleSignerInput::Delegated {
            address: bootstrap_signer_sc.clone(),
        }],
        vec![],
    );
    let cc_install_out = manager
        .install_rule(
            smart_account_sc.clone(),
            create_contract_definition,
            vec![ContextRuleId::new(0)],
            bootstrap_signer_box.as_ref(),
            None,
            rid(),
            false,
            false,
        )
        .await
        .expect("CreateContract rule install must succeed on testnet");
    let cc_rule_id = cc_install_out.rule_id;
    assert!(
        cc_rule_id != 0 && cc_rule_id != rule_id,
        "CreateContract rule_id must be distinct from the bootstrap rule and the CallContract \
         rule; got {cc_rule_id}"
    );

    let cc_rule_scval = manager
        .get_rule(smart_account_sc.clone(), cc_rule_id, &bootstrap_signer_g)
        .await
        .expect("get_rule must succeed")
        .expect("the newly installed CreateContract rule must exist");
    let decoded_cc_context =
        decode_context_type_from_scval(&cc_rule_scval).expect("context-type decode must succeed");
    assert_eq!(
        decoded_cc_context,
        RuleContext::CreateContract {
            wasm_hash: wasm_hash_bytes
        },
        "the on-chain CreateContract rule's decoded wasm_hash must match what was installed"
    );

    // Exercise the auth context simulate-only: a genuine CreateContractV2
    // deploy-by-the-smart-account host function, run through simulateTransaction
    // (no sign/submit). The ed25519-verifier WASM is guaranteed already
    // on-chain from Step 1, so the footprint resolves.
    let mut cc_salt = [0u8; 32];
    OsRng.fill_bytes(&mut cc_salt);
    let create_contract_fn = HostFunction::CreateContractV2(CreateContractArgsV2 {
        contract_id_preimage: ContractIdPreimage::Address(ContractIdPreimageFromAddress {
            address: smart_account_sc.clone(),
            salt: Uint256(cc_salt),
        }),
        executable: ContractExecutable::Wasm(Hash(wasm_hash_bytes)),
        constructor_args: VecM::default(),
    });
    let create_op = Operation {
        source_account: None,
        body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
            host_function: create_contract_fn,
            auth: VecM::default(),
        }),
    };

    let rpc_server = Client::new(TESTNET_RPC_URL).expect("rpc client construction must succeed");
    let network_client =
        StellarRpcClient::new(TESTNET_RPC_URL).expect("rpc client construction must succeed");
    let fee_payer_view = fetch_account(&network_client, &bootstrap_signer_g, &[])
        .await
        .expect("fee-payer account fetch must succeed");
    let mut fee_payer_account = BaselibAccount::new(
        &bootstrap_signer_g,
        &fee_payer_view.sequence_number.to_string(),
    )
    .expect("BaselibAccount::new must succeed");
    let mut cc_tx_builder =
        TransactionBuilder::new(&mut fee_payer_account, TESTNET_PASSPHRASE, None);
    cc_tx_builder.fee(1_000_000u32);
    cc_tx_builder.add_operation(create_op);
    let cc_tx: Transaction = cc_tx_builder.build_for_simulation();
    let cc_envelope = cc_tx
        .to_envelope()
        .expect("CreateContractV2 to_envelope must succeed");
    let cc_sim = rpc_server
        .simulate_transaction_envelope(&cc_envelope, None)
        .await
        .expect("CreateContractV2 simulate_transaction_envelope must succeed (RPC reachable)");

    assert!(
        cc_sim.error.is_none(),
        "CreateContractV2 auth-context simulate must not error: {:?}",
        cc_sim.error
    );

    let cc_results = cc_sim
        .results()
        .expect("CreateContractV2 simulate results must decode");
    let cc_result = cc_results
        .into_iter()
        .next()
        .expect("CreateContractV2 simulate must return exactly one result");
    let cc_auth_entry = cc_result
        .auth
        .iter()
        .find(|e| {
            matches!(
                &e.credentials,
                SorobanCredentials::Address(c) if c.address == smart_account_sc
            )
        })
        .expect(
            "simulate must derive a smart-account-credentialled auth requirement for the \
             CreateContractV2 deploy",
        );

    match &cc_auth_entry.root_invocation.function {
        SorobanAuthorizedFunction::CreateContractV2HostFn(create_args) => {
            match create_args.executable {
                ContractExecutable::Wasm(Hash(observed_hash)) => assert_eq!(
                    observed_hash, wasm_hash_bytes,
                    "the RPC-derived auth context's wasm hash must match the installed \
                 CreateContract rule's wasm_hash"
                ),
                ContractExecutable::StellarAsset => {
                    panic!("expected ContractExecutable::Wasm for a WASM deploy; got StellarAsset")
                }
            }
        }
        other => {
            panic!("expected SorobanAuthorizedFunction::CreateContractV2HostFn; got {other:?}")
        }
    }
}
