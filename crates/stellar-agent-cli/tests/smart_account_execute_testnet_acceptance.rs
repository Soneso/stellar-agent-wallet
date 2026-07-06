//! Testnet acceptance: `stellar-agent smart-account execute`.
//!
//! Exercises the External-Ed25519-signed CallContract submission surface as a
//! real child process. Fixture setup (verifier/policy deployment, smart-account
//! deployment, SAC funding) uses the library and test-support helpers
//! directly; the surface under test — `rules create` (installing the
//! External-Ed25519 CallContract rule), `rules add-policy` (attaching the
//! spending-limit policy), and `execute` (the agent-signed transfer) — all run
//! through the release BINARY (`env!("CARGO_BIN_EXE_stellar-agent")` +
//! `std::process::Command`, the `claim_testnet_acceptance.rs` precedent; the
//! CLI crate has no `[lib]` target).
//!
//! Flow:
//! 1. Deploy the OZ ed25519 verifier + spending-limit policy (library
//!    `deployment::deploy_ed25519_verifier` / `deploy_spending_limit_policy`,
//!    written to a temp registry path never consulted by the binary — every
//!    binary invocation below passes an explicit `--verifier` / `--policy`
//!    override, so the binary's own `STELLAR_AGENT_HOME` registry is never
//!    touched).
//! 2. Deploy a fresh smart account with a Delegated bootstrap signer
//!    (library `deployment::deploy_smart_account`).
//! 3. `smart-account rules create --signer-ed25519 ... --context
//!    call-contract:<XLM_SAC>` through the BINARY: installs a CallContract
//!    rule whose only signer is a fresh External-Ed25519 agent key.
//! 4. `smart-account rules add-policy --kind spending-limit` through the
//!    BINARY: attaches the spending-limit policy to that rule.
//! 5. Fund the smart account's SAC balance (test-support library helper
//!    `fund_sac_balance`).
//! 6. `smart-account execute` a transfer UNDER the limit through the BINARY
//!    -> assert submitted + on-chain recipient balance delta.
//! 7. `smart-account execute` a transfer OVER the limit through the BINARY ->
//!    assert the CLI's error envelope carries `SpendingLimitExceeded` (3221),
//!    not `NotAllowed` (3223).
//! 8. `smart-account execute` against a different contract (the smart account
//!    itself) through the BINARY -> assert `UnvalidatedContext` (3002).
//!
//! Every step's failure fails the whole test — there is no early return that
//! would let a later assertion be silently skipped.
//!
//! Gated behind `testnet-acceptance`:
//!
//! ```text
//! cargo test -p stellar-agent-cli --features testnet-acceptance \
//!   --test smart_account_execute_testnet_acceptance
//! ```

#![cfg(feature = "testnet-acceptance")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics and unwraps are acceptable in testnet acceptance tests"
)]

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore as _};
use stellar_agent_core::StellarAmount;
use stellar_agent_network::signing::Signer;
use stellar_agent_network::signing::envelope_signing::attach_signature;
use stellar_agent_network::submit::SubmissionSignerKind;
use stellar_agent_network::{
    SoftwareSigningKey, StellarRpcClient, fetch_account, submit_transaction_and_wait,
};
use stellar_agent_smart_account::deployment::{
    DeployerKeypair, DeploymentArgs, Ed25519VerifierDeployArgs, ResolvedFeePerOp,
    SpendingLimitPolicyDeployArgs, deploy_ed25519_verifier, deploy_smart_account,
    deploy_spending_limit_policy,
};
use stellar_agent_smart_account::managers::rules::{
    parse_c_strkey_to_smart_account, parse_g_strkey_to_signer_address,
};
use stellar_agent_test_support::testnet_helpers::fund_sac_balance;
use stellar_xdr::{
    Int128Parts, InvokeContractArgs, Limits, ScString, ScSymbol, ScVal, StringM, WriteXdr as _,
};
use zeroize::Zeroizing;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";
const TESTNET_FRIENDBOT_URL: &str = "https://friendbot.stellar.org";
const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";

/// Known-answer XLM SAC on testnet (SEP-41 native-asset contract). Source:
/// `soroswap-core/public/tokens.json:testnet:assets[0]:contract`; also a
/// known-answer test in `stellar-agent-dex/src/sac.rs` and the smart-account
/// delegation acceptance test.
const XLM_SAC_TESTNET: &str = "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC";

/// Spending limit installed on the CallContract rule (5 XLM, in stroops).
const SPENDING_LIMIT_STROOPS: i128 = 50_000_000;

/// Rolling-window length for the spending limit, in ledgers.
const SPENDING_PERIOD_LEDGERS: u32 = 1_000;

/// First transfer amount (1 XLM): strictly under the limit.
const FIRST_TRANSFER_STROOPS: i128 = 10_000_000;

/// Second transfer amount (4.5 XLM): pushes cumulative spend over the limit.
const SECOND_TRANSFER_STROOPS: i128 = 45_000_000;

/// XLM funded into the smart account's SAC balance (7 XLM): exceeds
/// `FIRST_TRANSFER_STROOPS + SECOND_TRANSFER_STROOPS` with margin so the
/// over-limit transfer is refused for `SpendingLimitExceeded` specifically,
/// not insufficient SAC balance.
const SMART_ACCOUNT_FUND_STROOPS: i128 = 70_000_000;

const RULE_SIGNER_ENV_VAR: &str = "EXEC_ACCEPTANCE_RULE_SIGNER";
const FEE_PAYER_ENV_VAR: &str = "EXEC_ACCEPTANCE_FEE_PAYER";

const DEPLOY_TIMEOUT: Duration = Duration::from_secs(120);

// ─────────────────────────────────────────────────────────────────────────────
// Keypair / funding helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Generates a fresh ed25519 keypair. Returns `(g_strkey, seed, raw_pubkey)`.
fn fresh_keypair() -> (String, Zeroizing<[u8; 32]>, [u8; 32]) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let g_strkey = stellar_strkey::ed25519::PublicKey(verifying_key.to_bytes())
        .to_string()
        .as_str()
        .to_owned();
    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(signing_key.to_bytes());
    (g_strkey, seed, verifying_key.to_bytes())
}

/// Encodes a 32-byte seed as an S-strkey.
fn s_strkey_from_seed(seed: &[u8; 32]) -> String {
    stellar_strkey::ed25519::PrivateKey::from_payload(seed)
        .expect("32-byte seed encodes as S-strkey")
        .as_unredacted()
        .to_string()
        .as_str()
        .to_owned()
}

async fn fund_via_friendbot(g_strkey: &str) {
    let url = format!("{TESTNET_FRIENDBOT_URL}?addr={g_strkey}");
    let resp = reqwest::get(&url)
        .await
        .expect("Friendbot HTTP request must succeed");
    assert!(
        resp.status().is_success(),
        "Friendbot must return 2xx for {g_strkey}; got {}",
        resp.status()
    );
}

async fn wait_until_account_queryable(g_strkey: &str) {
    let client = StellarRpcClient::new(TESTNET_RPC_URL).expect("RPC client");
    for _ in 0..30 {
        if fetch_account(&client, g_strkey, &[]).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("funded account {g_strkey} did not become RPC-queryable in time");
}

/// Returns the classic native (XLM) balance of `g_strkey`, in exact stroops.
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

fn fresh_deployer_keypair() -> (String, DeployerKeypair) {
    let (g_strkey, seed, _pk) = fresh_keypair();
    let signer: Box<dyn Signer + Send + Sync> =
        Box::new(SoftwareSigningKey::new_from_zeroizing(seed));
    (
        g_strkey,
        DeployerKeypair::SecretEnv {
            var_name: "exec-acceptance-generated".to_owned(),
            signer,
        },
    )
}

/// Deploys the OZ ed25519 verifier and OZ spending-limit policy to a
/// temporary `VerifierRegistry` path (never consulted by the binary — every
/// binary call below passes an explicit `--verifier` / `--policy` override).
async fn deploy_verifier_and_policy(registry_path: &Path) -> (String, String) {
    let (deployer_g, deployer) = fresh_deployer_keypair();
    fund_via_friendbot(&deployer_g).await;

    let verifier_args = Ed25519VerifierDeployArgs {
        deployer,
        network_passphrase: TESTNET_PASSPHRASE.to_owned(),
        rpc_url: TESTNET_RPC_URL.to_owned(),
        timeout: DEPLOY_TIMEOUT,
        fee: ResolvedFeePerOp {
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
        timeout: DEPLOY_TIMEOUT,
        fee: ResolvedFeePerOp {
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
        timeout: DEPLOY_TIMEOUT,
        fee: ResolvedFeePerOp {
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

// ─────────────────────────────────────────────────────────────────────────────
// SAC-transfer fixture callbacks (for `fund_sac_balance`)
// ─────────────────────────────────────────────────────────────────────────────

#[allow(
    clippy::result_large_err,
    reason = "SaError is the crate's production error type; this test-only builder \
              surfaces it unchanged rather than introducing a narrower local error type"
)]
fn transfer_invoke_args(
    sac: &str,
    from: &str,
    to: &str,
    amount: i128,
) -> Result<InvokeContractArgs, stellar_agent_smart_account::error::SaError> {
    let contract_address = parse_c_strkey_to_smart_account(sac)?;
    let from_sc = parse_g_strkey_to_signer_address(from)?;
    let to_sc = parse_c_strkey_to_smart_account(to)?;
    Ok(InvokeContractArgs {
        contract_address,
        function_name: ScSymbol::try_from("transfer").expect("\"transfer\" fits ScSymbol"),
        args: vec![
            ScVal::Address(from_sc),
            ScVal::Address(to_sc),
            ScVal::I128(i128_parts(amount)),
        ]
        .try_into()
        .expect("3-element transfer args vec fits VecM<ScVal>"),
    })
}

async fn fetch_testnet_sequence(
    account_id: String,
) -> Result<i64, Box<dyn std::error::Error + Send + Sync>> {
    let rpc_client = StellarRpcClient::new(TESTNET_RPC_URL)?;
    Ok(fetch_account(&rpc_client, &account_id, &[])
        .await?
        .sequence_number)
}

async fn sign_testnet_envelope(
    unsigned_xdr: String,
    funder_seed: Zeroizing<[u8; 32]>,
    network_passphrase: String,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let signer = SoftwareSigningKey::new_from_zeroizing(funder_seed);
    Ok(attach_signature(&unsigned_xdr, &signer, &network_passphrase).await?)
}

async fn submit_testnet_signed_xdr(
    signed_xdr: String,
) -> Result<stellar_agent_network::submit::SubmissionResult, Box<dyn std::error::Error + Send + Sync>>
{
    let rpc_client = StellarRpcClient::new(TESTNET_RPC_URL)?;
    Ok(submit_transaction_and_wait(
        &rpc_client,
        &signed_xdr,
        Duration::from_secs(120),
        TESTNET_PASSPHRASE,
        Some(SubmissionSignerKind::Software),
    )
    .await?)
}

fn i128_parts(amount: i128) -> Int128Parts {
    #[allow(
        clippy::cast_possible_truncation,
        reason = "canonical i128 -> Int128Parts split: hi = high 64 bits, lo = low 64 bits"
    )]
    Int128Parts {
        hi: (amount >> 64) as i64,
        lo: amount as u64,
    }
}

fn scval_b64(val: &ScVal) -> String {
    val.to_xdr_base64(Limits::none())
        .expect("ScVal XDR encoding must succeed")
}

// ─────────────────────────────────────────────────────────────────────────────
// CLI subprocess helper
// ─────────────────────────────────────────────────────────────────────────────

/// Runs the `stellar-agent` release binary with `args` and the given
/// environment variables set only on the child process. Returns
/// `(exit_success, last_stdout_line_as_json, stdout, stderr)`.
fn run_cli(args: &[&str], envs: &[(&str, &str)]) -> (bool, serde_json::Value, String, String) {
    let bin_path = env!("CARGO_BIN_EXE_stellar-agent");
    let mut cmd = Command::new(bin_path);
    cmd.args(args);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let output = cmd.output().expect("stellar-agent subprocess must spawn");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let last_line = stdout
        .lines()
        .rfind(|l| !l.trim().is_empty())
        .unwrap_or_else(|| panic!("no stdout for {args:?}; stderr={stderr}"));
    let envelope: serde_json::Value = serde_json::from_str(last_line).unwrap_or_else(|e| {
        panic!("stdout not valid JSON ({e}) for {args:?}: {last_line}; stderr={stderr}")
    });
    (output.status.success(), envelope, stdout, stderr)
}

// ─────────────────────────────────────────────────────────────────────────────
// Test
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn smart_account_execute_full_flow_testnet_acceptance() {
    let tmp = tempfile::tempdir().expect("tempdir must be created");
    let registry_path = tmp.path().join("networks.toml");

    // ── Step 1: deploy the ed25519 verifier + spending-limit policy ─────────
    let (verifier_address, policy_address) = deploy_verifier_and_policy(&registry_path).await;

    // ── Step 2: deploy a fresh smart account with a Delegated bootstrap signer ──
    let (bootstrap_g, bootstrap_seed, _bootstrap_pk) = fresh_keypair();
    fund_via_friendbot(&bootstrap_g).await;
    wait_until_account_queryable(&bootstrap_g).await;
    let smart_account = deploy_fresh_smart_account(&bootstrap_g).await;
    let bootstrap_s_strkey = s_strkey_from_seed(&bootstrap_seed);

    // ── Fresh External-Ed25519 rule signer (the agent's key) ────────────────
    let (_rule_signer_g, rule_signer_seed, rule_signer_pubkey) = fresh_keypair();
    let rule_signer_hex = hex::encode(rule_signer_pubkey);
    let rule_signer_s_strkey = s_strkey_from_seed(&rule_signer_seed);

    // ── Step 3: install the CallContract(XLM SAC) rule — through the BINARY ──
    let context_flag = format!("call-contract:{XLM_SAC_TESTNET}");
    let (ok, envelope, stdout, stderr) = run_cli(
        &[
            "smart-account",
            "rules",
            "create",
            "--account",
            &smart_account,
            "--name",
            "exec-accept",
            "--signer-ed25519",
            &rule_signer_hex,
            "--verifier",
            &verifier_address,
            "--accept-no-delegated-fallback",
            "--context",
            &context_flag,
            "--auth-rule-id",
            "0",
            "--signer-secret-env",
            FEE_PAYER_ENV_VAR,
            "--network",
            "testnet",
            "--rpc-url",
            TESTNET_RPC_URL,
        ],
        &[(FEE_PAYER_ENV_VAR, &bootstrap_s_strkey)],
    );
    assert!(
        ok,
        "rules create must succeed; stdout={stdout} stderr={stderr}"
    );
    let rule_id = envelope["data"]["rule_id"]
        .as_u64()
        .unwrap_or_else(|| panic!("rule_id missing from envelope: {envelope}"));
    assert!(rule_id != 0, "installed rule_id must differ from bootstrap");

    // ── Step 4: attach the spending-limit policy — through the BINARY ──────
    let (ok, envelope, stdout, stderr) = run_cli(
        &[
            "smart-account",
            "rules",
            "add-policy",
            "--account",
            &smart_account,
            "--rule-id",
            &rule_id.to_string(),
            "--kind",
            "spending-limit",
            "--limit",
            &SPENDING_LIMIT_STROOPS.to_string(),
            "--period",
            &SPENDING_PERIOD_LEDGERS.to_string(),
            "--policy",
            &policy_address,
            "--auth-rule-id",
            "0",
            "--signer-secret-env",
            FEE_PAYER_ENV_VAR,
            "--network",
            "testnet",
            "--rpc-url",
            TESTNET_RPC_URL,
        ],
        &[(FEE_PAYER_ENV_VAR, &bootstrap_s_strkey)],
    );
    assert!(
        ok,
        "rules add-policy must succeed; stdout={stdout} stderr={stderr}; envelope={envelope}"
    );

    // ── Fund the smart account's SAC balance so execute can actually settle ──
    let _fund_result: stellar_agent_network::submit::SubmissionResult = fund_sac_balance(
        "execute-acceptance",
        TESTNET_RPC_URL,
        TESTNET_PASSPHRASE,
        TESTNET_FRIENDBOT_URL,
        XLM_SAC_TESTNET,
        &smart_account,
        SMART_ACCOUNT_FUND_STROOPS,
        transfer_invoke_args,
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
    let (recipient_g, _recipient_seed, _recipient_pk) = fresh_keypair();
    fund_via_friendbot(&recipient_g).await;
    wait_until_account_queryable(&recipient_g).await;

    let smart_account_sc =
        parse_c_strkey_to_smart_account(&smart_account).expect("smart-account C-strkey parses");
    let recipient_sc =
        parse_g_strkey_to_signer_address(&recipient_g).expect("recipient G-strkey parses");

    // ── Step 6: execute UNDER the limit — MUST succeed ──────────────────────
    let balance_before = xlm_stroops_balance(&recipient_g).await;
    let first_amount_scval = ScVal::I128(i128_parts(FIRST_TRANSFER_STROOPS));
    let (ok, envelope, stdout, stderr) = run_cli(
        &[
            "smart-account",
            "execute",
            "--account",
            &smart_account,
            "--contract",
            XLM_SAC_TESTNET,
            "--function",
            "transfer",
            "--arg",
            &scval_b64(&ScVal::Address(smart_account_sc.clone())),
            "--arg",
            &scval_b64(&ScVal::Address(recipient_sc.clone())),
            "--arg",
            &scval_b64(&first_amount_scval),
            "--auth-rule-id",
            &rule_id.to_string(),
            "--rule-signer-ed25519-secret-env",
            RULE_SIGNER_ENV_VAR,
            "--verifier",
            &verifier_address,
            "--signer-secret-env",
            FEE_PAYER_ENV_VAR,
            "--network",
            "testnet",
            "--rpc-url",
            TESTNET_RPC_URL,
        ],
        &[
            (RULE_SIGNER_ENV_VAR, &rule_signer_s_strkey),
            (FEE_PAYER_ENV_VAR, &bootstrap_s_strkey),
        ],
    );
    assert!(
        ok,
        "execute under the spending limit must succeed; stdout={stdout} stderr={stderr}"
    );
    let tx_hash = envelope["data"]["tx_hash"]
        .as_str()
        .unwrap_or_else(|| panic!("tx_hash missing from envelope: {envelope}"));
    assert_eq!(tx_hash.len(), 64, "tx_hash must be a 32-byte hex digest");
    assert_eq!(
        envelope["data"]["rule_signer_pubkey_first8"].as_str(),
        Some(&rule_signer_hex[..8]),
        "envelope must report the rule signer's pubkey prefix"
    );

    let balance_after = xlm_stroops_balance(&recipient_g).await;
    #[allow(
        clippy::cast_possible_truncation,
        reason = "stroop amounts here are far below i64::MAX"
    )]
    let expected_delta = FIRST_TRANSFER_STROOPS as i64;
    assert_eq!(
        balance_after - balance_before,
        expected_delta,
        "recipient balance delta must equal the transferred amount exactly"
    );

    // ── Step 7: execute OVER the limit — MUST fail with SpendingLimitExceeded ──
    let second_amount_scval = ScVal::I128(i128_parts(SECOND_TRANSFER_STROOPS));
    let (ok, envelope, stdout, stderr) = run_cli(
        &[
            "smart-account",
            "execute",
            "--account",
            &smart_account,
            "--contract",
            XLM_SAC_TESTNET,
            "--function",
            "transfer",
            "--arg",
            &scval_b64(&ScVal::Address(smart_account_sc.clone())),
            "--arg",
            &scval_b64(&ScVal::Address(recipient_sc.clone())),
            "--arg",
            &scval_b64(&second_amount_scval),
            "--auth-rule-id",
            &rule_id.to_string(),
            "--rule-signer-ed25519-secret-env",
            RULE_SIGNER_ENV_VAR,
            "--verifier",
            &verifier_address,
            "--signer-secret-env",
            FEE_PAYER_ENV_VAR,
            "--network",
            "testnet",
            "--rpc-url",
            TESTNET_RPC_URL,
        ],
        &[
            (RULE_SIGNER_ENV_VAR, &rule_signer_s_strkey),
            (FEE_PAYER_ENV_VAR, &bootstrap_s_strkey),
        ],
    );
    assert!(
        !ok,
        "execute over the spending limit must fail; stdout={stdout} stderr={stderr}"
    );
    let error_message = envelope["error"]["message"]
        .as_str()
        .unwrap_or_else(|| panic!("error.message missing from envelope: {envelope}"));
    assert!(
        error_message.contains("[OZ:SpendingLimitExceeded]"),
        "expected SpendingLimitExceeded (3221); got: {error_message}"
    );
    assert!(
        !error_message.contains("[OZ:NotAllowed]"),
        "must not be misclassified as NotAllowed (3223): {error_message}"
    );

    // ── Step 8: execute against a DIFFERENT contract — MUST fail (scope) ────
    //
    // The "different contract" is the smart account itself: a self-call
    // (`update_context_rule_name`) has `context.contract == smart_account`,
    // which does not match this rule's `CallContract(xlm_sac)` context type.
    let rename_args = [
        scval_b64(&ScVal::U32(
            u32::try_from(rule_id).expect("rule_id fits u32"),
        )),
        scval_b64(&ScVal::String(ScString(
            StringM::try_from("x").expect("single-char name fits StringM"),
        ))),
    ];
    let (ok, envelope, stdout, stderr) = run_cli(
        &[
            "smart-account",
            "execute",
            "--account",
            &smart_account,
            "--contract",
            &smart_account,
            "--function",
            "update_context_rule_name",
            "--arg",
            &rename_args[0],
            "--arg",
            &rename_args[1],
            "--auth-rule-id",
            &rule_id.to_string(),
            "--rule-signer-ed25519-secret-env",
            RULE_SIGNER_ENV_VAR,
            "--verifier",
            &verifier_address,
            "--signer-secret-env",
            FEE_PAYER_ENV_VAR,
            "--network",
            "testnet",
            "--rpc-url",
            TESTNET_RPC_URL,
        ],
        &[
            (RULE_SIGNER_ENV_VAR, &rule_signer_s_strkey),
            (FEE_PAYER_ENV_VAR, &bootstrap_s_strkey),
        ],
    );
    assert!(
        !ok,
        "execute against a different contract must fail; stdout={stdout} stderr={stderr}"
    );
    let error_message = envelope["error"]["message"]
        .as_str()
        .unwrap_or_else(|| panic!("error.message missing from envelope: {envelope}"));
    assert!(
        error_message.contains("[OZ:UnvalidatedContext]"),
        "expected UnvalidatedContext (3002, CallContract scope mismatch); got: {error_message}"
    );
}
