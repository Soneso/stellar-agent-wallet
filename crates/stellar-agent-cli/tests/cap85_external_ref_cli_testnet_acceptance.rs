//! Testnet acceptance: the `stellar-agent` binary's handling of a CAP-85
//! external-reference verifier.
//!
//! Fixture setup uses the library and test-support helpers directly: a fresh
//! Friendbot-funded admin uploads and instantiates the vendored beacon, the
//! OZ ed25519 and WebAuthn verifiers are deployed through the wallet's deploy
//! functions (which upload their code), the admin publishes the tag
//! `"verifier"` at the ed25519 verifier hash and deploys the proxy, a
//! contract whose executable is the external reference `(beacon,
//! "verifier")`. A fresh smart account is deployed with a Delegated bootstrap
//! signer.
//!
//! The surface under test runs through the BINARY
//! (`env!("CARGO_BIN_EXE_stellar-agent")`), with `STELLAR_AGENT_HOME` and
//! `HOME` pointing at a fresh temporary directory and the headless keyring
//! backend selected, so no child reaches the operator's data root or the OS
//! keychain:
//!
//! 1. `smart-account rules create --verifier <proxy>` without
//!    `--accept-mutable-verifier` refuses with `sa.verifier_mutable`.
//! 2. The same command with `--accept-mutable-verifier` installs the rule and
//!    reports the pinned reference: tag `"verifier"`, the redacted beacon and
//!    the first 8 bytes of the ed25519 verifier hash.
//! 3. `smart-account execute` signs a transfer through the rule with the
//!    agent's key and confirms: the pinned-hash drift check passes.
//! 4. After the beacon repoints the tag at the WebAuthn verifier,
//!    `smart-account execute` through the rule exits non-zero with
//!    `sa.verifier_hash_drift` before signing, and
//!    `smart-account rules verify-pins` reports `verifier_pin_status:
//!    "drift"` and exits 1.
//!
//! Gated behind `testnet-acceptance`:
//!
//! ```text
//! cargo test -p stellar-agent-cli --features testnet-acceptance \
//!   --test cap85_external_ref_cli_testnet_acceptance
//! ```

#![cfg(feature = "testnet-acceptance")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    reason = "test-only; panics and diagnostic output are acceptable in testnet acceptance tests"
)]

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore as _};
use sha2::{Digest as _, Sha256};
use stellar_agent_core::observability::redact_strkey_first5_last5;
use stellar_agent_network::signing::Signer;
use stellar_agent_network::signing::envelope_signing::attach_signature;
use stellar_agent_network::submit::{SubmissionResult, SubmissionSignerKind};
use stellar_agent_network::{
    SoftwareSigningKey, StellarRpcClient, fetch_account, submit_transaction_and_wait,
};
use stellar_agent_smart_account::cap85_beacon::CAP85_BEACON_WASM;
use stellar_agent_smart_account::deployment::{
    DeployerKeypair, DeploymentArgs, Ed25519VerifierDeployArgs, ResolvedFeePerOp,
    WebAuthnVerifierDeployArgs, deploy_ed25519_verifier, deploy_smart_account,
    deploy_webauthn_verifier,
};
use stellar_agent_smart_account::ed25519_verifier::ED25519_VERIFIER_WASM;
use stellar_agent_smart_account::managers::rules::{
    parse_c_strkey_to_smart_account, parse_g_strkey_to_signer_address,
};
use stellar_agent_smart_account::webauthn_verifier::WEBAUTHN_VERIFIER_WASM;
use stellar_agent_test_support::testnet_helpers::{
    SourceAccountInvocation, account_scaddress, contract_scaddress, derive_contract_address,
    fund_sac_balance, invoke_as_source_account, upload_and_create_contract,
};
use stellar_xdr::{
    BytesM, Int128Parts, InvokeContractArgs, Limits, ScBytes, ScString, ScSymbol, ScVal, StringM,
    WriteXdr as _,
};
use zeroize::Zeroizing;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";
const TESTNET_FRIENDBOT_URL: &str = "https://friendbot.stellar.org";
const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";

/// Known-answer XLM SAC on testnet (SEP-41 native-asset contract); also a
/// known-answer test in `stellar-agent-dex/src/sac.rs`.
const XLM_SAC_TESTNET: &str = "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC";

/// The executable-reference tag the beacon publishes.
const TAG: &str = "verifier";

const FEE_PAYER_ENV_VAR: &str = "CAP85_CLI_ACCEPTANCE_FEE_PAYER";
const RULE_SIGNER_ENV_VAR: &str = "CAP85_CLI_ACCEPTANCE_RULE_SIGNER";

/// XLM funded into the smart account's SAC balance (1 XLM).
const SMART_ACCOUNT_FUND_STROOPS: i128 = 10_000_000;

/// XLM each `smart-account execute` transfer moves (0.1 XLM).
const TRANSFER_STROOPS: i128 = 1_000_000;
const TIMEOUT: Duration = Duration::from_secs(120);

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Prints one report record; every value is public testnet data.
fn record(item: &str, value: &str) {
    eprintln!("CAP85-RECORD cli {item} {value}");
}

/// Generates a fresh ed25519 keypair: `(g_strkey, seed)`.
fn fresh_keypair() -> (String, Zeroizing<[u8; 32]>) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let g_strkey = format!(
        "{}",
        stellar_strkey::ed25519::PublicKey(signing_key.verifying_key().to_bytes())
    );
    (g_strkey, Zeroizing::new(signing_key.to_bytes()))
}

fn s_strkey_from_seed(seed: &[u8; 32]) -> String {
    let secret = stellar_strkey::ed25519::PrivateKey::from_payload(seed)
        .expect("32-byte seed encodes as S-strkey");
    format!("{}", secret.as_unredacted())
}

fn random_bytes() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

async fn fund_via_friendbot(g_strkey: &str) {
    let url = format!("{TESTNET_FRIENDBOT_URL}?addr={g_strkey}");
    let resp = stellar_agent_test_support::testnet_helpers::friendbot_funding_request(&url)
        .await
        .expect("Friendbot HTTP request must succeed");
    assert!(
        resp.status().is_success(),
        "Friendbot must return 2xx for {g_strkey}; got {}",
        resp.status()
    );
    let client = StellarRpcClient::new(TESTNET_RPC_URL).expect("RPC client");
    for _ in 0..30 {
        if fetch_account(&client, g_strkey, &[]).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("funded account {g_strkey} did not become RPC-queryable in time");
}

async fn funded_deployer(label: &str) -> DeployerKeypair {
    let (g, seed) = fresh_keypair();
    fund_via_friendbot(&g).await;
    let signer: Box<dyn Signer + Send + Sync> =
        Box::new(SoftwareSigningKey::new_from_zeroizing(seed));
    DeployerKeypair::SecretEnv {
        var_name: format!("cap85-cli-acceptance-{label}"),
        signer,
    }
}

fn explicit_fee() -> ResolvedFeePerOp {
    ResolvedFeePerOp {
        stroops: 1_000_000,
        percentile_label: "explicit".to_owned(),
    }
}

fn bytes_scval(bytes: &[u8]) -> ScVal {
    ScVal::Bytes(ScBytes(
        BytesM::try_from(bytes.to_vec()).expect("bytes fit ScBytes"),
    ))
}

fn tag_scval() -> ScVal {
    ScVal::String(ScString(StringM::try_from(TAG).expect("tag fits ScString")))
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
    seed: Zeroizing<[u8; 32]>,
    network_passphrase: String,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let signer = SoftwareSigningKey::new_from_zeroizing(seed);
    Ok(attach_signature(&unsigned_xdr, &signer, &network_passphrase).await?)
}

async fn submit_testnet_signed_xdr(
    signed_xdr: String,
) -> Result<SubmissionResult, Box<dyn std::error::Error + Send + Sync>> {
    let rpc_client = StellarRpcClient::new(TESTNET_RPC_URL)?;
    Ok(submit_transaction_and_wait(
        &rpc_client,
        &signed_xdr,
        TIMEOUT,
        TESTNET_PASSPHRASE,
        Some(SubmissionSignerKind::Software),
        None,
    )
    .await?)
}

fn i128_scval(amount: i128) -> ScVal {
    #[allow(
        clippy::cast_possible_truncation,
        reason = "canonical i128 -> Int128Parts split: hi = high 64 bits, lo = low 64 bits"
    )]
    ScVal::I128(Int128Parts {
        hi: (amount >> 64) as i64,
        lo: amount as u64,
    })
}

fn scval_b64(val: &ScVal) -> String {
    val.to_xdr_base64(Limits::none())
        .expect("ScVal XDR encoding must succeed")
}

/// Builds the SAC `transfer(from, to, amount)` invocation `fund_sac_balance`
/// submits from its funder account.
#[allow(
    clippy::result_large_err,
    reason = "SaError is the crate's production error type; this test-only builder \
              surfaces it unchanged"
)]
fn transfer_invoke_args(
    sac: &str,
    from: &str,
    to: &str,
    amount: i128,
) -> Result<InvokeContractArgs, stellar_agent_smart_account::error::SaError> {
    Ok(InvokeContractArgs {
        contract_address: parse_c_strkey_to_smart_account(sac)?,
        function_name: ScSymbol::try_from("transfer").expect("\"transfer\" fits ScSymbol"),
        args: vec![
            ScVal::Address(parse_g_strkey_to_signer_address(from)?),
            ScVal::Address(parse_c_strkey_to_smart_account(to)?),
            i128_scval(amount),
        ]
        .try_into()
        .expect("3-element transfer args vec fits VecM<ScVal>"),
    })
}

/// Invokes a beacon function as its admin.
async fn invoke_beacon(
    beacon: &str,
    function_name: &str,
    args: Vec<ScVal>,
    admin_g: &str,
    admin_seed: &Zeroizing<[u8; 32]>,
) -> SourceAccountInvocation<SubmissionResult> {
    invoke_as_source_account(
        TESTNET_RPC_URL,
        TESTNET_PASSPHRASE,
        admin_g,
        admin_seed,
        beacon,
        function_name,
        args,
        |account_id| fetch_testnet_sequence(account_id.to_owned()),
        |unsigned_xdr, seed, network_passphrase| {
            sign_testnet_envelope(unsigned_xdr, seed, network_passphrase.to_owned())
        },
        submit_testnet_signed_xdr,
    )
    .await
    .unwrap_or_else(|e| panic!("beacon {function_name} must succeed: {e}"))
}

/// Runs the binary with `args`, `STELLAR_AGENT_HOME` and `HOME` under
/// `home`, the headless keyring backend, and `envs`. Returns
/// `(exit_code, last_stdout_line_as_json, stdout, stderr)`.
fn run_cli(
    home: &Path,
    keyring_key: &str,
    args: &[&str],
    envs: &[(&str, &str)],
) -> (i32, serde_json::Value, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_stellar-agent"));
    cmd.args(args)
        .env("STELLAR_AGENT_HOME", home.join("agent"))
        .env("HOME", home.join("home"))
        .env_remove("STELLAR_AGENT_PROFILE")
        .env(
            stellar_agent_headless_keyring::BACKEND_ENV_VAR,
            "headless-env",
        )
        .env(stellar_agent_headless_keyring::ENV_KEY_VAR, keyring_key);
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
    let code = output
        .status
        .code()
        .unwrap_or_else(|| panic!("process must exit with a status code; stderr={stderr}"));
    (code, envelope, stdout, stderr)
}

// ─────────────────────────────────────────────────────────────────────────────
// Test
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn rules_create_pins_the_reference_and_verify_pins_reports_the_repoint() {
    let tmp = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(tmp.path().join("agent")).expect("agent home");
    std::fs::create_dir_all(tmp.path().join("home")).expect("HOME");
    let registry_path = tmp.path().join("networks.toml");
    let keyring_key = URL_SAFE_NO_PAD.encode(random_bytes());

    // ── Beacon ──────────────────────────────────────────────────────────────
    let (admin_g, admin_seed) = fresh_keypair();
    fund_via_friendbot(&admin_g).await;
    record("beacon-admin", &admin_g);
    let beacon = upload_and_create_contract(
        TESTNET_RPC_URL,
        TESTNET_PASSPHRASE,
        &admin_g,
        &admin_seed,
        CAP85_BEACON_WASM,
        random_bytes(),
        vec![ScVal::Address(
            account_scaddress(&admin_g).expect("admin G-strkey parses"),
        )],
        |account_id| fetch_testnet_sequence(account_id.to_owned()),
        |unsigned_xdr, seed, network_passphrase| {
            sign_testnet_envelope(unsigned_xdr, seed, network_passphrase.to_owned())
        },
        submit_testnet_signed_xdr,
    )
    .await
    .unwrap_or_else(|e| panic!("beacon upload and create must succeed: {e}"));
    record("beacon", &beacon.contract);
    record(
        "beacon-upload-tx",
        beacon
            .upload
            .as_ref()
            .map_or("none (not submitted)", |s| s.tx_hash.as_str()),
    );
    record("beacon-create-tx", &beacon.create.tx_hash);

    // ── Verifiers (their deploys upload the two code hashes) ────────────────
    let ed25519 = deploy_ed25519_verifier(
        Ed25519VerifierDeployArgs {
            deployer: funded_deployer("ed25519-verifier").await,
            network_passphrase: TESTNET_PASSPHRASE.to_owned(),
            rpc_url: TESTNET_RPC_URL.to_owned(),
            timeout: TIMEOUT,
            fee: explicit_fee(),
            dry_run: false,
            registry_path_override: Some(registry_path.clone()),
        },
        None,
    )
    .await
    .expect("ed25519 verifier deployment must succeed on testnet");
    record("ed25519-verifier", &ed25519.verifier_address);
    record(
        "ed25519-verifier-tx",
        ed25519.tx_hash.as_deref().unwrap_or("none (not submitted)"),
    );
    let webauthn = deploy_webauthn_verifier(
        WebAuthnVerifierDeployArgs {
            deployer: funded_deployer("webauthn-verifier").await,
            network_passphrase: TESTNET_PASSPHRASE.to_owned(),
            rpc_url: TESTNET_RPC_URL.to_owned(),
            timeout: TIMEOUT,
            fee: explicit_fee(),
            dry_run: false,
            registry_path_override: Some(registry_path.clone()),
        },
        None,
    )
    .await
    .expect("WebAuthn verifier deployment must succeed on testnet");
    record("webauthn-verifier", &webauthn.verifier_address);
    record(
        "webauthn-verifier-tx",
        webauthn
            .tx_hash
            .as_deref()
            .unwrap_or("none (not submitted)"),
    );
    let ed25519_hash: [u8; 32] = Sha256::digest(ED25519_VERIFIER_WASM).into();
    let webauthn_hash: [u8; 32] = Sha256::digest(WEBAUTHN_VERIFIER_WASM).into();

    // ── Proxy ───────────────────────────────────────────────────────────────
    let published = invoke_beacon(
        &beacon.contract,
        "publish",
        vec![tag_scval(), bytes_scval(&ed25519_hash)],
        &admin_g,
        &admin_seed,
    )
    .await;
    record("publish-ed25519-tx", &published.submission.tx_hash);
    let proxy_salt = random_bytes();
    let deployed = invoke_beacon(
        &beacon.contract,
        "deploy_ref",
        vec![tag_scval(), bytes_scval(&proxy_salt)],
        &admin_g,
        &admin_seed,
    )
    .await;
    record("deploy-ref-tx", &deployed.submission.tx_hash);
    let beacon_sc = contract_scaddress(&beacon.contract).expect("beacon C-strkey parses");
    let proxy = derive_contract_address(&beacon_sc, &proxy_salt, TESTNET_PASSPHRASE)
        .expect("proxy address derives");
    assert_eq!(
        deployed.return_value,
        ScVal::Address(contract_scaddress(&proxy).expect("proxy C-strkey parses")),
        "deploy_ref must return the address derived from the beacon and the salt"
    );
    record("proxy", &proxy);

    // ── Smart account with a Delegated bootstrap signer ─────────────────────
    let (bootstrap_g, bootstrap_seed) = fresh_keypair();
    fund_via_friendbot(&bootstrap_g).await;
    let smart_account = deploy_smart_account(
        DeploymentArgs {
            deployer: funded_deployer("smart-account").await,
            initial_signer: bootstrap_g.clone(),
            salt: random_bytes(),
            network_passphrase: TESTNET_PASSPHRASE.to_owned(),
            rpc_url: TESTNET_RPC_URL.to_owned(),
            timeout: TIMEOUT,
            fee: explicit_fee(),
            dry_run: false,
            genesis_signer_scval_override: None,
        },
        None,
    )
    .await
    .expect("smart-account deployment must succeed on testnet");
    record("smart-account", &smart_account.smart_account);
    record(
        "smart-account-tx",
        smart_account
            .tx_hash
            .as_deref()
            .unwrap_or("none (not submitted)"),
    );
    let smart_account = smart_account.smart_account;
    let bootstrap_s_strkey = s_strkey_from_seed(&bootstrap_seed);
    let (_agent_g, agent_seed) = fresh_keypair();
    let agent_hex = hex::encode(
        SigningKey::from_bytes(&agent_seed)
            .verifying_key()
            .to_bytes(),
    );
    let context_flag = format!("call-contract:{XLM_SAC_TESTNET}");
    let fee_payer_env = [(FEE_PAYER_ENV_VAR, bootstrap_s_strkey.as_str())];

    let create_args = |accept_mutable: bool| {
        let mut args = vec![
            "smart-account",
            "rules",
            "create",
            "--account",
            smart_account.as_str(),
            "--name",
            "cap85-cli",
            "--signer-ed25519",
            agent_hex.as_str(),
            "--verifier",
            proxy.as_str(),
            "--accept-no-delegated-fallback",
            "--context",
            context_flag.as_str(),
            "--auth-rule-id",
            "0",
            "--signer-secret-env",
            FEE_PAYER_ENV_VAR,
            "--network",
            "testnet",
            "--rpc-url",
            TESTNET_RPC_URL,
        ];
        if accept_mutable {
            args.push("--accept-mutable-verifier");
        }
        args
    };

    // ── rules create without the override: refused ──────────────────────────
    let (code, envelope, stdout, stderr) = run_cli(
        tmp.path(),
        &keyring_key,
        &create_args(false),
        &fee_payer_env,
    );
    assert_ne!(
        code, 0,
        "rules create through a mutable reference must fail; stdout={stdout} stderr={stderr}"
    );
    assert_eq!(
        envelope["error"]["code"].as_str(),
        Some("sa.verifier_mutable"),
        "refusal must carry sa.verifier_mutable: {envelope}"
    );

    // ── rules create with the override: installs and reports the pin ───────
    let (code, envelope, stdout, stderr) =
        run_cli(tmp.path(), &keyring_key, &create_args(true), &fee_payer_env);
    assert_eq!(
        code, 0,
        "rules create with --accept-mutable-verifier must succeed; stdout={stdout} stderr={stderr}"
    );
    let rule_id = envelope["data"]["rule_id"]
        .as_u64()
        .unwrap_or_else(|| panic!("rule_id missing from envelope: {envelope}"));
    record("rule-id", &rule_id.to_string());
    assert_ne!(
        rule_id, 0,
        "the installed rule must not be the bootstrap rule"
    );
    let pinned = &envelope["data"]["pinned_verifier_executable_refs"];
    assert_eq!(
        pinned.as_array().map(Vec::len),
        Some(1),
        "exactly one verifier reference pin: {envelope}"
    );
    assert_eq!(pinned[0]["tag"].as_str(), Some(TAG));
    assert_eq!(
        pinned[0]["resolved_hash_first8"].as_str(),
        Some(hex::encode(&ed25519_hash[..8]).as_str())
    );
    assert_eq!(
        pinned[0]["owner_redacted"].as_str(),
        Some(redact_strkey_first5_last5(&beacon.contract).as_str())
    );
    assert_eq!(envelope["data"]["mutable_override"].as_bool(), Some(true));

    // ── execute through the pinned rule: the drift check passes ─────────────
    let funded: SubmissionResult = fund_sac_balance(
        "cap85-cli-acceptance",
        TESTNET_RPC_URL,
        TESTNET_PASSPHRASE,
        TESTNET_FRIENDBOT_URL,
        XLM_SAC_TESTNET,
        &smart_account,
        SMART_ACCOUNT_FUND_STROOPS,
        transfer_invoke_args,
        |account_id| fetch_testnet_sequence(account_id.to_owned()),
        |unsigned_xdr, seed, network_passphrase| {
            sign_testnet_envelope(unsigned_xdr, seed, network_passphrase.to_owned())
        },
        submit_testnet_signed_xdr,
    )
    .await
    .unwrap_or_else(|e| panic!("SAC funding of the smart account must succeed: {e}"));
    record("fund-sac-tx", &funded.tx_hash);
    let (recipient_g, _recipient_seed) = fresh_keypair();
    fund_via_friendbot(&recipient_g).await;
    let smart_account_arg = scval_b64(&ScVal::Address(
        contract_scaddress(&smart_account).expect("smart-account C-strkey parses"),
    ));
    let recipient_arg = scval_b64(&ScVal::Address(
        account_scaddress(&recipient_g).expect("recipient G-strkey parses"),
    ));
    let amount_arg = scval_b64(&i128_scval(TRANSFER_STROOPS));
    let rule_id_arg = rule_id.to_string();
    let agent_s_strkey = s_strkey_from_seed(&agent_seed);
    let execute_env = [
        (FEE_PAYER_ENV_VAR, bootstrap_s_strkey.as_str()),
        (RULE_SIGNER_ENV_VAR, agent_s_strkey.as_str()),
    ];
    let execute_args = [
        "smart-account",
        "execute",
        "--account",
        smart_account.as_str(),
        "--contract",
        XLM_SAC_TESTNET,
        "--function",
        "transfer",
        "--arg",
        smart_account_arg.as_str(),
        "--arg",
        recipient_arg.as_str(),
        "--arg",
        amount_arg.as_str(),
        "--auth-rule-id",
        rule_id_arg.as_str(),
        "--rule-signer-ed25519-secret-env",
        RULE_SIGNER_ENV_VAR,
        "--verifier",
        proxy.as_str(),
        "--signer-secret-env",
        FEE_PAYER_ENV_VAR,
        "--network",
        "testnet",
        "--rpc-url",
        TESTNET_RPC_URL,
    ];
    let (code, envelope, stdout, stderr) =
        run_cli(tmp.path(), &keyring_key, &execute_args, &execute_env);
    assert_eq!(
        code, 0,
        "execute through the pinned rule must confirm before the repoint; \
         stdout={stdout} stderr={stderr}"
    );
    let execute_tx = envelope["data"]["tx_hash"]
        .as_str()
        .unwrap_or_else(|| panic!("tx_hash missing from envelope: {envelope}"));
    assert_eq!(execute_tx.len(), 64, "tx_hash must be a 32-byte hex digest");
    record("execute-before-repoint-tx", execute_tx);

    // ── Repoint, then execute refuses on drift and verify-pins reports it ───
    let repointed = invoke_beacon(
        &beacon.contract,
        "publish",
        vec![tag_scval(), bytes_scval(&webauthn_hash)],
        &admin_g,
        &admin_seed,
    )
    .await;
    record("repoint-webauthn-tx", &repointed.submission.tx_hash);

    let (code, envelope, stdout, stderr) =
        run_cli(tmp.path(), &keyring_key, &execute_args, &execute_env);
    assert_ne!(
        code, 0,
        "execute through the repointed reference must fail; stdout={stdout} stderr={stderr}"
    );
    assert_eq!(
        envelope["error"]["code"].as_str(),
        Some("sa.verifier_hash_drift"),
        "execute must refuse with sa.verifier_hash_drift after the repoint: {envelope}"
    );
    let message = envelope["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains(&format!("pinned={}", hex::encode(&ed25519_hash[..8])))
            && message.contains(&format!("observed={}", hex::encode(&webauthn_hash[..8]))),
        "the drift refusal must name the pinned and observed hashes: {message}"
    );
    record("execute-after-repoint-code", "sa.verifier_hash_drift");

    let (code, envelope, stdout, stderr) = run_cli(
        tmp.path(),
        &keyring_key,
        &[
            "smart-account",
            "rules",
            "verify-pins",
            "--account",
            smart_account.as_str(),
            "--rule-id",
            rule_id_arg.as_str(),
            "--network",
            "testnet",
            "--rpc-url",
            TESTNET_RPC_URL,
        ],
        &[],
    );
    assert_eq!(
        envelope["data"]["verifier_pin_status"].as_str(),
        Some("drift"),
        "verify-pins must report verifier drift after the repoint; stdout={stdout} stderr={stderr}"
    );
    assert_eq!(code, 1, "verify-pins exits 1 on drift; stderr={stderr}");
}
