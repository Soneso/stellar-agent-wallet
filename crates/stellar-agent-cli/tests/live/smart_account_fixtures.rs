//! Live testnet fixtures for the CLI's smart-account suites: the testnet
//! endpoints and native-asset SAC, fresh keypairs, Friendbot funding, a fresh
//! smart-account deployment, and the sequence, signing, and submission hooks
//! the test-support live helpers take.
//!
//! The `smart_account_execute_testnet_acceptance` and
//! `smart_account_multicall_cli_testnet_acceptance` targets include this file
//! through a `#[path]` attribute; moving or renaming it breaks their build.

#![allow(dead_code, reason = "Helpers are shared by two test targets.")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test fixtures assert their own preconditions"
)]

use std::time::Duration;

use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore as _};
use stellar_agent_network::signing::Signer;
use stellar_agent_network::signing::envelope_signing::attach_signature;
use stellar_agent_network::submit::{SubmissionResult, SubmissionSignerKind};
use stellar_agent_network::{
    SoftwareSigningKey, StellarRpcClient, fetch_account, submit_transaction_and_wait,
};
use stellar_agent_smart_account::deployment::{
    DeployerKeypair, DeploymentArgs, ResolvedFeePerOp, deploy_smart_account,
};
use zeroize::Zeroizing;

/// Soroban RPC endpoint for SDF testnet.
pub const TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";

/// Friendbot endpoint for testnet account funding.
pub const TESTNET_FRIENDBOT_URL: &str = "https://friendbot.stellar.org";

/// Network passphrase for SDF testnet.
pub const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";

/// Known-answer XLM SAC on testnet (SEP-41 native-asset contract). Source:
/// `soroswap-core/public/tokens.json:testnet:assets[0]:contract`; also a
/// known-answer test in `stellar-agent-dex/src/sac.rs` and the smart-account
/// delegation acceptance test.
pub const XLM_SAC_TESTNET: &str = "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC";

/// Deployment and submission budget of the fixtures.
pub const DEPLOY_TIMEOUT: Duration = Duration::from_secs(120);

/// Base fee of the fixture deployments, in stroops.
const DEPLOY_FEE_STROOPS: u32 = 1_000_000;

/// Generates a fresh ed25519 keypair. Returns `(g_strkey, seed, raw_pubkey)`.
pub fn fresh_keypair() -> (String, Zeroizing<[u8; 32]>, [u8; 32]) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let g_strkey = stellar_strkey::ed25519::PublicKey(verifying_key.to_bytes())
        .to_string()
        .as_str()
        .to_owned();
    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(signing_key.to_bytes());
    (g_strkey, seed, verifying_key.to_bytes())
}

/// Funds `g_strkey` through testnet Friendbot.
pub async fn fund_via_friendbot(g_strkey: &str) {
    let url = format!("{TESTNET_FRIENDBOT_URL}?addr={g_strkey}");
    let resp = stellar_agent_test_support::testnet_helpers::friendbot_funding_request(&url)
        .await
        .expect("Friendbot HTTP request must succeed");
    assert!(
        resp.status().is_success(),
        "Friendbot must return 2xx for {g_strkey}; got {}",
        resp.status()
    );
}

/// Waits until the testnet RPC answers for a freshly funded account.
pub async fn wait_until_account_queryable(g_strkey: &str) {
    let client = StellarRpcClient::new(TESTNET_RPC_URL).expect("RPC client");
    for _ in 0..30 {
        if fetch_account(&client, g_strkey, &[]).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("funded account {g_strkey} did not become RPC-queryable in time");
}

/// A fresh deployer keypair for the deployment library.
pub fn fresh_deployer_keypair() -> (String, DeployerKeypair) {
    let (g_strkey, seed, _pk) = fresh_keypair();
    let signer: Box<dyn Signer + Send + Sync> =
        Box::new(SoftwareSigningKey::new_from_zeroizing(seed));
    (
        g_strkey,
        DeployerKeypair::SecretEnv {
            var_name: "cli-acceptance-generated".to_owned(),
            signer,
        },
    )
}

/// Deploys a fresh smart account whose constructor-rule signer is
/// `initial_signer_g`, from a funded fresh deployer with a random salt.
/// Returns the deployed C-strkey.
pub async fn deploy_fresh_smart_account(initial_signer_g: &str) -> String {
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
            stroops: DEPLOY_FEE_STROOPS,
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

/// Fetches an account's current sequence number via the testnet RPC.
pub async fn fetch_testnet_sequence(
    account_id: String,
) -> Result<i64, Box<dyn std::error::Error + Send + Sync>> {
    let rpc_client = StellarRpcClient::new(TESTNET_RPC_URL)?;
    Ok(fetch_account(&rpc_client, &account_id, &[])
        .await?
        .sequence_number)
}

/// Signs an unsigned envelope XDR with a raw ed25519 seed.
pub async fn sign_testnet_envelope(
    unsigned_xdr: String,
    seed: Zeroizing<[u8; 32]>,
    network_passphrase: String,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let signer = SoftwareSigningKey::new_from_zeroizing(seed);
    Ok(attach_signature(&unsigned_xdr, &signer, &network_passphrase).await?)
}

/// Submits a signed envelope XDR and waits for confirmation.
pub async fn submit_testnet_signed_xdr(
    signed_xdr: String,
) -> Result<SubmissionResult, Box<dyn std::error::Error + Send + Sync>> {
    let rpc_client = StellarRpcClient::new(TESTNET_RPC_URL)?;
    Ok(submit_transaction_and_wait(
        &rpc_client,
        &signed_xdr,
        DEPLOY_TIMEOUT,
        TESTNET_PASSPHRASE,
        Some(SubmissionSignerKind::Software),
        None,
    )
    .await?)
}
