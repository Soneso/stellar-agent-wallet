//! Testnet acceptance tests for `deploy_smart_account`.
//!
//! These tests require a live testnet RPC endpoint and Friendbot access. They
//! are gated behind the `testnet-integration` feature flag:
//!
//! ```text
//! cargo test --features testnet-integration
//! ```
//!
//! Under default `cargo test` (no `--features testnet-integration`), this file
//! compiles but all tests are compiled-out via `#[cfg(feature = "testnet-integration")]`.
//!
//! # Coverage
//!
//! - Deploys a C-account on testnet via `deploy_smart_account`.
//! - Returns the C-strkey + derivation seed in `DeploymentResult`.
//! - Recovers the same C-strkey from the same seed + deployer (in-process
//!   equivalent at `tests/recover_strkey_from_seed_and_deployer.rs`).
//!
//! End-to-end acceptance of `deploy_smart_account` on testnet.
//! Address-recovery property: re-derive from (deployer, salt, passphrase) without a network call.

#![cfg(feature = "testnet-integration")]
#![allow(clippy::unwrap_used, clippy::expect_used, reason = "test-only")]

mod common;

use std::time::Duration;

use common::{TESTNET_PASSPHRASE, TESTNET_RPC_URL, fund_via_friendbot};
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use stellar_agent_network::SoftwareSigningKey;
use stellar_agent_smart_account::deployment::{
    DeployerKeypair, DeploymentArgs, ResolvedFeePerOp, deploy_smart_account,
    derive_smart_account_address, interop_deployer_pubkey,
};
use zeroize::Zeroizing;

/// Generates a fresh ed25519 keypair and returns `(g_strkey, DeployerKeypair::SecretEnv)`.
fn fresh_deployer() -> (String, DeployerKeypair) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let g_strkey = format!(
        "{}",
        stellar_strkey::ed25519::PublicKey(verifying_key.to_bytes())
    );
    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(signing_key.to_bytes());
    let signer: Box<dyn stellar_agent_network::Signer + Send + Sync> =
        Box::new(SoftwareSigningKey::new_from_zeroizing(seed));
    let deployer = DeployerKeypair::SecretEnv {
        var_name: "testnet-acceptance-generated".to_owned(),
        signer,
    };
    (g_strkey, deployer)
}

/// Generates a fresh G-strkey for the initial signer.
fn fresh_initial_signer_g() -> String {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    format!(
        "{}",
        stellar_strkey::ed25519::PublicKey(verifying_key.to_bytes())
    )
}

/// Deploys a C-account on testnet and verifies the returned
/// `DeploymentResult` carries the expected C-strkey matching the pre-derived address.
#[tokio::test]
async fn deploy_smart_account_on_testnet_matches_derived_address() {
    // Generate a fresh deployer keypair.
    let (deployer_g, deployer) = fresh_deployer();

    // Fund the deployer via Friendbot.
    fund_via_friendbot(&deployer_g).await;

    // Generate a fresh initial signer (Friendbot-funded not required for initial_signer
    // at deployment; the signer just needs to be a valid G-strkey).
    let initial_signer = fresh_initial_signer_g();

    // Generate a random salt.
    let mut salt = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut OsRng, &mut salt);

    // Pre-derive the expected C-strkey from the same inputs.
    let expected_c = derive_smart_account_address(&deployer_g, &salt, TESTNET_PASSPHRASE)
        .expect("pre-derivation must succeed");

    let args = DeploymentArgs {
        deployer,
        initial_signer: initial_signer.clone(),
        salt,
        network_passphrase: TESTNET_PASSPHRASE.to_owned(),
        rpc_url: TESTNET_RPC_URL.to_owned(),
        timeout: Duration::from_secs(120),
        fee: ResolvedFeePerOp {
            stroops: 1_000_000,
            percentile_label: "explicit".to_owned(),
        },
        dry_run: false,
        genesis_signer_scval_override: None,
    };

    let result = deploy_smart_account(args, None)
        .await
        .expect("deploy_smart_account must succeed on testnet with a funded deployer");

    // Verify the deployment result envelope.
    assert_eq!(
        result.smart_account, expected_c,
        "on-chain deployed smart_account must match pre-derived address"
    );
    assert_eq!(
        result.deployer_pubkey, deployer_g,
        "deployer_pubkey in result must match the deployer"
    );
    assert!(
        result.tx_hash.is_some(),
        "tx_hash must be present after successful deployment"
    );
    assert!(
        result.ledger.is_some(),
        "ledger must be present after successful deployment"
    );
    assert_eq!(
        result.initial_signer, initial_signer,
        "initial_signer must round-trip through the result"
    );

    // Verify the C-strkey is a valid C-strkey.
    stellar_strkey::Contract::from_string(&result.smart_account)
        .expect("result.smart_account must be a valid C-strkey");
}

/// Verifies that deploying a second time with the SAME deployer + salt returns
/// a different transaction (the contract is already deployed) OR produces the
/// same C-strkey (re-derivation property).
///
/// This test deploys ONCE with a fresh random salt, then re-derives the address
/// from the same inputs WITHOUT a second network call (the recovery property).
#[tokio::test]
async fn recover_c_strkey_from_same_deployer_and_salt() {
    let (deployer_g, deployer) = fresh_deployer();
    fund_via_friendbot(&deployer_g).await;

    let initial_signer = fresh_initial_signer_g();
    let mut salt = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut OsRng, &mut salt);

    let args = DeploymentArgs {
        deployer,
        initial_signer: initial_signer.clone(),
        salt,
        network_passphrase: TESTNET_PASSPHRASE.to_owned(),
        rpc_url: TESTNET_RPC_URL.to_owned(),
        timeout: Duration::from_secs(120),
        fee: ResolvedFeePerOp {
            stroops: 1_000_000,
            percentile_label: "explicit".to_owned(),
        },
        dry_run: false,
        genesis_signer_scval_override: None,
    };

    let result = deploy_smart_account(args, None)
        .await
        .expect("deployment must succeed");
    let deployed_c = result.smart_account.clone();

    // Re-derive from (deployer, salt, passphrase) WITHOUT a network call.
    let recovered_c = derive_smart_account_address(&deployer_g, &salt, TESTNET_PASSPHRASE)
        .expect("recovery derivation must succeed");

    assert_eq!(
        deployed_c, recovered_c,
        "recovering C-strkey from same deployer + salt must yield the same address"
    );
}

/// Deploys a C-account on testnet using the well-known interop deployer.
///
/// The interop deployer must be pre-funded on testnet.
///
/// NOTE: this test races with other simultaneous interop deployments using the
/// same deployer. If `txBadSeq` is returned, retry once. The test is marked
/// `#[ignore]` by default to avoid CI races; run explicitly with `--include-ignored`.
#[tokio::test]
#[ignore = "requires pre-funded interop deployer on testnet; races with parallel interop deployments"]
async fn deploy_smart_account_via_interop_deployer() {
    let interop_g = interop_deployer_pubkey();
    // The well-known interop deployer must be pre-funded; Friendbot it here if needed.
    fund_via_friendbot(&interop_g).await;

    let initial_signer = fresh_initial_signer_g();
    let mut salt = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut OsRng, &mut salt);

    let expected_c = derive_smart_account_address(&interop_g, &salt, TESTNET_PASSPHRASE)
        .expect("pre-derivation must succeed");

    let deployer = stellar_agent_smart_account::deployment::interop_deployer();

    let args = DeploymentArgs {
        deployer,
        initial_signer,
        salt,
        network_passphrase: TESTNET_PASSPHRASE.to_owned(),
        rpc_url: TESTNET_RPC_URL.to_owned(),
        timeout: Duration::from_secs(120),
        fee: ResolvedFeePerOp {
            stroops: 1_000_000,
            percentile_label: "explicit".to_owned(),
        },
        dry_run: false,
        genesis_signer_scval_override: None,
    };

    let result = deploy_smart_account(args, None)
        .await
        .expect("interop deployer deployment must succeed");

    assert_eq!(
        result.smart_account, expected_c,
        "interop deployer deployed address must match pre-derived address"
    );
}
