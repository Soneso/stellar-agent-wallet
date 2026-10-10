//! Testnet acceptance: `stellar-agent smart-account multicall` under a signed
//! V1 policy, through the test-built binary.
//!
//! The surface under test runs as child processes of
//! `env!("CARGO_BIN_EXE_stellar-agent")`: the signed-policy ceremony,
//! `smart-account register-multicall`, and `smart-account multicall`. Fixture
//! deployment uses the library and test-support helpers directly, as the
//! other CLI live suites do.
//!
//! Flow:
//! 1. Generate fresh signer and owner keypairs; fund the signer through
//!    Friendbot.
//! 2. Deploy a fresh smart account whose bootstrap signer is the signer, and
//!    the vendored multicall router from a funded fresh deployer with a random
//!    salt and no constructor arguments.
//! 3. Provision a V1 profile in an isolated home on the headless keyring:
//!    `profile init`, the audit, signer, nonce, owner, and attestation keys,
//!    and a policy allowing `wallet_multicall` on `stellar:testnet`, signed by
//!    the owner.
//! 4. `smart-account register-multicall` records the router.
//! 5. `smart-account multicall` submits three native-SAC `symbol` calls under
//!    rule 0, signed by the enrolled signer, which is also the transaction's
//!    source account. The primary endpoint stands in as the secondary, so the
//!    cross-RPC check compares one provider with itself.
//!
//! Every account and key is fresh per run, so reruns and concurrent runs share
//! neither an account nor a sequence. The router and secondary-endpoint
//! overrides of the library suite do not apply here.
//!
//! Gated behind `testnet-acceptance`:
//!
//! ```text
//! cargo test -p stellar-agent-cli --features testnet-acceptance \
//!   --test smart_account_multicall_cli_testnet_acceptance
//! ```

#![cfg(feature = "testnet-acceptance")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    reason = "test-only; panics, unwraps, and progress output on stderr are acceptable in \
              testnet acceptance tests"
)]

#[path = "live/smart_account_fixtures.rs"]
mod smart_account_fixtures;
#[path = "cli/v1_ceremony.rs"]
mod v1_ceremony;

use rand_core::{OsRng, RngCore as _};
use smart_account_fixtures::{
    TESTNET_PASSPHRASE, TESTNET_RPC_URL, XLM_SAC_TESTNET, deploy_fresh_smart_account,
    fetch_testnet_sequence, fresh_keypair, fund_via_friendbot, sign_testnet_envelope,
    submit_testnet_signed_xdr, wait_until_account_queryable,
};
use stellar_agent_smart_account::multicall::{MULTICALL_WASM, MULTICALL_WASM_SHA256};
use stellar_agent_test_support::testnet_helpers::upload_and_create_contract;
use stellar_xdr::{Limits, ReadXdr as _, ScString, ScVal};
use v1_ceremony::{IsolatedHome, Keypair, policy_document, policy_rule};

/// The profile the ceremony provisions.
const PROFILE: &str = "multicall-cli-acceptance";

/// The symbol the native asset's SAC returns from `symbol`.
const NATIVE_ASSET_SYMBOL: &str = "native";

/// Inner invocations in the bundle.
const INNER_COUNT: usize = 3;

/// The variable the multicall child reads the signer secret from.
const SIGNER_ENV: &str = "MULTICALL_CLI_ACCEPTANCE_SIGNER_SECRET";

/// Deploys the vendored multicall router from a funded fresh deployer with a
/// random salt and no constructor arguments. Returns its C-strkey.
async fn deploy_router() -> String {
    let (deployer_g, deployer_seed, _pk) = fresh_keypair();
    fund_via_friendbot(&deployer_g).await;
    wait_until_account_queryable(&deployer_g).await;
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);
    upload_and_create_contract(
        TESTNET_RPC_URL,
        TESTNET_PASSPHRASE,
        &deployer_g,
        &deployer_seed,
        MULTICALL_WASM,
        salt,
        Vec::new(),
        |account_id| fetch_testnet_sequence(account_id.to_owned()),
        |unsigned_xdr, seed, network_passphrase| {
            sign_testnet_envelope(unsigned_xdr, seed, network_passphrase.to_owned())
        },
        submit_testnet_signed_xdr,
    )
    .await
    .unwrap_or_else(|e| panic!("the vendored multicall router must deploy on testnet: {e}"))
    .contract
}

#[tokio::test]
async fn smart_account_multicall_cli_confirms_three_native_sac_symbol_calls() {
    // ── Step 1: fresh keys; the signer is funded as the source account ──────
    let signer = Keypair::generate();
    let owner = Keypair::generate();
    fund_via_friendbot(signer.public()).await;
    wait_until_account_queryable(signer.public()).await;

    // ── Step 2: the smart account and the router ────────────────────────────
    let smart_account = deploy_fresh_smart_account(signer.public()).await;
    let router = deploy_router().await;
    eprintln!(
        "[multicall-cli] smart account {}, router {}",
        &smart_account[..8],
        &router[..8]
    );

    // ── Step 3: the signed V1 policy ceremony ───────────────────────────────
    let home = IsolatedHome::new();
    home.provision_v1_profile(
        PROFILE,
        &["--rpc-url", TESTNET_RPC_URL],
        &signer,
        &owner,
        &policy_document(
            PROFILE,
            &[policy_rule(
                "wallet_multicall",
                "stellar:testnet",
                "[]",
                "allow",
            )],
        ),
    );

    // ── Step 4: register the router ─────────────────────────────────────────
    let registered = home.run_ok(
        &[
            "smart-account",
            "register-multicall",
            "--profile",
            PROFILE,
            "--network",
            "testnet",
            "--address",
            &router,
            "--wasm-sha256",
            MULTICALL_WASM_SHA256,
        ],
        &[],
    );
    assert_eq!(
        registered["data"]["status"], "registered",
        "register-multicall reports the registration: {registered}"
    );

    // ── Step 5: submit the bundle ───────────────────────────────────────────
    let invocation = format!("{XLM_SAC_TESTNET}:symbol:[]");
    let mut args = vec![
        "smart-account",
        "multicall",
        "--profile",
        PROFILE,
        "--smart-account",
        &smart_account,
        "--rule-id",
        "0",
        "--secondary-rpc-url",
        TESTNET_RPC_URL,
        "--signer-secret-env",
        SIGNER_ENV,
        "--timeout-seconds",
        "120",
    ];
    for _ in 0..INNER_COUNT {
        args.extend(["--invocation", invocation.as_str()]);
    }
    let run = home.run(&args, &[(SIGNER_ENV, signer.secret())]);
    assert_eq!(
        run.code, 0,
        "smart-account multicall must confirm: {} stderr={}",
        run.envelope, run.stderr
    );
    let data = &run.envelope["data"];
    assert_eq!(data["inner_count"], INNER_COUNT, "{}", run.envelope);
    assert!(
        data["bundle_tx_hash"]
            .as_str()
            .is_some_and(|hash| !hash.is_empty()),
        "the envelope carries the bundle's transaction hash: {}",
        run.envelope
    );
    assert!(
        data["ledger"].as_u64().is_some_and(|ledger| ledger > 0),
        "the bundle confirmed on chain: {}",
        run.envelope
    );

    let expected = ScVal::String(ScString(
        NATIVE_ASSET_SYMBOL
            .try_into()
            .expect("the native symbol fits an ScString"),
    ));
    let inner_results = data["inner_results"]
        .as_array()
        .unwrap_or_else(|| panic!("the envelope lists the inner results: {}", run.envelope));
    assert_eq!(inner_results.len(), INNER_COUNT, "{}", run.envelope);
    for inner in inner_results {
        let returned =
            ScVal::from_xdr_base64(inner["return_scval_b64"].as_str().unwrap(), Limits::none())
                .unwrap_or_else(|e| panic!("an inner return value decodes ({e}): {inner}"));
        assert_eq!(
            returned, expected,
            "each inner returns the native asset's symbol: {inner}"
        );
    }
    eprintln!(
        "[multicall-cli] PASS: {INNER_COUNT} symbol calls confirmed at ledger {}",
        data["ledger"]
    );
}
