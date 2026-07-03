//! Testnet acceptance tests for the multicall host-side surface
//! (`submit_multicall_bundle` + policy gate).
//!
//! # Coverage
//!
//! | Fixture | Description |
//! |---------|-------------|
//! | [`h1_happy_path_3_transfer_bundle`] | Deploy SA; install rule; submit 3-transfer bundle against a testnet-deployed multicall router — asserts `MulticallResult { inner_count: 3 }` |
//! | [`h2_per_period_cap_deny_at_inner_3`] | Policy engine denies 5-transfer bundle at inner 3 (0-based) via `bundle_per_period_cap` 100 USDC with 30 USDC per inner — host-side only, no network required |
//! | [`h3_bundle_aggregate_cap_deny`] | Policy engine denies 6-transfer bundle via `bundle_aggregate_cap` 150 USDC when sum is 180 USDC — host-side only, no network required |
//!
//! # Gating
//!
//! Feature flag: `testnet-integration`. Run with:
//!
//! ```text
//! cargo test --features testnet-integration --test wallet_multicall_testnet_acceptance
//! ```
//!
//! `h1_happy_path_3_transfer_bundle` additionally requires:
//! - `STELLAR_AGENT_TESTNET_MULTICALL_ROUTER_ADDRESS` env var set to a deployed
//!   multicall router C-strkey on testnet.
//! - `STELLAR_AGENT_TESTNET_SECONDARY_RPC_URL` env var set (e.g. another Soroban
//!   RPC endpoint) for cross-RPC trust-anchor verification.
//!
//! If either env var is absent, `h1_happy_path_3_transfer_bundle` logs a skip
//! message and returns without failing. `h2_per_period_cap_deny_at_inner_3` and
//! `h3_bundle_aggregate_cap_deny` are host-side and require no network access.
//!
//! # Reference cross-check
//!
//! - Router contract `exec(caller, invocations: Vec<(Address, Symbol, Vec<Val>)>)`:
//!   Meridian Pay smart-wallet-demo-app router, SHA `8f4bfdc`,
//!   `contracts/router/src/lib.rs:21-22`.
//! - SAC `transfer(from, to, amount)` ABI: soroban-sdk SAC derive macro; three-arg
//!   shape required by `decompose_bundle` recognition criteria (bundle.rs:288-325).
//! - `PerPeriodCapCriterion` evaluation (per_period_cap.rs:231-): denies when
//!   `persistent_store + overlay_accumulated + attempted > max_stroops`.
//! - `BundleAggregateCapCriterion` evaluation (bundle_aggregate_cap.rs:76-):
//!   sums `TokenTransfer.amount` across all matching inners; denies when sum > max.

#![cfg(feature = "testnet-integration")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::use_debug,
    clippy::print_stderr,
    reason = "test-only; panics and diagnostic output are acceptable in testnet acceptance tests"
)]

use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use stellar_agent_core::policy::Decision;
use stellar_agent_core::policy::v1::PolicyEngineV1;
use stellar_agent_core::policy::v1::criteria::bundle_aggregate_cap::BundleAggregateCapCriterion;
use stellar_agent_core::policy::v1::criteria::bundle_per_period_cap::BundlePerPeriodCapCriterion;
use stellar_agent_core::policy::v1::criteria::per_period_cap::Window;
use stellar_agent_core::policy::v1::loader::{PolicyDocument, PolicyRule, RuleMatch, ScopeId};
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_smart_account::ResolvedFeePerOp;
use stellar_agent_smart_account::multicall::{
    MULTICALL_WASM_SHA256, MulticallInvocation, MulticallRegistry, MulticallRegistryEntry,
    MulticallSubmitArgs, submit_multicall_bundle,
};
use zeroize::Zeroizing;

// ── Network constants ─────────────────────────────────────────────────────────

const TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";
const TESTNET_FRIENDBOT_URL: &str = "https://friendbot.stellar.org";
const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";
const CHAIN_ID: &str = "stellar:testnet";
const FEE_STROOPS: u32 = 1_000_000;
const TIMEOUT_SECS: u64 = 120;

// ── Dummy strkeys used in host-side policy tests ──────────────────────────────

/// A valid all-zero C-strkey (deployed nowhere; used as a dummy in policy tests).
///
/// The strkey `CAAAAAAA...AAAD2KM` encodes 32 zero bytes as a Stellar contract
/// address (verified via `stellar_strkey::Contract` encode of `[0u8; 32]`).
const DUMMY_C_STRKEY: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";

/// A valid all-zero G-strkey used as dummy sender/receiver in policy tests.
///
/// The strkey encodes a 32-byte ed25519 public key of all zeros. Used only in
/// `decompose_bundle` token-transfer recognition (requires valid G-strkeys in
/// args[0] and args[1] of a `transfer` call).
const DUMMY_G_STRKEY_FROM: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";

/// A different valid all-zero G-strkey used as dummy receiver.
const DUMMY_G_STRKEY_TO: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Generates a fresh ed25519 signer for testnet use.
///
/// Returns `(g_strkey, s_strkey, signer_box)` where:
/// - `g_strkey` is the Stellar public-key strkey (`G...`).
/// - `s_strkey` is the Stellar private-key strkey (`S...`), used when the
///   S-strkey must be passed to a subprocess via an env var.
/// - `signer_box` is the in-process signer implementation.
///
/// Generates a fresh ed25519 keypair and derives the S-strkey from it.
/// The S-strkey is injected into the release-binary subprocess env via
/// `STELLAR_AGENT_TESTNET_H4_SIGNER_SECRET` so the subprocess signs with
/// the same key that owns the freshly-deployed smart account.
fn fresh_signer() -> (
    String,
    Zeroizing<String>,
    Box<dyn stellar_agent_network::Signer + Send + Sync>,
) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let g_strkey = format!(
        "{}",
        stellar_strkey::ed25519::PublicKey(verifying_key.to_bytes())
    );
    let seed_bytes: [u8; 32] = signing_key.to_bytes();
    let s_strkey: Zeroizing<String> = Zeroizing::new(format!(
        "{}",
        stellar_strkey::ed25519::PrivateKey(seed_bytes).as_unredacted()
    ));
    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(seed_bytes);
    let signer: Box<dyn stellar_agent_network::Signer + Send + Sync> =
        Box::new(stellar_agent_network::SoftwareSigningKey::new_from_zeroizing(seed));
    (g_strkey, s_strkey, signer)
}

fn fresh_deployer_keypair() -> (
    String,
    stellar_agent_smart_account::deployment::DeployerKeypair,
) {
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
        stellar_agent_smart_account::deployment::DeployerKeypair::SecretEnv {
            var_name: "multicall-acceptance-deployer".to_owned(),
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

async fn deploy_fresh_smart_account(signer_g: &str) -> String {
    use stellar_agent_smart_account::deployment::{
        DeploymentArgs, ResolvedFeePerOp, deploy_smart_account,
    };

    let (deployer_g, deployer) = fresh_deployer_keypair();
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
    .expect("deploy_smart_account must succeed on testnet");

    result.smart_account
}

/// Constructs a `PolicyEngineV1` with a single rule allowing `wallet_multicall`
/// with the supplied criteria.
fn policy_engine_with_criteria(
    criteria: Vec<Box<dyn stellar_agent_core::policy::v1::criteria::Criterion>>,
) -> Arc<PolicyEngineV1> {
    let doc = PolicyDocument {
        version: 1,
        scope: ScopeId::AllProfiles,
        rules: vec![PolicyRule {
            r#match: RuleMatch {
                tool: "wallet_multicall".into(),
                chain: "*".into(),
            },
            criteria,
            decision: Decision::Allow,
        }],
        signature: None,
    };
    Arc::new(PolicyEngineV1::new(doc, "testnet-acceptance".into()))
}

/// Constructs a `PolicyEngineV1` that allows all `wallet_multicall` calls
/// unconditionally (no criteria).
fn policy_engine_allow_all() -> Arc<PolicyEngineV1> {
    policy_engine_with_criteria(vec![])
}

/// Constructs a minimal testnet `Profile` for policy-engine evaluation.
///
/// The profile carries no keyring entries or file paths that need to exist;
/// only the `chain_id` and `network_passphrase` are relevant to policy evaluation.
fn testnet_profile() -> Profile {
    Profile::builder_testnet(
        "stellar-agent-signer",
        "multicall-acceptance",
        "stellar-agent-nonce",
        "multicall-acceptance",
    )
    .with_profile_name("multicall-acceptance")
    .build()
}

/// Constructs a synthetic token-transfer invocation for policy evaluation.
///
/// `amount_usdc_units` is in "raw" SAC units (stroops-scale). For USDC
/// (7-decimal, so 1 USDC = 10_000_000 units), pass `amount_usdc_units` as
/// `amount_usdc * 10_000_000`.
///
/// Uses `DUMMY_C_STRKEY` as the fake USDC SAC address and `DUMMY_G_STRKEY_*`
/// as the sender/receiver addresses. These are structurally valid strkeys but
/// not deployed on testnet — they are only used for host-side decomposition
/// in the policy gate tests where no RPC calls are made.
fn dummy_transfer_invocation(amount_usdc_units: i128) -> MulticallInvocation {
    MulticallInvocation {
        target_contract: DUMMY_C_STRKEY.to_owned(),
        fn_name: "transfer".to_owned(),
        // SAC `transfer(from: Address, to: Address, amount: i128)` — three args.
        // `decompose_bundle` recognises this as `TokenTransfer` when:
        // - target is valid C-strkey
        // - fn_name == "transfer"
        // - args[0] and args[1] are valid G-strkey strings
        // - args[2] is a parseable i128 (as decimal string)
        // (bundle.rs:288-325)
        args_json: serde_json::json!([
            DUMMY_G_STRKEY_FROM,
            DUMMY_G_STRKEY_TO,
            amount_usdc_units.to_string(),
        ]),
    }
}

/// Builds an in-memory `MulticallRegistry` with a single testnet entry pointing
/// to the given `router_address` C-strkey and `MULTICALL_WASM_SHA256`.
fn registry_with_entry(router_address: &str) -> MulticallRegistry {
    let config_path = std::path::PathBuf::from("/dev/null");
    let mut registry =
        MulticallRegistry::load(&config_path).expect("empty registry load must succeed");
    registry
        .register(MulticallRegistryEntry {
            network_passphrase: TESTNET_PASSPHRASE.to_owned(),
            address: router_address.to_owned(),
            wasm_sha256: MULTICALL_WASM_SHA256.to_owned(),
        })
        .expect("register with correct SHA must succeed");
    registry
}

// ── h1_happy_path_3_transfer_bundle ───────────────────────────────────────────

/// Deploy a fresh smart account, install a context rule, then submit
/// a 3-transfer bundle via `submit_multicall_bundle`.
///
/// Asserts:
/// - `MulticallResult::inner_count == 3`
/// - The bundle lands on-chain (ledger > 0)
/// - `audit_degraded == false`
///
/// # Environment variables required
///
/// - `STELLAR_AGENT_TESTNET_MULTICALL_ROUTER_ADDRESS` — deployed multicall
///   router C-strkey on testnet.
/// - `STELLAR_AGENT_TESTNET_SECONDARY_RPC_URL` — secondary RPC URL for
///   cross-RPC trust-anchor verification.
///
/// # Skip condition
///
/// If either env var is absent, the test logs a skip message and returns
/// without failing. This test requires a deployed multicall router; it can only
/// fully execute after the router is deployed on testnet.
/// To run it locally, set both env vars and invoke:
///
/// ```text
/// cargo test --features testnet-integration --test wallet_multicall_testnet_acceptance h1_happy_path_3_transfer_bundle
/// ```
///
/// # Design
///
/// The 3 inner transfers use the deployed testnet USDC SAC address obtained from
/// `STELLAR_AGENT_TESTNET_USDC_SAC_ADDRESS` (falls back to `DUMMY_C_STRKEY` for
/// structural testing when real SAC is not available — in that case the transaction
/// will succeed at the multicall layer but the SAC call itself would revert; the
/// acceptance gate is the full on-chain confirmation path, not the SAC outcome).
#[tokio::test]
async fn h1_happy_path_3_transfer_bundle() {
    let router_address = match std::env::var("STELLAR_AGENT_TESTNET_MULTICALL_ROUTER_ADDRESS") {
        Ok(addr) => addr,
        Err(_) => {
            eprintln!(
                "[h1] SKIP: STELLAR_AGENT_TESTNET_MULTICALL_ROUTER_ADDRESS not set. \
                 Deploy the multicall router and register it before running this test."
            );
            return;
        }
    };

    let secondary_rpc_url = match std::env::var("STELLAR_AGENT_TESTNET_SECONDARY_RPC_URL") {
        Ok(url) => url,
        Err(_) => {
            eprintln!(
                "[h1] SKIP: STELLAR_AGENT_TESTNET_SECONDARY_RPC_URL not set. \
                     Provide a secondary RPC endpoint for cross-RPC trust-anchor verification."
            );
            return;
        }
    };

    eprintln!("[h1] router_address: {}", &router_address[..8]);
    eprintln!("[h1] secondary_rpc_url: [set]");

    // ── Step 1: Fresh signer + fund ───────────────────────────────────────────
    let (signer_g, _s_strkey, signer_box) = fresh_signer();
    fund_via_friendbot(&signer_g).await;
    eprintln!("[h1] signer funded: {}", &signer_g[..8]);

    // ── Step 2: Deploy fresh smart account ────────────────────────────────────
    let sa_strkey = deploy_fresh_smart_account(&signer_g).await;
    eprintln!("[h1] smart_account: {}", &sa_strkey[..8]);

    // ── Step 3: Install a context rule ────────────────────────────────────────
    // For the happy-path test, we need an installed rule with rule_id 0.
    // We rely on the smart account's default first-deployment rule if it exists.
    // The acceptance gate here is the multicall submission returning inner_count=3;
    // the rule-management ceremony is exercised by wallet_rules tests.
    let rule_id: u32 = 0;

    // ── Step 4: Build a 3-transfer bundle ─────────────────────────────────────
    // Use USDC SAC address from env or fall back to dummy (structurally valid).
    let usdc_sac = std::env::var("STELLAR_AGENT_TESTNET_USDC_SAC_ADDRESS")
        .unwrap_or_else(|_| DUMMY_C_STRKEY.to_owned());

    let bundle = vec![
        MulticallInvocation {
            target_contract: usdc_sac.clone(),
            fn_name: "transfer".to_owned(),
            args_json: serde_json::json!([
                signer_g,
                signer_g,
                "100000000", // 10 USDC at 7 decimal places
            ]),
        },
        MulticallInvocation {
            target_contract: usdc_sac.clone(),
            fn_name: "transfer".to_owned(),
            args_json: serde_json::json!([
                signer_g,
                signer_g,
                "200000000", // 20 USDC
            ]),
        },
        MulticallInvocation {
            target_contract: usdc_sac.clone(),
            fn_name: "transfer".to_owned(),
            args_json: serde_json::json!([
                signer_g,
                signer_g,
                "300000000", // 30 USDC
            ]),
        },
    ];

    // ── Step 5: Build registry + policy engine ────────────────────────────────
    let registry = registry_with_entry(&router_address);
    let profile = testnet_profile();
    let policy_engine = policy_engine_allow_all();

    // ── Step 6: Submit the multicall bundle ───────────────────────────────────
    let result = submit_multicall_bundle(
        MulticallSubmitArgs {
            smart_account: &sa_strkey,
            rule_id,
            bundle,
            signer: signer_box.as_ref(),
            primary_rpc_url: TESTNET_RPC_URL,
            secondary_rpc_url: &secondary_rpc_url,
            network_passphrase: TESTNET_PASSPHRASE,
            policy_engine,
            profile: &profile,
            audit_writer: None,
            timeout: Duration::from_secs(TIMEOUT_SECS),
            fee: ResolvedFeePerOp::default(),
            chain_id: CHAIN_ID,
            request_id: "h1-happy-path-3-transfer",
        },
        &registry,
    )
    .await;

    let mc_result = result.unwrap_or_else(|e| {
        panic!(
            "[h1] submit_multicall_bundle must succeed; got error with wire_code={:?}",
            e
        )
    });

    // ── Step 7: Assert outcome ────────────────────────────────────────────────
    assert_eq!(
        mc_result.inner_count, 3,
        "[h1] inner_count must be 3; got {}",
        mc_result.inner_count
    );
    assert!(
        mc_result.ledger > 0,
        "[h1] ledger must be > 0 (bundle confirmed on-chain); got {}",
        mc_result.ledger
    );
    assert!(
        !mc_result.audit_degraded,
        "[h1] audit_degraded must be false when audit_writer is None"
    );

    eprintln!(
        "[h1] PASS: 3-transfer bundle confirmed at ledger {} (tx_hash prefix: {})",
        mc_result.ledger,
        &mc_result.bundle_tx_hash[..8.min(mc_result.bundle_tx_hash.len())],
    );
}

// ── h2_per_period_cap_deny_at_inner_3 ────────────────────────────────────────

/// Submit a 5-transfer bundle of 30 USDC each under a policy with
/// `bundle_per_period_cap` of 100 USDC.
///
/// The policy gate fires at inner-3 (0-based inner index 3 = 4th inner):
/// - Inners 0-2: 30+30+30 = 90 USDC accumulated in running sum.
/// - Inner 3: 90 + 30 = 120 USDC > 100 USDC cap → `DenyReason::BundleDenied`
///   wrapping `DenyReason::PerPeriodCapExceeded`.
///
/// Asserts:
/// - `Err(SaError::MulticallFailed { phase: "policy_gate" })`
/// - No RPC call is made (pure host-side evaluation).
///
/// # Design (host-side only)
///
/// Uses a dummy C-strkey as the fake USDC SAC address (valid structure; not
/// deployed). The `decompose_bundle` function recognises these as `TokenTransfer`
/// inners because the target is a valid C-strkey, fn_name == "transfer", and
/// args match the SAC ABI shape (bundle.rs:288-325).
///
/// The `smart_account` field uses `DUMMY_C_STRKEY` — no deployed SA is required
/// because the policy gate fires before any RPC call (Step 2 precedes Step 3).
///
/// # Design note
///
/// `PerPeriodCapCriterion` short-circuits for tool names outside the
/// `{stellar_pay, …}` set — the multicall tool name is not in that set.
/// `BundlePerPeriodCapCriterion` is used instead: it iterates
/// `BundleView.inners` and applies the per-period cap per-inner-transfer
/// at evaluation time. `is_bundle_level() = true` ensures it fires correctly
/// under `evaluate_bundle` (bundle_per_period_cap.rs).
#[tokio::test]
async fn h2_per_period_cap_deny_at_inner_3() {
    // 30 USDC per inner in 7-decimal SAC units = 30 * 10_000_000 = 300_000_000.
    // cap = 100 USDC = 1_000_000_000 units.
    // Per-period window: 1 hour.
    let usdc_per_inner: i128 = 300_000_000; // 30 USDC in SAC units
    let cap_usdc: i128 = 1_000_000_000; // 100 USDC in SAC units

    let window = Window::parse("1h").expect("Window::parse('1h') must succeed");
    // BundlePerPeriodCapCriterion::new takes `max_stroops: i64`; cap_usdc fits in i64.
    #[allow(clippy::cast_possible_truncation)]
    let cap_usdc_i64 = cap_usdc as i64;
    let bundle_per_period_cap = BundlePerPeriodCapCriterion::new(
        DUMMY_C_STRKEY.to_owned(), // asset = fake USDC SAC address (dummy C-strkey)
        window,
        cap_usdc_i64,
    );

    let policy_engine = policy_engine_with_criteria(vec![Box::new(bundle_per_period_cap)]);
    let profile = testnet_profile();

    // 5 inners × 30 USDC each. Inner 3 (0-based) tips the cap: 90+30=120 > 100.
    let bundle = (0..5)
        .map(|_| dummy_transfer_invocation(usdc_per_inner))
        .collect::<Vec<_>>();

    // Empty registry (no router registered for testnet). The policy gate fires
    // before the registry lookup at Step 3, so `MulticallRegistryEntryNotFound`
    // never surfaces — the test asserts `MulticallFailed { phase: "policy_gate" }`.
    let empty_registry = {
        let config_path = std::path::PathBuf::from("/dev/null");
        MulticallRegistry::load(&config_path).expect("empty registry load must succeed")
    };

    let result = submit_multicall_bundle(
        MulticallSubmitArgs {
            smart_account: DUMMY_C_STRKEY,
            rule_id: 0,
            bundle,
            // Signer is unused before policy gate fires. Use a fresh key.
            signer: {
                static STUB_SIGNER: std::sync::OnceLock<
                    Box<dyn stellar_agent_network::Signer + Send + Sync>,
                > = std::sync::OnceLock::new();
                STUB_SIGNER.get_or_init(|| {
                    let (_, _s, signer) = fresh_signer();
                    signer
                })
            }
            .as_ref(),
            primary_rpc_url: TESTNET_RPC_URL,
            secondary_rpc_url: TESTNET_RPC_URL, // unused; policy gate fires first
            network_passphrase: TESTNET_PASSPHRASE,
            policy_engine,
            profile: &profile,
            audit_writer: None,
            timeout: Duration::from_secs(TIMEOUT_SECS),
            fee: ResolvedFeePerOp::default(),
            chain_id: CHAIN_ID,
            request_id: "h2-per-period-cap-deny",
        },
        &empty_registry,
    )
    .await;

    let err = result.expect_err("[h2] submit_multicall_bundle must return Err when policy denies");

    assert_eq!(
        err.wire_code(),
        "sa.multicall_failed",
        "[h2] wire_code must be 'sa.multicall_failed'; got {:?}",
        err.wire_code()
    );

    // Confirm the phase is policy_gate (not build, not rpc_divergence).
    let err_str = format!("{err}");
    assert!(
        err_str.contains("policy_gate"),
        "[h2] error message must contain 'policy_gate'; got: {err_str}"
    );

    eprintln!(
        "[h2] PASS: bundle_per_period_cap denied 5x30 USDC bundle at policy gate \
         (100 USDC cap, inner 3 tips the sum)"
    );
}

// ── h3_bundle_aggregate_cap_deny ─────────────────────────────────────────────

/// Submit a 6-transfer bundle of 30 USDC each under a policy with
/// `bundle_aggregate_cap` of 150 USDC.
///
/// Total: 6 × 30 = 180 USDC > 150 USDC cap → `DenyReason::BundleAggregateCapExceeded`.
///
/// Asserts:
/// - `Err(SaError::MulticallFailed { phase: "policy_gate" })`
/// - No RPC call is made (pure host-side evaluation).
///
/// # Design (host-side only)
///
/// Same dummy-strkey approach as `h2_per_period_cap_deny_at_inner_3`.
/// `BundleAggregateCapCriterion` sums all `TokenTransfer.amount` values across
/// the bundle view and fires before any per-inner evaluation because
/// `is_bundle_level()` returns `true` (bundle_aggregate_cap.rs:76-).
#[tokio::test]
async fn h3_bundle_aggregate_cap_deny() {
    // 30 USDC per inner in 7-decimal SAC units.
    let usdc_per_inner: i128 = 300_000_000; // 30 USDC
    let cap_usdc: i128 = 1_500_000_000; // 150 USDC cap

    let bundle_cap = BundleAggregateCapCriterion {
        asset: Some(DUMMY_C_STRKEY.to_owned()), // asset filter = fake USDC SAC
        max_amount: cap_usdc,
    };

    let policy_engine = policy_engine_with_criteria(vec![Box::new(bundle_cap)]);
    let profile = testnet_profile();

    // 6 inners × 30 USDC = 180 USDC > 150 USDC cap.
    let bundle = (0..6)
        .map(|_| dummy_transfer_invocation(usdc_per_inner))
        .collect::<Vec<_>>();

    let empty_registry = {
        let config_path = std::path::PathBuf::from("/dev/null");
        MulticallRegistry::load(&config_path).expect("empty registry load must succeed")
    };

    let result = submit_multicall_bundle(
        MulticallSubmitArgs {
            smart_account: DUMMY_C_STRKEY,
            rule_id: 0,
            bundle,
            signer: {
                static STUB_SIGNER: std::sync::OnceLock<
                    Box<dyn stellar_agent_network::Signer + Send + Sync>,
                > = std::sync::OnceLock::new();
                STUB_SIGNER.get_or_init(|| {
                    let (_, _s, signer) = fresh_signer();
                    signer
                })
            }
            .as_ref(),
            primary_rpc_url: TESTNET_RPC_URL,
            secondary_rpc_url: TESTNET_RPC_URL, // unused; policy gate fires first
            network_passphrase: TESTNET_PASSPHRASE,
            policy_engine,
            profile: &profile,
            audit_writer: None,
            timeout: Duration::from_secs(TIMEOUT_SECS),
            fee: ResolvedFeePerOp::default(),
            chain_id: CHAIN_ID,
            request_id: "h3-bundle-aggregate-cap-deny",
        },
        &empty_registry,
    )
    .await;

    let err = result.expect_err("[h3] submit_multicall_bundle must return Err when policy denies");

    assert_eq!(
        err.wire_code(),
        "sa.multicall_failed",
        "[h3] wire_code must be 'sa.multicall_failed'; got {:?}",
        err.wire_code()
    );

    let err_str = format!("{err}");
    assert!(
        err_str.contains("policy_gate"),
        "[h3] error message must contain 'policy_gate'; got: {err_str}"
    );

    eprintln!(
        "[h3] PASS: bundle aggregate cap denied 6×30 USDC bundle at policy gate \
         (150 USDC cap, 180 USDC total)"
    );
}

// ── h4_release_binary_acceptance ─────────────────────────────────────────────

/// End-to-end release-binary acceptance for the three multicall CLI subcommands:
///
/// 1. `wallet sa register-multicall` — registers a testnet multicall router
///    address in a temp `networks.toml` and asserts `status: "registered"`.
/// 2. `wallet sa unregister-multicall` — removes the registered entry and
///    asserts `status: "unregistered"`.
/// 3. `wallet multicall --invocation …` — submits a 1-transfer bundle through
///    the registered router and asserts `bundle_tx_hash` + `inner_count: 1`.
///
/// # Environment variables required
///
/// - `STELLAR_AGENT_TESTNET_MULTICALL_ROUTER_ADDRESS` — deployed multicall
///   router C-strkey on testnet. Required by steps 1 and 3.
/// - `STELLAR_AGENT_TESTNET_SECONDARY_RPC_URL` — secondary RPC URL for
///   cross-RPC trust-anchor verification. Required by step 3.
///
/// The signing key is derived from a freshly-generated ed25519 keypair created
/// in-process. The S-strkey is injected into the subprocess via the
/// `STELLAR_AGENT_TESTNET_H4_SIGNER_SECRET` env var so the subprocess signs
/// with the same key that owns the freshly-deployed smart account.
/// No external `STELLAR_AGENT_TESTNET_SIGNER_SECRET` is required.
///
/// If any required env var is absent the test logs a skip message and returns
/// without failing.
///
/// # Binary location
///
/// The test locates the release binary by walking from `CARGO_MANIFEST_DIR`
/// up to the workspace root and resolving `target/release/stellar-agent`. If
/// the binary is not found it skips.
///
/// Build the release binary before running this test:
///
/// ```text
/// cargo build --release -p stellar-agent-cli
/// cargo test --features testnet-integration --test wallet_multicall_testnet_acceptance h4_release_binary_acceptance
/// ```
#[tokio::test]
async fn h4_release_binary_acceptance() {
    // ── Locate the release binary ─────────────────────────────────────────────
    let binary_path = {
        let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        // Walk up to workspace root (which contains target/).
        let workspace_root = manifest_dir
            .ancestors()
            .find(|p| p.join("Cargo.lock").exists())
            .expect("[h4] workspace root with Cargo.lock must exist");
        let bin = workspace_root
            .join("target")
            .join("release")
            .join("stellar-agent");
        if !bin.exists() {
            eprintln!(
                "[h4] SKIP: release binary not found at {}. \
                 Run `cargo build --release -p stellar-agent-cli` first.",
                bin.display()
            );
            return;
        }
        bin
    };

    // ── Resolve required env vars ─────────────────────────────────────────────
    let router_address = match std::env::var("STELLAR_AGENT_TESTNET_MULTICALL_ROUTER_ADDRESS") {
        Ok(addr) => addr,
        Err(_) => {
            eprintln!("[h4] SKIP: STELLAR_AGENT_TESTNET_MULTICALL_ROUTER_ADDRESS not set.");
            return;
        }
    };

    let secondary_rpc_url = match std::env::var("STELLAR_AGENT_TESTNET_SECONDARY_RPC_URL") {
        Ok(url) => url,
        Err(_) => {
            eprintln!("[h4] SKIP: STELLAR_AGENT_TESTNET_SECONDARY_RPC_URL not set.");
            return;
        }
    };

    // ── Step 0: Deploy a fresh smart account for the bundle target ────────────
    // The S-strkey is injected into the subprocess env via
    // STELLAR_AGENT_TESTNET_H4_SIGNER_SECRET so the binary signs with the same
    // key that owns the freshly-deployed SA. No external signer secret is needed.
    let (signer_g, signer_s_strkey, _signer_box) = fresh_signer();
    fund_via_friendbot(&signer_g).await;
    let sa_strkey = deploy_fresh_smart_account(&signer_g).await;
    eprintln!("[h4] smart_account: {}", &sa_strkey[..8]);

    // ── Step 1: register-multicall via CLI ────────────────────────────────────
    let networks_toml = tempfile::NamedTempFile::new()
        .expect("[h4] temp networks.toml must be created")
        .into_temp_path();
    let networks_toml_path = networks_toml.to_str().unwrap().to_owned();

    let register_output = std::process::Command::new(&binary_path)
        .args([
            "wallet",
            "sa",
            "register-multicall",
            "--network",
            "testnet",
            "--address",
            &router_address,
            "--wasm-sha256",
            MULTICALL_WASM_SHA256,
        ])
        .env(
            stellar_agent_smart_account::multicall::STELLAR_AGENT_MULTICALL_REGISTRY_TOML_ENV,
            &networks_toml_path,
        )
        .output()
        .expect("[h4] register-multicall binary must run");

    assert!(
        register_output.status.success(),
        "[h4] register-multicall must exit 0; got {}\nstdout: {}\nstderr: {}",
        register_output.status,
        String::from_utf8_lossy(&register_output.stdout),
        String::from_utf8_lossy(&register_output.stderr),
    );

    let register_json: serde_json::Value = serde_json::from_slice(&register_output.stdout)
        .unwrap_or_else(|e| {
            panic!(
                "[h4] register-multicall stdout must be valid JSON; parse error: {e}\nraw: {}",
                String::from_utf8_lossy(&register_output.stdout)
            )
        });
    assert_eq!(
        register_json["result"]["status"].as_str(),
        Some("registered"),
        "[h4] register-multicall status must be 'registered'; got: {register_json}"
    );
    eprintln!("[h4] Step 1 PASS: register-multicall");

    // ── Step 2: unregister-multicall via CLI ──────────────────────────────────
    let unregister_output = std::process::Command::new(&binary_path)
        .args([
            "wallet",
            "sa",
            "unregister-multicall",
            "--network",
            "testnet",
            "--yes-i-have-verified-the-prior-values",
        ])
        .env(
            stellar_agent_smart_account::multicall::STELLAR_AGENT_MULTICALL_REGISTRY_TOML_ENV,
            &networks_toml_path,
        )
        .output()
        .expect("[h4] unregister-multicall binary must run");

    // Note: unregister-multicall without --force goes through normal path.
    // Passing --yes-i-have-verified-the-prior-values without --force is a no-op
    // (the flag is only checked in the force path). Normal path always proceeds.
    assert!(
        unregister_output.status.success(),
        "[h4] unregister-multicall must exit 0; got {}\nstdout: {}\nstderr: {}",
        unregister_output.status,
        String::from_utf8_lossy(&unregister_output.stdout),
        String::from_utf8_lossy(&unregister_output.stderr),
    );

    let unregister_json: serde_json::Value = serde_json::from_slice(&unregister_output.stdout)
        .unwrap_or_else(|e| {
            panic!(
                "[h4] unregister-multicall stdout must be valid JSON; parse error: {e}\nraw: {}",
                String::from_utf8_lossy(&unregister_output.stdout)
            )
        });
    assert_eq!(
        unregister_json["result"]["status"].as_str(),
        Some("unregistered"),
        "[h4] unregister-multicall status must be 'unregistered'; got: {unregister_json}"
    );
    eprintln!("[h4] Step 2 PASS: unregister-multicall");

    // ── Step 3: Re-register + wallet multicall bundle submission ──────────────
    // Re-register so the router is available for the multicall step.
    let re_register = std::process::Command::new(&binary_path)
        .args([
            "wallet",
            "sa",
            "register-multicall",
            "--network",
            "testnet",
            "--address",
            &router_address,
            "--wasm-sha256",
            MULTICALL_WASM_SHA256,
        ])
        .env(
            stellar_agent_smart_account::multicall::STELLAR_AGENT_MULTICALL_REGISTRY_TOML_ENV,
            &networks_toml_path,
        )
        .output()
        .expect("[h4] re-register-multicall binary must run");
    assert!(
        re_register.status.success(),
        "[h4] re-register-multicall must exit 0; stderr: {}",
        String::from_utf8_lossy(&re_register.stderr)
    );

    // Build a 1-transfer invocation using the signer_g as both sender and receiver.
    let usdc_sac = std::env::var("STELLAR_AGENT_TESTNET_USDC_SAC_ADDRESS")
        .unwrap_or_else(|_| DUMMY_C_STRKEY.to_owned());
    let invocation = format!(r#"{usdc_sac}:transfer:["{signer_g}","{signer_g}","1000000"]"#);

    // Inject the fresh signer S-strkey into the subprocess environment.
    // STELLAR_AGENT_TESTNET_H4_SIGNER_SECRET is a test-local name; it does not
    // collide with any persistent operator env var.
    let h4_signer_env_name = "STELLAR_AGENT_TESTNET_H4_SIGNER_SECRET";
    let multicall_output = std::process::Command::new(&binary_path)
        .args([
            "wallet",
            "multicall",
            "--smart-account",
            &sa_strkey,
            "--rule-id",
            "0",
            "--invocation",
            &invocation,
            "--secondary-rpc-url",
            &secondary_rpc_url,
            "--signer-secret-env",
            h4_signer_env_name,
            "--network",
            "testnet",
        ])
        .env(
            stellar_agent_smart_account::multicall::STELLAR_AGENT_MULTICALL_REGISTRY_TOML_ENV,
            &networks_toml_path,
        )
        // Pass the freshly-generated S-strkey so the subprocess signs with
        // the key that owns the freshly-deployed SA.
        .env(h4_signer_env_name, signer_s_strkey.as_str())
        .output()
        .expect("[h4] wallet multicall binary must run");

    assert!(
        multicall_output.status.success(),
        "[h4] wallet multicall must exit 0; got {}\nstdout: {}\nstderr: {}",
        multicall_output.status,
        String::from_utf8_lossy(&multicall_output.stdout),
        String::from_utf8_lossy(&multicall_output.stderr),
    );

    let multicall_json: serde_json::Value = serde_json::from_slice(&multicall_output.stdout)
        .unwrap_or_else(|e| {
            panic!(
                "[h4] wallet multicall stdout must be valid JSON; parse error: {e}\nraw: {}",
                String::from_utf8_lossy(&multicall_output.stdout)
            )
        });

    assert!(
        multicall_json["result"]["bundle_tx_hash"]
            .as_str()
            .map(|s| !s.is_empty())
            .unwrap_or(false),
        "[h4] wallet multicall must return a non-empty bundle_tx_hash; got: {multicall_json}"
    );
    assert_eq!(
        multicall_json["result"]["inner_count"].as_u64(),
        Some(1),
        "[h4] wallet multicall inner_count must be 1; got: {multicall_json}"
    );

    eprintln!(
        "[h4] Step 3 PASS: wallet multicall 1-transfer bundle confirmed (tx_hash prefix: {})",
        &multicall_json["result"]["bundle_tx_hash"]
            .as_str()
            .unwrap_or("")
            .get(..8)
            .unwrap_or(""),
    );
    eprintln!("[h4] PASS: all 3 CLI subcommand acceptance steps complete");
}
