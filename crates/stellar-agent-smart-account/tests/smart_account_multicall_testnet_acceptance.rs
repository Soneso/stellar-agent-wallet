//! Testnet acceptance tests for the multicall host-side surface
//! (`submit_multicall_bundle` + policy gate).
//!
//! # Coverage
//!
//! | Fixture | Description |
//! |---------|-------------|
//! | [`h1_three_native_sac_symbol_calls_confirm`] | Deploy the vendored router and a smart account; submit three native-SAC `symbol` calls under rule 0; asserts `MulticallResult { inner_count: 3 }`, on-chain confirmation, and each inner returning the native asset's symbol |
//! | [`h2_per_period_cap_deny_at_inner_3`] | Policy engine denies 5-transfer bundle at inner 3 (0-based) via `bundle_per_period_cap` 100 USDC with 30 USDC per inner — host-side only, no network required |
//! | [`h3_bundle_aggregate_cap_deny`] | Policy engine denies 6-transfer bundle via `bundle_aggregate_cap` 150 USDC when sum is 180 USDC — host-side only, no network required |
//! | [`h5_bundle_under_a_rule_other_than_0_checks_its_signer_set`] | Install a rule other than 0 and submit three native-SAC `symbol` calls under it, which the submit path checks against the rule's signer-set state. After an out-of-band `signers add`, the next bundle refuses with `sa.signer_set_diverged` at phase `policy_gate` |
//!
//! The live bundles call the native asset's SAC `symbol`, which takes no
//! arguments and requires no authorization. They cover router invocation,
//! the wallet's authorization of `exec`, and the router's return values; a
//! typed SAC transfer is outside their coverage.
//!
//! # Gating
//!
//! Feature flag: `testnet-integration`. Run with:
//!
//! ```text
//! cargo test --features testnet-integration --test smart_account_multicall_testnet_acceptance
//! ```
//!
//! `h1_three_native_sac_symbol_calls_confirm` and
//! `h5_bundle_under_a_rule_other_than_0_checks_its_signer_set` need only
//! testnet RPC and Friendbot. Each deploys the vendored router
//! ([`MULTICALL_WASM`]) from a funded ephemeral deployer with a fresh salt,
//! unless `STELLAR_AGENT_TESTNET_MULTICALL_ROUTER_ADDRESS` names a deployed
//! router C-strkey. `STELLAR_AGENT_TESTNET_SECONDARY_RPC_URL` optionally names
//! a second Soroban RPC endpoint for the cross-RPC trust-anchor check; without
//! it the primary endpoint stands in as the secondary, so the check compares
//! one provider with itself. An empty variable counts as unset. An override
//! that does not parse, and a router deployment that fails, fail the test.
//! `h2_per_period_cap_deny_at_inner_3` and `h3_bundle_aggregate_cap_deny` are
//! host-side and require no network access.
//!
//! The CLI's on-chain multicall coverage lives in the `stellar-agent-cli`
//! suite `smart_account_multicall_cli_testnet_acceptance`.
//!
//! # Reference cross-check
//!
//! - Router contract `exec(caller, invocations: Vec<(Address, Symbol, Vec<Val>)>)`:
//!   the in-tree router contract `contracts/multicall-router/src/lib.rs`.
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

mod common;
#[path = "common/pin_check_manager.rs"]
mod pin_check_manager;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use stellar_agent_core::audit_log::entry::AuditEntry;
use stellar_agent_core::audit_log::schema::EventKind;
use stellar_agent_core::audit_log::test_helpers::verified_audit_entries;
use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_core::policy::Decision;
use stellar_agent_core::policy::v1::PolicyEngineV1;
use stellar_agent_core::policy::v1::criteria::bundle_aggregate_cap::BundleAggregateCapCriterion;
use stellar_agent_core::policy::v1::criteria::bundle_per_period_cap::BundlePerPeriodCapCriterion;
use stellar_agent_core::policy::v1::criteria::per_period_cap::Window;
use stellar_agent_core::policy::v1::loader::{PolicyDocument, PolicyRule, RuleMatch, ScopeId};
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_core::smart_account::rule_id::ContextRuleId;
use stellar_agent_smart_account::managers::rules::{
    ContextRuleDefinition, ContextRuleSignerInput, RuleContext, parse_c_strkey_to_smart_account,
    parse_g_strkey_to_signer_address,
};
use stellar_agent_smart_account::managers::signers::{
    PreviousBaseline, build_delegated_signer_scval,
};
use stellar_agent_smart_account::multicall::{
    MULTICALL_WASM, MULTICALL_WASM_SHA256, MulticallInnerResult, MulticallInvocation,
    MulticallRegistry, MulticallRegistryEntry, MulticallSubmitArgs, submit_multicall_bundle,
};
use stellar_agent_smart_account::test_helpers::{
    rule_manager_for_tests, signers_manager_for_tests,
};
use stellar_agent_smart_account::{ResolvedFeePerOp, SaError};
use stellar_xdr::{Limits, ReadXdr as _, ScString, ScVal};
use zeroize::Zeroizing;

use common::{
    TESTNET_PASSPHRASE, TESTNET_RPC_URL, XLM_SAC_TESTNET, fund_via_friendbot,
    upload_and_create_contract,
};

// ── Network constants ─────────────────────────────────────────────────────────

const CHAIN_ID: &str = "stellar:testnet";
const FEE_STROOPS: u32 = 1_000_000;
const TIMEOUT_SECS: u64 = 120;

/// Names a deployed multicall router C-strkey that replaces the per-test
/// deployment.
const ROUTER_ADDRESS_ENV: &str = "STELLAR_AGENT_TESTNET_MULTICALL_ROUTER_ADDRESS";

/// Names a second Soroban RPC endpoint for the cross-RPC trust-anchor check.
const SECONDARY_RPC_URL_ENV: &str = "STELLAR_AGENT_TESTNET_SECONDARY_RPC_URL";

/// The symbol the native asset's SAC returns from `symbol`.
const NATIVE_ASSET_SYMBOL: &str = "native";

/// Inner invocations in each live bundle.
const LIVE_INNER_COUNT: usize = 3;

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
/// Returns `(g_strkey, signer_box)`: the Stellar public-key strkey (`G...`)
/// and the in-process signer implementation.
fn fresh_signer() -> (String, Box<dyn stellar_agent_network::Signer + Send + Sync>) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let g_strkey = format!(
        "{}",
        stellar_strkey::ed25519::PublicKey(signing_key.verifying_key().to_bytes())
    );
    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(signing_key.to_bytes());
    let signer: Box<dyn stellar_agent_network::Signer + Send + Sync> =
        Box::new(stellar_agent_network::SoftwareSigningKey::new_from_zeroizing(seed));
    (g_strkey, signer)
}

fn fresh_deployer_keypair() -> (
    String,
    stellar_agent_smart_account::deployment::DeployerKeypair,
) {
    let (g_strkey, signer) = fresh_signer();
    (
        g_strkey,
        stellar_agent_smart_account::deployment::DeployerKeypair::SecretEnv {
            var_name: "multicall-acceptance-deployer".to_owned(),
            signer,
        },
    )
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
            genesis_signer_scval_override: None,
        },
        None,
    )
    .await
    .expect("deploy_smart_account must succeed on testnet");

    result.smart_account
}

/// The value of `name`, or `None` when it is unset or empty.
fn env_override(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

/// The router the live bundles go through: the C-strkey named by
/// [`ROUTER_ADDRESS_ENV`], or a fresh deployment of [`MULTICALL_WASM`] from a
/// funded ephemeral deployer with a random salt and no constructor
/// arguments.
///
/// # Panics
///
/// Panics when the override is not a C-strkey or the deployment fails.
async fn multicall_router() -> String {
    if let Some(address) = env_override(ROUTER_ADDRESS_ENV) {
        assert!(
            stellar_strkey::Contract::from_string(&address).is_ok(),
            "{ROUTER_ADDRESS_ENV} must be a contract C-strkey"
        );
        return address;
    }
    let signing_key = SigningKey::generate(&mut OsRng);
    let deployer_g = format!(
        "{}",
        stellar_strkey::ed25519::PublicKey(signing_key.verifying_key().to_bytes())
    );
    let deployer_seed: Zeroizing<[u8; 32]> = Zeroizing::new(signing_key.to_bytes());
    fund_via_friendbot(&deployer_g).await;
    let mut salt = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut OsRng, &mut salt);
    upload_and_create_contract(
        MULTICALL_WASM,
        &deployer_g,
        &deployer_seed,
        salt,
        Vec::new(),
    )
    .await
    .unwrap_or_else(|e| panic!("the vendored multicall router must deploy on testnet: {e}"))
    .contract
}

/// The secondary endpoint of the cross-RPC trust-anchor check: the URL named
/// by [`SECONDARY_RPC_URL_ENV`], or the primary endpoint. The primary
/// standing in as the secondary does not demonstrate verification against an
/// independent provider.
///
/// # Panics
///
/// Panics when the override is not an `http` or `https` URL.
fn secondary_rpc_url() -> String {
    match env_override(SECONDARY_RPC_URL_ENV) {
        Some(url) => {
            let parsed = reqwest::Url::parse(&url)
                .unwrap_or_else(|e| panic!("{SECONDARY_RPC_URL_ENV} must be a URL: {e}"));
            assert!(
                matches!(parsed.scheme(), "http" | "https"),
                "{SECONDARY_RPC_URL_ENV} must be an http or https URL"
            );
            url
        }
        None => TESTNET_RPC_URL.to_owned(),
    }
}

/// [`LIVE_INNER_COUNT`] calls of the native asset SAC's `symbol`.
fn native_symbol_bundle() -> Vec<MulticallInvocation> {
    (0..LIVE_INNER_COUNT)
        .map(|_| MulticallInvocation {
            target_contract: XLM_SAC_TESTNET.to_owned(),
            fn_name: "symbol".to_owned(),
            args_json: serde_json::json!([]),
        })
        .collect()
}

/// Asserts each inner of a confirmed [`native_symbol_bundle`] returned the
/// native asset's symbol.
fn assert_native_symbols(label: &str, inner_results: &[MulticallInnerResult]) {
    assert_eq!(
        inner_results.len(),
        LIVE_INNER_COUNT,
        "[{label}] one result per inner"
    );
    let expected = ScVal::String(ScString(
        NATIVE_ASSET_SYMBOL
            .try_into()
            .expect("the native symbol fits an ScString"),
    ));
    for inner in inner_results {
        let returned = ScVal::from_xdr_base64(&inner.return_scval_b64, Limits::none())
            .unwrap_or_else(|e| {
                panic!(
                    "[{label}] inner {} return value must decode: {e}",
                    inner.inner_index
                )
            });
        assert_eq!(
            returned, expected,
            "[{label}] inner {} returns the native asset's symbol",
            inner.inner_index
        );
    }
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
            allow_opaque_signing: false,
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

// ── h1_three_native_sac_symbol_calls_confirm ──────────────────────────────────

/// Deploy the router and a fresh smart account, then submit three native-SAC
/// `symbol` calls under rule 0 via `submit_multicall_bundle`.
///
/// Asserts:
/// - `MulticallResult::inner_count == 3`
/// - The bundle lands on-chain (ledger > 0)
/// - `audit_degraded == false`
/// - Each inner's return value decodes to the native asset's symbol
///
/// The router is [`multicall_router`]'s and the secondary endpoint
/// [`secondary_rpc_url`]'s; see the module's gating section.
#[tokio::test]
#[serial_test::serial]
async fn h1_three_native_sac_symbol_calls_confirm() {
    let data_root = tempfile::tempdir().expect("temporary wallet data root");
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(data_root.path());
    let secondary_rpc_url = secondary_rpc_url();

    // ── Step 1: Fresh signer + fund ───────────────────────────────────────────
    let (signer_g, signer_box) = fresh_signer();
    fund_via_friendbot(&signer_g).await;
    eprintln!("[h1] signer funded: {}", &signer_g[..8]);

    // ── Step 2: Deploy the router and a fresh smart account ──────────────────
    let router_address = multicall_router().await;
    eprintln!("[h1] router_address: {}", &router_address[..8]);
    let sa_strkey = deploy_fresh_smart_account(&signer_g).await;
    eprintln!("[h1] smart_account: {}", &sa_strkey[..8]);

    // ── Step 3: Build registry + policy engine ────────────────────────────────
    // The bundle signs under the deployment's bootstrap rule 0; the
    // rule-management ceremony is exercised by the smart_account_rules suites.
    let registry = registry_with_entry(&router_address);
    let profile = testnet_profile();
    let policy_engine = policy_engine_allow_all();

    // ── Step 4: Submit the multicall bundle ───────────────────────────────────
    let signers_manager = pin_check_manager::pin_check_manager(
        TESTNET_RPC_URL,
        &secondary_rpc_url,
        "multicall-acceptance",
        data_root.path(),
    );
    let result = submit_multicall_bundle(
        MulticallSubmitArgs {
            smart_account: &sa_strkey,
            rule_id: 0,
            bundle: native_symbol_bundle(),
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
            request_id: "h1-three-native-sac-symbol-calls",
            signers_manager: &signers_manager,
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

    // ── Step 5: Assert outcome ────────────────────────────────────────────────
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
    assert_native_symbols("h1", &mc_result.inner_results);

    eprintln!(
        "[h1] PASS: 3 symbol calls confirmed at ledger {} (tx_hash prefix: {})",
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
#[serial_test::serial]
async fn h2_per_period_cap_deny_at_inner_3() {
    let data_root = tempfile::tempdir().expect("temporary wallet data root");
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(data_root.path());
    // 30 USDC per inner in 7-decimal SAC units = 30 * 10_000_000 = 300_000_000.
    // cap = 100 USDC = 1_000_000_000 units.
    // Per-period window: 1 hour.
    let usdc_per_inner: i128 = 300_000_000; // 30 USDC in SAC units
    let cap_usdc: i128 = 1_000_000_000; // 100 USDC in SAC units

    let window = Window::parse("1h").expect("Window::parse('1h') must succeed");
    let bundle_per_period_cap = BundlePerPeriodCapCriterion::new(
        DUMMY_C_STRKEY.to_owned(), // asset = fake USDC SAC address (dummy C-strkey)
        window,
        cap_usdc,
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
                    let (_, signer) = fresh_signer();
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
            signers_manager: &pin_check_manager::pin_check_manager(
                TESTNET_RPC_URL,
                TESTNET_RPC_URL,
                "multicall-acceptance",
                data_root.path(),
            ),
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
#[serial_test::serial]
async fn h3_bundle_aggregate_cap_deny() {
    let data_root = tempfile::tempdir().expect("temporary wallet data root");
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(data_root.path());
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
                    let (_, signer) = fresh_signer();
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
            signers_manager: &pin_check_manager::pin_check_manager(
                TESTNET_RPC_URL,
                TESTNET_RPC_URL,
                "multicall-acceptance",
                data_root.path(),
            ),
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

// ── h5_bundle_under_a_rule_other_than_0_checks_its_signer_set ────────────────

/// The rows of the audit log at `path`, in order.
fn audit_rows(audit_writer: &Arc<Mutex<AuditWriter>>) -> Vec<AuditEntry> {
    verified_audit_entries(audit_writer)
}

/// A fresh audit writer over `audit.jsonl` in `dir`, with the log's path.
fn audit_writer_in(dir: &std::path::Path) -> (Arc<Mutex<AuditWriter>>, std::path::PathBuf) {
    let path = dir.join("audit.jsonl");
    let writer = Arc::new(Mutex::new(
        AuditWriter::open(path.clone(), None).expect("the audit log opens"),
    ));
    (writer, path)
}

/// A bundle under a rule other than 0 goes through the submit path's
/// signer-set check of that rule.
///
/// Installs a `Default` rule whose one signer is the bundle signer's G key
/// as a `Delegated` signer. The rule manager's signers manager shares one
/// audit log with it, so the install records the rule's version-2 state
/// there. A bundle under the rule then confirms, `signers
/// list` matches and the log holds no divergence row. A second signers
/// manager over another log records its own state of the rule and adds a
/// fresh `Delegated` signer to it, a change the first log never sees. The
/// next bundle under the rule through the first manager refuses at phase
/// `policy_gate` with `sa.signer_set_diverged`, writing the divergence row
/// and the denied-bundle row into the first log.
///
/// Each bundle is three native-SAC `symbol` calls. The router is
/// [`multicall_router`]'s and the secondary endpoint [`secondary_rpc_url`]'s;
/// see the module's gating section.
#[tokio::test]
#[serial_test::serial]
async fn h5_bundle_under_a_rule_other_than_0_checks_its_signer_set() {
    let data_root = tempfile::tempdir().expect("temporary wallet data root");
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(data_root.path());
    let secondary_rpc_url = secondary_rpc_url();
    let timeout = Duration::from_secs(TIMEOUT_SECS);
    let rid = || uuid::Uuid::new_v4().to_string();

    // ── Step 1: a fresh signer, the router, and a smart account ──────────────
    let (signer_g, signer_box) = fresh_signer();
    fund_via_friendbot(&signer_g).await;
    let router_address = multicall_router().await;
    eprintln!("[h5] router_address: {}", &router_address[..8]);
    let sa_strkey = deploy_fresh_smart_account(&signer_g).await;
    let sa_addr = parse_c_strkey_to_smart_account(&sa_strkey).expect("C-strkey must parse");
    eprintln!("[h5] smart_account: {}", &sa_strkey[..8]);

    // ── Step 2: the managers over one log, and the rule ───────────────────────
    let log_dir = tempfile::tempdir().expect("temporary audit-log directory");
    let (writer, log_path) = audit_writer_in(log_dir.path());
    let signers_manager = signers_manager_for_tests(
        TESTNET_RPC_URL,
        &secondary_rpc_url,
        Arc::clone(&writer),
        log_path.clone(),
        timeout,
    );
    let rule_manager = rule_manager_for_tests(
        TESTNET_RPC_URL,
        None,
        Arc::clone(&signers_manager),
        Arc::clone(&writer),
        timeout,
    );
    let definition = ContextRuleDefinition::new(
        RuleContext::Default,
        "h5-multicall".to_owned(),
        None,
        vec![ContextRuleSignerInput::Delegated {
            address: parse_g_strkey_to_signer_address(&signer_g).expect("G-strkey must parse"),
        }],
        vec![],
    );
    let rule_id = rule_manager
        .install_rule(
            sa_addr.clone(),
            definition,
            vec![ContextRuleId::new(0)],
            signer_box.as_ref(),
            None,
            rid(),
            false,
            false,
        )
        .await
        .expect("the rule installs and records its version-2 state")
        .rule_id;
    assert_ne!(
        rule_id, 0,
        "[h5] the installed rule is not the bootstrap rule"
    );
    eprintln!("[h5] rule installed: {rule_id}");

    // ── Step 3: a bundle under the rule ───────────────────────────────────────
    let registry = registry_with_entry(&router_address);
    let profile = testnet_profile();
    let submit = |request_id: &'static str| {
        submit_multicall_bundle(
            MulticallSubmitArgs {
                smart_account: &sa_strkey,
                rule_id,
                bundle: native_symbol_bundle(),
                signer: signer_box.as_ref(),
                primary_rpc_url: TESTNET_RPC_URL,
                secondary_rpc_url: &secondary_rpc_url,
                network_passphrase: TESTNET_PASSPHRASE,
                policy_engine: policy_engine_allow_all(),
                profile: &profile,
                audit_writer: Some(Arc::clone(&writer)),
                timeout,
                fee: ResolvedFeePerOp::default(),
                chain_id: CHAIN_ID,
                request_id,
                signers_manager: &signers_manager,
            },
            &registry,
        )
    };
    let confirmed = submit("h5-bundle-under-the-rule")
        .await
        .unwrap_or_else(|e| panic!("[h5] the bundle under rule {rule_id} must confirm: {e:?}"));
    assert_eq!(confirmed.inner_count, 3, "[h5] inner_count");
    assert!(confirmed.ledger > 0, "[h5] the bundle confirmed on chain");
    assert_native_symbols("h5", &confirmed.inner_results);
    let listed = signers_manager
        .list_signers(sa_addr.clone(), rule_id, Some(&signer_g), rid())
        .await
        .expect("signers list reads the rule");
    assert_eq!(listed.baseline, PreviousBaseline::Matched);
    assert!(
        !audit_rows(&writer)
            .iter()
            .any(|row| matches!(row.event_kind, EventKind::SaSignerSetDiverged { .. })),
        "[h5] the matched rule writes no divergence row"
    );

    // ── Step 4: an out-of-band signer add through another manager ────────────
    let other_dir = tempfile::tempdir().expect("temporary audit-log directory");
    let (other_writer, other_log_path) = audit_writer_in(other_dir.path());
    let other_manager = signers_manager_for_tests(
        TESTNET_RPC_URL,
        &secondary_rpc_url,
        other_writer,
        other_log_path,
        timeout,
    );
    let first = other_manager
        .list_signers(sa_addr.clone(), rule_id, Some(&signer_g), rid())
        .await
        .expect("signers list records the rule in the other log");
    assert_eq!(first.baseline, PreviousBaseline::None);
    let (added_g, _added_signer) = fresh_signer();
    other_manager
        .add_signer(
            sa_addr.clone(),
            rule_id,
            build_delegated_signer_scval(&added_g).expect("a Delegated signer value"),
            signer_box.as_ref(),
            rid(),
            false,
            false,
        )
        .await
        .expect("the out-of-band signer add confirms");
    eprintln!("[h5] out-of-band signer added");

    // ── Step 5: the next bundle under the rule refuses ───────────────────────
    let request_id = "h5-bundle-after-the-out-of-band-add";
    let refused = submit(request_id)
        .await
        .expect_err("[h5] the bundle under the changed rule must refuse");
    match &refused {
        SaError::MulticallFailed {
            phase,
            redacted_reason,
            ..
        } => {
            assert_eq!(*phase, "policy_gate");
            assert_eq!(redacted_reason, "submit error: sa.signer_set_diverged");
        }
        other => panic!("[h5] expected MulticallFailed at policy_gate; got {other:?}"),
    }
    let rows = audit_rows(&writer);
    assert!(
        rows.iter().any(|row| row.request_id == request_id
            && matches!(row.event_kind, EventKind::SaSignerSetDiverged { rule_id: diverged, .. } if diverged == rule_id)),
        "[h5] the divergence row of the rule is in the bundle manager's log"
    );
    assert!(
        rows.iter().any(|row| row.request_id == request_id
            && matches!(
                &row.event_kind,
                EventKind::SaMulticallBundleDenied { deny_wire_code, refusal_phase, .. }
                    if deny_wire_code == "multicall.sa.signer_set_diverged"
                        && refusal_phase == "policy_gate"
            )),
        "[h5] the denied-bundle row names the divergence"
    );
    eprintln!("[h5] PASS: the bundle under rule {rule_id} checks its signer set");
}
