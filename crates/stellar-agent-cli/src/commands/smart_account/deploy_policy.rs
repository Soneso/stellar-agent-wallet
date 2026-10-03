//! `stellar-agent smart-account deploy-policy` subcommand.
//!
//! Unified deploy verb for the three OZ policy contracts this wallet
//! vendors: `--kind simple-threshold`, `--kind spending-limit`, `--kind
//! weighted-threshold`. Each kind is a per-network singleton: one deployed
//! instance serves every account and context rule on the network.
//!
//! `--kind spending-limit` routes to the same substrate as the standalone
//! `smart-account deploy-spending-limit-policy` verb (which remains
//! available unchanged); the two are equivalent for that kind.
//!
//! # Signer modes
//!
//! ## Mode A — `--deployer-secret-env <VAR>`
//!
//! Reads the deployer S-strkey from the named environment variable. The deployer
//! G-strkey is derived from the secret; must be pre-funded with at least the
//! deployment fee.
//!
//! ## Mode B — `--sign-with-ledger`
//!
//! Uses a Ledger hardware wallet at the specified `--account-index`. The Ledger
//! device must have the Stellar app open.
//!
//! # Mainnet rejection
//!
//! Deployment on mainnet is structurally refused at the CLI layer before any RPC
//! or signing call.
//!
//! # Dry-run mode (`--dry-run`)
//!
//! Computes the derived policy C-strkey without any network access.
//!
//! # Idempotency
//!
//! If the registry already contains an entry for the target network + kind
//! with the same `wasm_sha256`, the command returns immediately with
//! `status: "already_deployed"` and no RPC traffic.

use std::time::Duration;

use clap::{ArgGroup, Args};
use stellar_agent_core::envelope::{Envelope, OutputFormat};
use stellar_agent_core::error::{NetworkError, WalletError};
use stellar_agent_network::{
    StellarRpcClient, parse_classic_fee_choice, resolve_classic_fee_selection,
};
use stellar_agent_smart_account::deployment::{
    PolicyDeployArgs, PolicyDeployKind, PolicyDeployResult, ResolvedFeePerOp, deploy_policy,
};
use tracing::info;

use crate::common::network::{
    EndpointFlags, EndpointUrlFlag, TargetNetwork, network_context_for_command,
};
use crate::common::profile_access::load_profile_or_synthesize_testnet;
use crate::common::render::{render_json, sanitize_for_table};
use crate::common::resolve_profile_name;
use crate::common::signer_ceremony::resolve_deployer_keypair;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Default base fee per operation in stroops.
const DEFAULT_FEE_STROOPS: u32 = 100;

/// Default submission timeout in seconds.
const DEFAULT_TIMEOUT_SECONDS: u64 = 60;

// ─────────────────────────────────────────────────────────────────────────────
// PolicyKindArg — CLI-facing `--kind` value enum
// ─────────────────────────────────────────────────────────────────────────────

/// Selects which policy contract `smart-account deploy-policy` deploys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum PolicyKindArg {
    /// OZ `multisig-threshold-policy-example` (unweighted signer-count threshold).
    #[value(name = "simple-threshold")]
    SimpleThreshold,
    /// OZ `multisig-spending-limit-policy-example`. Routes to the same
    /// substrate as `smart-account deploy-spending-limit-policy`.
    #[value(name = "spending-limit")]
    SpendingLimit,
    /// OZ `multisig-weighted-threshold-policy-example` (weighted-signer quorum).
    #[value(name = "weighted-threshold")]
    WeightedThreshold,
}

impl From<PolicyKindArg> for PolicyDeployKind {
    fn from(arg: PolicyKindArg) -> Self {
        match arg {
            PolicyKindArg::SimpleThreshold => Self::SimpleThreshold,
            PolicyKindArg::SpendingLimit => Self::SpendingLimit,
            PolicyKindArg::WeightedThreshold => Self::WeightedThreshold,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DeployPolicyArgs
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for the `smart-account deploy-policy` subcommand.
///
/// Two mutually-exclusive deployer-source modes; one required (clap enforces
/// via the `deployer_group` arg-group).
#[non_exhaustive]
#[derive(Debug, Args)]
#[command(
    group(
        ArgGroup::new("deployer_group")
            .args(["deployer_secret_env", "sign_with_ledger"])
            .required(true)
    ),
)]
pub struct DeployPolicyArgs {
    /// Profile name; falls back to the environment, then the default profile.
    #[arg(long, value_name = "NAME")]
    pub profile: Option<String>,
    /// Which policy contract to deploy.
    #[arg(
        long,
        value_enum,
        value_name = "simple-threshold|spending-limit|weighted-threshold"
    )]
    pub kind: PolicyKindArg,

    /// Name of the environment variable holding the deployer S-strkey.
    ///
    /// Mutually exclusive with `--sign-with-ledger`.
    #[arg(long, value_name = "VAR", group = "deployer_group")]
    pub deployer_secret_env: Option<String>,

    /// Use the connected Ledger hardware wallet as the deployer.
    ///
    /// Mutually exclusive with `--deployer-secret-env`.
    #[arg(long, group = "deployer_group")]
    pub sign_with_ledger: bool,

    /// BIP-44 account index for Ledger derivation path (default 0).
    #[arg(long, default_value_t = 0_u32, value_name = "INDEX")]
    pub account_index: u32,

    /// The network comes from the profile when absent.
    /// When supplied, this flag must equal the profile's chain.
    #[arg(long, value_name = "NETWORK")]
    pub network: Option<TargetNetwork>,

    /// The RPC endpoint comes from the profile when absent.
    /// On testnet, this flag overrides the profile endpoint.
    /// On mainnet, this flag is refused, including equal values.
    /// URL credentials are refused.
    #[arg(long, value_name = "URL", value_parser = EndpointUrlFlag)]
    pub rpc_url: Option<String>,

    /// Base fee per operation in stroops, or `auto` / `auto:pNN` for `getFeeStats`
    /// automatic selection.
    #[arg(long, value_name = "STROOPS|auto[:pNN]")]
    pub fee: Option<String>,

    /// Submission timeout in seconds. Default: 60.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECONDS, value_name = "SECONDS")]
    pub timeout_seconds: u64,

    /// Output format: `json` (default) or `table`.
    #[arg(long, default_value_t = OutputFormat::DEFAULT, value_name = "FORMAT")]
    pub output: OutputFormat,

    /// Compute the derived policy C-strkey without any network access.
    #[arg(long)]
    pub dry_run: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// run — main dispatch
// ─────────────────────────────────────────────────────────────────────────────

/// Runs the `smart-account deploy-policy` subcommand.
///
/// Returns an exit code: `0` on success, `1` on any error.
///
/// # Errors
///
/// Never returns `Err` — all errors are captured into the envelope and the exit code.
///
/// # Panics
///
/// Never panics.
pub async fn run(args: &DeployPolicyArgs) -> i32 {
    let resolved = resolve_profile_name(args.profile.as_deref());
    let (profile, _origin) = match load_profile_or_synthesize_testnet(&resolved) {
        Ok(loaded) => loaded,
        Err(e) => {
            print_error(
                &Envelope::<()>::err_raw(e.code(), e.message(&resolved.name)),
                args.output,
            );
            return 1;
        }
    };
    let context = match network_context_for_command(
        &profile,
        &resolved.name,
        EndpointFlags {
            network: args.network,
            rpc_url: args.rpc_url.as_deref(),
            secondary_rpc_url: None,
        },
    ) {
        Ok(context) => context,
        Err(e) => {
            print_error(&Envelope::<()>::err(&e), args.output);
            return 1;
        }
    };
    if context.chain_id.is_mainnet() {
        let err = WalletError::Network(NetworkError::MainnetWriteForbidden);
        let envelope = Envelope::<()>::err(&err);
        print_error(&envelope, args.output);
        return 1;
    }

    // These verbs open no audit writer, so an `mlock` degradation is reported
    // only through the warning `Wallet::unlock` emits.
    let (deployer, _mlock_degradation) = match resolve_deployer_keypair(
        args.deployer_secret_env.as_deref(),
        args.sign_with_ledger,
        args.account_index,
        "deploy-policy",
        &profile,
        &resolved.name,
    )
    .await
    {
        Ok(d) => d,
        Err(e) => {
            let envelope = Envelope::<()>::err(&e);
            print_error(&envelope, args.output);
            return 1;
        }
    };

    let passphrase = context.network_passphrase();

    let resolved_fee = if args.dry_run {
        ResolvedFeePerOp {
            stroops: DEFAULT_FEE_STROOPS,
            percentile_label: "profile_default".to_owned(),
        }
    } else {
        let fee_choice = match parse_classic_fee_choice(args.fee.as_deref()) {
            Ok(c) => c,
            Err(e) => {
                let envelope = Envelope::<()>::err(&e);
                print_error(&envelope, args.output);
                return 1;
            }
        };

        let fee_client = match StellarRpcClient::new(&context.rpc_url) {
            Ok(c) => c,
            Err(e) => {
                let envelope = Envelope::<()>::err(&e);
                print_error(&envelope, args.output);
                return 1;
            }
        };

        match resolve_classic_fee_selection(&fee_client, DEFAULT_FEE_STROOPS, fee_choice).await {
            Ok(sel) => ResolvedFeePerOp {
                stroops: sel.per_op_stroops,
                percentile_label: sel.selected_fee_percentile,
            },
            Err(e) => {
                let envelope = Envelope::<()>::err(&e);
                print_error(&envelope, args.output);
                return 1;
            }
        }
    };

    let deploy_args = PolicyDeployArgs {
        kind: args.kind.into(),
        deployer,
        network_passphrase: passphrase.to_owned(),
        rpc_url: context.rpc_url.clone(),
        timeout: Duration::from_secs(args.timeout_seconds),
        fee: resolved_fee,
        dry_run: args.dry_run,
        registry_path_override: None,
    };

    // A profile-scoped AuditWriter is not yet plumbed through, so deploy actions are not recorded to a profile audit log.
    match deploy_policy(deploy_args, None).await {
        Ok(result) => {
            info!(
                kind = result.kind,
                policy = %stellar_agent_core::observability::redact_strkey_first5_last5(
                    &result.policy_address),
                wasm_sha256 = %stellar_agent_core::hex::redact_hex_first8_last8(
                    &result.policy_wasm_sha256),
                status = result.status,
                dry_run = args.dry_run,
                "deploy-policy: complete"
            );
            let envelope = Envelope::ok(result.clone());
            print_success(&result, &envelope, args.output);
            0
        }
        Err(e) => {
            let err = WalletError::SmartAccount {
                wire_code: e.wire_code(),
                message: e.to_string(),
            };
            let envelope = Envelope::<()>::err(&err);
            print_error(&envelope, args.output);
            1
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Output helpers
// ─────────────────────────────────────────────────────────────────────────────

fn print_success(
    result: &PolicyDeployResult,
    envelope: &Envelope<PolicyDeployResult>,
    format: OutputFormat,
) {
    match format {
        OutputFormat::Table => {
            use stellar_agent_core::observability::redact_strkey_first5_last5;
            use stellar_agent_network::submit::redact_tx_hash;

            #[allow(clippy::print_stdout, reason = "CLI binary intentional user output")]
            {
                let policy = redact_strkey_first5_last5(&result.policy_address);
                println!("Policy ({}) {}: {}", result.kind, result.status, policy);

                let wasm_display =
                    stellar_agent_core::hex::redact_hex_first8_last8(&result.policy_wasm_sha256);
                println!("  wasm_sha256    {wasm_display}");

                if let Some(ref tx_hash) = result.tx_hash {
                    println!("  tx_hash        {}", redact_tx_hash(tx_hash));
                } else {
                    let reason = if result.status == "dry_run" {
                        "(dry-run)"
                    } else {
                        "(already deployed)"
                    };
                    println!("  tx_hash        {reason}");
                }

                if let Some(ledger) = result.ledger {
                    println!("  ledger         {ledger}");
                }
            }
        }
        _ => render_json(envelope),
    }
}

fn print_error(envelope: &Envelope<()>, format: OutputFormat) {
    match format {
        OutputFormat::Table =>
        {
            #[allow(clippy::print_stdout, reason = "CLI binary intentional user output")]
            if let Some(err) = &envelope.error {
                let safe_msg = sanitize_for_table(&err.message);
                println!("Error: {} — {}", err.code, safe_msg);
            }
        }
        _ => render_json(envelope),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test-only")]
    #![allow(clippy::expect_used, reason = "test-only")]

    use clap::Parser;
    use serial_test::serial;

    use super::*;

    #[derive(Parser)]
    struct DeployPolicyArgsHarness {
        #[command(flatten)]
        args: DeployPolicyArgs,
    }

    const TEST_DEPLOYER_ENV_VAR: &str = "__STELLAR_AGENT_TEST_DEPLOY_POLICY_SKEY";

    fn test_deployer_skey() -> String {
        stellar_strkey::ed25519::PrivateKey::from_payload(&[0x43u8; 32])
            .expect("32-byte test seed must encode as S-strkey")
            .as_unredacted()
            .to_string()
            .as_str()
            .to_owned()
    }

    struct EnvGuard {
        var: &'static str,
    }

    #[allow(
        unsafe_code,
        reason = "test-only process environment override; #[serial] prevents sibling mutation"
    )]
    impl EnvGuard {
        fn set(var: &'static str, value: &str) -> Self {
            // SAFETY: serialised by #[serial]; no concurrent env access.
            unsafe {
                std::env::set_var(var, value);
            }
            Self { var }
        }
    }

    #[allow(
        unsafe_code,
        reason = "test-only environment cleanup; panic-safe via Drop"
    )]
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            // SAFETY: same as set(); serialised by #[serial].
            unsafe {
                std::env::remove_var(self.var);
            }
        }
    }

    fn dry_run_args(kind: PolicyKindArg) -> DeployPolicyArgs {
        DeployPolicyArgs {
            profile: None,
            kind,
            deployer_secret_env: Some(TEST_DEPLOYER_ENV_VAR.to_owned()),
            sign_with_ledger: false,
            account_index: 0,
            network: Some(TargetNetwork::Testnet),
            rpc_url: Some(crate::common::network::TESTNET_RPC_URL.to_owned()),
            fee: None,
            timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
            output: OutputFormat::Json,
            dry_run: true,
        }
    }

    /// A mainnet profile exits 1 before any request reaches its endpoint.
    /// The binary tests in `tests/profile_env_var_resolution.rs` pin the
    /// refusal's wire code.
    #[tokio::test]
    #[serial_test::serial]
    async fn mainnet_profile_reaches_no_endpoint() {
        let guard_rpc = wiremock::MockServer::start().await;
        let (_guard_dir, _guard_home, _guard_env) =
            crate::common::profile_access::test_fixtures::mainnet_guard_fixture(&guard_rpc.uri());
        let mut args = dry_run_args(PolicyKindArg::SimpleThreshold);
        args.network = Some(TargetNetwork::Mainnet);
        args.profile = Some("guard-mainnet".into());
        args.rpc_url = None;
        let code = run(&args).await;
        assert_eq!(code, 1, "a mainnet deploy must exit 1");
        assert!(
            guard_rpc
                .received_requests()
                .await
                .expect("requests")
                .is_empty()
        );
    }

    /// `--network mainnet` with no profile exits 1 before any request reaches
    /// the endpoint `--rpc-url` names. The binary tests pin the wire code.
    #[tokio::test]
    #[serial_test::serial]
    async fn mainnet_flag_without_profile_reaches_no_endpoint() {
        let guard_rpc = wiremock::MockServer::start().await;
        let guard_home = tempfile::tempdir().expect("home");
        let _guard_home = stellar_agent_test_support::StellarAgentHomeGuard::new(guard_home.path());
        let _guard_env = stellar_agent_test_support::ProfileEnvVarGuard::cleared();
        let mut args = dry_run_args(PolicyKindArg::SimpleThreshold);
        args.network = Some(TargetNetwork::Mainnet);
        args.rpc_url = Some(guard_rpc.uri());
        let code = run(&args).await;
        assert_eq!(code, 1, "a mainnet deploy must exit 1");
        assert!(
            guard_rpc
                .received_requests()
                .await
                .expect("requests")
                .is_empty()
        );
    }

    /// The dry-run path derives the policy address offline (no RPC, no
    /// registry write) for each of the three kinds.
    #[tokio::test]
    #[serial]
    async fn dry_run_derives_address_without_network_for_each_kind() {
        let _guard = EnvGuard::set(TEST_DEPLOYER_ENV_VAR, &test_deployer_skey());
        for kind in [
            PolicyKindArg::SimpleThreshold,
            PolicyKindArg::SpendingLimit,
            PolicyKindArg::WeightedThreshold,
        ] {
            let args = dry_run_args(kind);
            let code = run(&args).await;
            assert_eq!(code, 0, "dry-run must succeed offline for {kind:?}");
        }
    }

    /// An unrecognised `--kind` value is a clap grammar error, not a runtime
    /// refusal.
    #[test]
    fn deploy_policy_args_unknown_kind_is_grammar_error() {
        let result = DeployPolicyArgsHarness::try_parse_from([
            "test",
            "--kind",
            "not-a-real-kind",
            "--deployer-secret-env",
            "__STELLAR_AGENT_TEST_DEPLOY_POLICY_GRAMMAR_DUMMY",
        ]);
        assert!(
            result.is_err(),
            "an unrecognised --kind value must be a clap parse error"
        );
    }

    /// Each of the three valid `--kind` values parses successfully.
    #[test]
    fn deploy_policy_args_kind_grammar_accepts_all_values() {
        for label in ["simple-threshold", "spending-limit", "weighted-threshold"] {
            let parsed = DeployPolicyArgsHarness::try_parse_from([
                "test",
                "--kind",
                label,
                "--deployer-secret-env",
                "__STELLAR_AGENT_TEST_DEPLOY_POLICY_GRAMMAR_DUMMY",
            ]);
            assert!(parsed.is_ok(), "--kind {label} must parse");
        }
    }

    /// `PolicyKindArg` converts to the matching `PolicyDeployKind` label.
    #[test]
    fn kind_arg_converts_to_deploy_kind() {
        assert_eq!(
            PolicyDeployKind::from(PolicyKindArg::SimpleThreshold).label(),
            "simple-threshold"
        );
        assert_eq!(
            PolicyDeployKind::from(PolicyKindArg::SpendingLimit).label(),
            "spending-limit"
        );
        assert_eq!(
            PolicyDeployKind::from(PolicyKindArg::WeightedThreshold).label(),
            "weighted-threshold"
        );
    }
}
