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
use stellar_agent_core::error::{AuthError, NetworkError, WalletError};
use stellar_agent_network::{
    StellarRpcClient, parse_classic_fee_choice, resolve_classic_fee_selection,
};
use stellar_agent_smart_account::deployment::{
    DeployerKeypair, PolicyDeployArgs, PolicyDeployKind, PolicyDeployResult, ResolvedFeePerOp,
    deploy_policy,
};
use tracing::info;
use zeroize::Zeroizing;

use crate::common::network::TargetNetwork;
use crate::common::render::{render_json, sanitize_for_table};

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Default base fee per operation in stroops.
const DEFAULT_FEE_STROOPS: u32 = 100;

/// Default submission timeout in seconds.
const DEFAULT_TIMEOUT_SECONDS: u64 = 60;

/// Stellar testnet Soroban RPC endpoint (SDF operated).
const TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";

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

    /// Network to target.
    ///
    /// Only `testnet` is accepted for deployment. Mainnet is structurally
    /// refused. Default: `testnet`.
    #[arg(long, default_value_t = TargetNetwork::Testnet, value_name = "NETWORK")]
    pub network: TargetNetwork,

    /// Soroban RPC endpoint URL.
    #[arg(long, default_value = TESTNET_RPC_URL, value_name = "URL")]
    pub rpc_url: String,

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
    if args.network == TargetNetwork::Mainnet {
        let err = WalletError::Network(NetworkError::MainnetWriteForbidden);
        let envelope = Envelope::<()>::err(&err);
        print_error(&envelope, args.output);
        return 1;
    }

    let deployer = match resolve_deployer(args).await {
        Ok(d) => d,
        Err(e) => {
            let envelope = Envelope::<()>::err(&e);
            print_error(&envelope, args.output);
            return 1;
        }
    };

    let passphrase = args.network.passphrase();

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

        let fee_client = match StellarRpcClient::new(&args.rpc_url) {
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
        rpc_url: args.rpc_url.clone(),
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
// Deployer resolution
// ─────────────────────────────────────────────────────────────────────────────

/// Resolves the deployer keypair from the CLI flags.
///
/// # Errors
///
/// - [`WalletError::Auth`] — env var not set, S-strkey invalid, or Ledger not connected.
async fn resolve_deployer(args: &DeployPolicyArgs) -> Result<DeployerKeypair, WalletError> {
    if args.sign_with_ledger {
        use stellar_agent_network::signing::hardware::HardwareSigningKey;
        let hw_key = HardwareSigningKey::native()
            .map_err(|e| {
                WalletError::Auth(AuthError::KeyringNotFound {
                    name: format!("Ledger not found or Stellar app not open: {e}"),
                })
            })?
            .with_account_index(args.account_index);

        let signer: Box<dyn stellar_agent_network::Signer + Send + Sync> = Box::new(hw_key);
        return Ok(DeployerKeypair::Ledger {
            account_index: args.account_index,
            signer,
        });
    }

    let var_name = args
        .deployer_secret_env
        .as_deref()
        .ok_or_else(|| WalletError::Auth(AuthError::KeyringLocked))?;

    let s_strkey: Zeroizing<String> = Zeroizing::new(std::env::var(var_name).map_err(|_| {
        WalletError::Auth(AuthError::KeyringNotFound {
            name: format!("environment variable '{var_name}' not set"),
        })
    })?);

    let private_key =
        stellar_strkey::ed25519::PrivateKey::from_string(&s_strkey).map_err(|_| {
            WalletError::Auth(AuthError::KeyringNotFound {
                name: format!("environment variable '{var_name}' contains an invalid S-strkey"),
            })
        })?;

    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(private_key.0);
    let signer = stellar_agent_network::SoftwareSigningKey::new_from_zeroizing(seed);
    let signer: Box<dyn stellar_agent_network::Signer + Send + Sync> = Box::new(signer);

    Ok(DeployerKeypair::SecretEnv {
        var_name: var_name.to_owned(),
        signer,
    })
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
            kind,
            deployer_secret_env: Some(TEST_DEPLOYER_ENV_VAR.to_owned()),
            sign_with_ledger: false,
            account_index: 0,
            network: TargetNetwork::Testnet,
            rpc_url: TESTNET_RPC_URL.to_owned(),
            fee: None,
            timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
            output: OutputFormat::Json,
            dry_run: true,
        }
    }

    /// The CLI structurally refuses mainnet before any key access or RPC call.
    #[tokio::test]
    async fn mainnet_is_structurally_refused() {
        let mut args = dry_run_args(PolicyKindArg::SimpleThreshold);
        args.network = TargetNetwork::Mainnet;
        let code = run(&args).await;
        assert_eq!(code, 1, "mainnet deploy must be refused with exit code 1");
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
