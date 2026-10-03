//! `stellar-agent smart-account deploy-webauthn-verifier` subcommand.
//!
//! Deploys the vendored OZ WebAuthn-verifier contract WASM to a Stellar network and
//! records the resulting contract address in the wallet-local verifier registry
//! (`<canonical_data_root>/networks.toml`).
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
//! or signing call. A mainnet profile returns `MainnetWriteForbidden` as soon
//! as its network context is built.
//!
//! # Dry-run mode (`--dry-run`)
//!
//! Computes the derived verifier C-strkey without any network access. Returns a
//! JSON envelope with `status: "dry_run"`, populated `verifier_address` and
//! `verifier_wasm_sha256`, and `null` for `tx_hash` / `ledger`.
//!
//! # Idempotency
//!
//! If the registry already contains an entry for the target network with the same
//! `wasm_sha256`, the command returns immediately with `status: "already_deployed"`
//! and no RPC traffic.
//!
//! This is the verifier bootstrap CLI verb for WebAuthn signers.

use std::time::Duration;

use clap::{ArgGroup, Args};
use stellar_agent_core::envelope::{Envelope, OutputFormat};
use stellar_agent_core::error::{NetworkError, WalletError};
use stellar_agent_network::{
    StellarRpcClient, parse_classic_fee_choice, resolve_classic_fee_selection,
};
use stellar_agent_smart_account::deployment::{
    ResolvedFeePerOp, WebAuthnVerifierDeployArgs, WebAuthnVerifierDeployResult,
    deploy_webauthn_verifier,
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
///
/// 100 stroops is the standard Stellar SDK profile default for the base fee.
/// Soroban resource fees are computed by simulation and added by `prepare_transaction`;
/// this constant is only the base fee applied before simulation. Pass `--fee auto`
/// to select a fee via `getFeeStats` percentile.
const DEFAULT_FEE_STROOPS: u32 = 100;

/// Default submission timeout in seconds.
const DEFAULT_TIMEOUT_SECONDS: u64 = 60;

// ─────────────────────────────────────────────────────────────────────────────
// DeployWebAuthnVerifierArgs
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for the `smart-account deploy-webauthn-verifier` subcommand.
///
/// Two mutually-exclusive deployer-source modes; one required (clap enforces via
/// the `deployer_group` arg-group).
///
/// # Clap arg-groups
///
/// - `deployer_group` — exactly one of `--deployer-secret-env`,
///   `--sign-with-ledger`. Required.
#[non_exhaustive]
#[derive(Debug, Args)]
#[command(
    group(
        ArgGroup::new("deployer_group")
            .args(["deployer_secret_env", "sign_with_ledger"])
            .required(true)
    ),
)]
pub struct DeployWebAuthnVerifierArgs {
    /// Profile name; falls back to the environment, then the default profile.
    #[arg(long, value_name = "NAME")]
    pub profile: Option<String>,
    /// Name of the environment variable holding the deployer S-strkey.
    ///
    /// Mutually exclusive with `--sign-with-ledger`.
    /// The deployer G-strkey is derived from the S-strkey; the deployer account
    /// must be pre-funded.
    #[arg(long, value_name = "VAR", group = "deployer_group")]
    pub deployer_secret_env: Option<String>,

    /// Use the connected Ledger hardware wallet as the deployer.
    ///
    /// Mutually exclusive with `--deployer-secret-env`.
    /// The Ledger device must have the Stellar app open.
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
    ///
    /// Accepts:
    /// - `<integer>` — use that value as the explicit per-op fee in stroops.
    /// - `auto` — fetch `getFeeStats` and use the p95 percentile.
    /// - `auto:p50` / `auto:p75` / `auto:p95` / `auto:p99` — explicit percentile.
    /// - absent — use the profile default (100 stroops; Soroban resource fees
    ///   are set by simulation and are additional to this base).
    #[arg(long, value_name = "STROOPS|auto[:pNN]")]
    pub fee: Option<String>,

    /// Submission timeout in seconds. Default: 60.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECONDS, value_name = "SECONDS")]
    pub timeout_seconds: u64,

    /// Output format: `json` (default) or `table`.
    #[arg(long, default_value_t = OutputFormat::DEFAULT, value_name = "FORMAT")]
    pub output: OutputFormat,

    /// Compute the derived verifier C-strkey without any network access.
    ///
    /// Returns a JSON envelope with `verifier_address`, `verifier_wasm_sha256`,
    /// and `status: "dry_run"`. `tx_hash` and `ledger` are absent. No signing,
    /// no RPC traffic.
    #[arg(long)]
    pub dry_run: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// run — main dispatch
// ─────────────────────────────────────────────────────────────────────────────

/// Runs the `smart-account deploy-webauthn-verifier` subcommand.
///
/// Validates inputs, resolves the deployer keypair, resolves the fee, then
/// delegates to `deploy_webauthn_verifier`. Renders the result per `args.output`.
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
pub async fn run(args: &DeployWebAuthnVerifierArgs) -> i32 {
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
    // First layer: structural mainnet rejection before any key access.
    if context.chain_id.is_mainnet() {
        let err = WalletError::Network(NetworkError::MainnetWriteForbidden);
        let envelope = Envelope::<()>::err(&err);
        print_error(&envelope, args.output);
        return 1;
    }

    // Resolve the deployer keypair.
    // These verbs open no audit writer, so an `mlock` degradation is reported
    // only through the warning `Wallet::unlock` emits.
    let (deployer, _mlock_degradation) = match resolve_deployer_keypair(
        args.deployer_secret_env.as_deref(),
        args.sign_with_ledger,
        args.account_index,
        "deploy-webauthn-verifier",
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

    // Resolve the fee. In dry-run mode there is no network access so we skip
    // getFeeStats and fall back to the profile default.
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

    let deploy_args = WebAuthnVerifierDeployArgs {
        deployer,
        network_passphrase: passphrase.to_owned(),
        rpc_url: context.rpc_url.clone(),
        timeout: Duration::from_secs(args.timeout_seconds),
        fee: resolved_fee,
        dry_run: args.dry_run,
        registry_path_override: None,
    };

    // A profile-scoped AuditWriter is not yet plumbed through, so deploy actions are not recorded to a profile audit log.
    match deploy_webauthn_verifier(deploy_args, None).await {
        Ok(result) => {
            info!(
                verifier = %stellar_agent_core::observability::redact_strkey_first5_last5(
                    &result.verifier_address),
                wasm_sha256 = %stellar_agent_core::hex::redact_hex_first8_last8(
                    &result.verifier_wasm_sha256),
                status = result.status,
                dry_run = args.dry_run,
                "deploy-webauthn-verifier: complete"
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
    result: &WebAuthnVerifierDeployResult,
    envelope: &Envelope<WebAuthnVerifierDeployResult>,
    format: OutputFormat,
) {
    match format {
        OutputFormat::Table => {
            use stellar_agent_core::observability::redact_strkey_first5_last5;
            use stellar_agent_network::submit::redact_tx_hash;

            #[allow(clippy::print_stdout, reason = "CLI binary intentional user output")]
            {
                let verifier = redact_strkey_first5_last5(&result.verifier_address);
                println!("WebAuthn verifier {}: {}", result.status, verifier);

                let wasm_display =
                    stellar_agent_core::hex::redact_hex_first8_last8(&result.verifier_wasm_sha256);
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
