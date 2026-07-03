//! `stellar-agent fees stats` subcommand.

use clap::Args;
use stellar_agent_core::envelope::{Envelope, OutputFormat};
use stellar_agent_core::error::{ValidationError, WalletError};
use stellar_agent_core::profile::loader;
use stellar_agent_network::{FeeStatsView, StellarRpcClient, fetch_fee_stats, validate_rpc_url};

use crate::common::render::{render_json, sanitize_for_table};
use crate::render::table::render_fee_stats_table;

const TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";

/// Arguments for `stellar-agent fees stats`.
#[derive(Debug, Args)]
pub struct FeesStatsArgs {
    /// Profile name whose RPC URL should be used.
    #[arg(long, value_name = "NAME")]
    pub profile: Option<String>,

    /// Allow-listed Stellar RPC endpoint override.
    #[arg(long, value_name = "URL")]
    pub rpc_url: Option<String>,

    /// Output format: `json` (default) or `table`.
    #[arg(long, default_value_t = OutputFormat::DEFAULT, value_name = "FORMAT")]
    pub output: OutputFormat,
}

/// Runs `stellar-agent fees stats`.
pub async fn run(args: &FeesStatsArgs) -> i32 {
    let rpc_url = match resolve_rpc_url(args) {
        Ok(url) => url,
        Err(err) => {
            let envelope = Envelope::<()>::err(&err);
            print_error(&envelope, args.output);
            return 1;
        }
    };

    if args.rpc_url.is_some()
        && let Err(err) = validate_rpc_url_for_cli(&rpc_url)
    {
        let envelope = Envelope::<()>::err(&err);
        print_error(&envelope, args.output);
        return 1;
    }

    let client = match StellarRpcClient::new(&rpc_url) {
        Ok(client) => client,
        Err(err) => {
            let envelope = Envelope::<()>::err(&err);
            print_error(&envelope, args.output);
            return 1;
        }
    };

    match fetch_fee_stats(&client).await {
        Ok(view) => {
            let envelope = Envelope::ok(view);
            print_success(&envelope, args.output);
            0
        }
        Err(err) => {
            let wallet_err = WalletError::Network(err);
            let envelope = Envelope::<()>::err(&wallet_err);
            print_error(&envelope, args.output);
            1
        }
    }
}

fn resolve_rpc_url(args: &FeesStatsArgs) -> Result<String, WalletError> {
    if let Some(url) = &args.rpc_url {
        return Ok(url.clone());
    }
    if let Some(profile_name) = &args.profile {
        return loader::load(profile_name, None)
            .map(|profile| profile.rpc_url)
            .map_err(|_| {
                WalletError::Validation(ValidationError::ProfileNotFound {
                    name: profile_name.clone(),
                })
            });
    }
    Ok(TESTNET_RPC_URL.to_owned())
}

fn validate_rpc_url_for_cli(url: &str) -> Result<(), WalletError> {
    validate_rpc_url(url).map_err(|err| {
        WalletError::Validation(ValidationError::ProfileNotFound {
            name: format!("invalid rpc_url: {err}"),
        })
    })
}

fn print_success(envelope: &Envelope<FeeStatsView>, format: OutputFormat) {
    match format {
        OutputFormat::Table =>
        {
            #[allow(clippy::print_stdout, reason = "CLI binary intentional user output")]
            if let Some(view) = &envelope.data {
                println!("{}", render_fee_stats_table(view));
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
                println!("Error: {} - {}", err.code, safe_msg);
            }
        }
        _ => render_json(envelope),
    }
}
