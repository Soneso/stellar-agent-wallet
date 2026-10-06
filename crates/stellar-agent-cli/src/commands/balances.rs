//! `stellar-agent balances` subcommand.
//!
//! Displays the native XLM balance and trustlines for a Stellar account. Uses
//! the Stellar RPC `getLedgerEntries` via `stellar-agent-network::fetch_account`.
//! Read-only; no signing or key access.
//!
//! Account lookup routes through Stellar RPC.
//!
//! # Output
//!
//! With `--output json` (default): the JSON envelope wrapping an [`AccountView`].
//! With `--output table`: a stable-column-order text table.
//!
//! # Exit codes
//!
//! - 0 on success.
//! - 1 on any [`WalletError`](stellar_agent_core::error::WalletError); the
//!   envelope's `error.code` is the diagnostic.
//! - 1 with `validation.usage_error` when `--account` is omitted: the flag is
//!   required by the argument parser, and no profile supplies a fallback.

use clap::Args;
use stellar_agent_core::envelope::{Envelope, OutputFormat};
use stellar_agent_network::{AccountView, Asset, StellarRpcClient, fetch_account};

use crate::common::network::{EndpointUrlFlag, TESTNET_RPC_URL};
use crate::render::table::render_balances_table;

/// Arguments for the `balances` subcommand.
#[derive(Debug, Args)]
pub struct BalancesArgs {
    /// Required G-strkey account to query.
    #[arg(long, required = true, value_name = "G_STRKEY")]
    pub account: String,

    /// Output format: `json` (default) or `table`.
    #[arg(
        long,
        default_value_t = OutputFormat::DEFAULT,
        value_name = "FORMAT"
    )]
    pub output: OutputFormat,

    /// Stellar RPC endpoint URL.
    ///
    /// Defaults to the Stellar testnet RPC.
    /// No profile is consulted; the flag is the only source.
    #[arg(
        long,
        default_value = TESTNET_RPC_URL,
        value_name = "URL",
        value_parser = EndpointUrlFlag
    )]
    pub rpc_url: String,

    /// Trustline assets to query alongside the native XLM balance.
    ///
    /// Format: `CODE:ISSUER` (e.g. `USDC:GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN`).
    /// Repeat this flag to query multiple assets.  Assets the account does not
    /// currently trust are silently omitted from the output.
    ///
    /// Example: `--asset USDC:GA5Z...KZVN --asset EURC:GAQH...KSVN`
    #[arg(long = "asset", value_name = "CODE:ISSUER")]
    pub assets: Vec<String>,
}

/// Runs the `balances` subcommand.
///
/// Fetches the account state from the Stellar RPC endpoint and renders the
/// result according to `args.output`. Writes the rendered output to stdout.
/// Returns an exit code: `0` on success, `1` on any error.
///
/// # Errors
///
/// Never returns an `Err` variant — all errors are captured into the envelope
/// and the exit code; the caller simply exits with the returned integer.
///
/// # Panics
///
/// Only if UUID generation or `serde_json` serialisation panics
/// (effectively never in practice).
pub async fn run(args: &BalancesArgs) -> i32 {
    // Parse --asset CODE:ISSUER flags.
    // Boundary check: `Asset::parse` validates the code length and issuer
    // G-strkey; invalid inputs are rejected before the network call.
    let mut trustline_assets: Vec<Asset> = Vec::with_capacity(args.assets.len());
    for raw in &args.assets {
        match Asset::parse(raw) {
            Ok(a) => trustline_assets.push(a),
            Err(err) => {
                let envelope = Envelope::<()>::err(&err);
                print_error(&envelope, args.output);
                return 1;
            }
        }
    }

    let client = match StellarRpcClient::new(&args.rpc_url) {
        Ok(c) => c,
        Err(err) => {
            let envelope = Envelope::<()>::err(&err);
            print_error(&envelope, args.output);
            return 1;
        }
    };

    match fetch_account(&client, &args.account, &trustline_assets).await {
        Ok(view) => {
            let envelope = Envelope::ok(view);
            print_success(&envelope, args.output);
            0
        }
        Err(err) => {
            let envelope = Envelope::<()>::err(&err);
            print_error(&envelope, args.output);
            1
        }
    }
}

/// Writes a success envelope to stdout in the requested format.
fn print_success(envelope: &Envelope<AccountView>, format: OutputFormat) {
    match format {
        OutputFormat::Json =>
        {
            #[allow(clippy::print_stdout, reason = "CLI binary intentional user output")]
            match envelope.to_json_compact() {
                Ok(json) => println!("{json}"),
                Err(e) => {
                    #[allow(clippy::print_stderr, reason = "fatal serialisation failure")]
                    {
                        eprintln!("stellar-agent: JSON serialisation failed: {e}");
                    }
                }
            }
        }
        OutputFormat::Table =>
        {
            #[allow(clippy::print_stdout, reason = "CLI binary intentional user output")]
            if let Some(view) = &envelope.data {
                println!("{}", render_balances_table(view));
            }
        }
        // Wildcard required because OutputFormat is #[non_exhaustive].
        _ =>
        {
            #[allow(clippy::print_stdout, reason = "CLI binary intentional user output")]
            match envelope.to_json_compact() {
                Ok(json) => println!("{json}"),
                Err(e) => {
                    #[allow(clippy::print_stderr, reason = "fatal serialisation failure")]
                    {
                        eprintln!("stellar-agent: JSON serialisation failed: {e}");
                    }
                }
            }
        }
    }
}

/// Writes an error envelope to stdout in the requested format.
fn print_error(envelope: &Envelope<()>, format: OutputFormat) {
    match format {
        OutputFormat::Json =>
        {
            #[allow(clippy::print_stdout, reason = "CLI binary intentional user output")]
            match envelope.to_json_compact() {
                Ok(json) => println!("{json}"),
                Err(e) => {
                    #[allow(clippy::print_stderr, reason = "fatal serialisation failure")]
                    {
                        eprintln!("stellar-agent: JSON serialisation failed: {e}");
                    }
                }
            }
        }
        OutputFormat::Table => {
            // On error, table mode falls back to a plain message.
            #[allow(clippy::print_stdout, reason = "CLI binary intentional user output")]
            if let Some(err) = &envelope.error {
                println!("Error: {} — {}", err.code, err.message);
            }
        }
        // `#[non_exhaustive]` on `OutputFormat` requires a wildcard arm;
        // future variants default to JSON rather than silently joining
        // the table branch.
        _ =>
        {
            #[allow(clippy::print_stdout, reason = "CLI binary intentional user output")]
            match envelope.to_json_compact() {
                Ok(json) => println!("{json}"),
                Err(e) => {
                    #[allow(clippy::print_stderr, reason = "fatal serialisation failure")]
                    {
                        eprintln!("stellar-agent: JSON serialisation failed: {e}");
                    }
                }
            }
        }
    }
}
