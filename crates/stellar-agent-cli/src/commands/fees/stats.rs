//! `stellar-agent fees stats` subcommand.

use clap::Args;
use stellar_agent_core::envelope::{Envelope, OutputFormat};
use stellar_agent_core::error::{ValidationError, WalletError};
use stellar_agent_core::profile::ResolvedProfileName;
use stellar_agent_network::{
    FeeStatsView, NetworkContext, StellarRpcClient, fetch_fee_stats, validate_rpc_url,
};

use crate::common::network::{EndpointUrlFlag, TESTNET_RPC_URL};
use crate::common::profile_access::load_profile_reconciled;
use crate::common::render::{render_json, sanitize_for_table};
use crate::render::table::render_fee_stats_table;

/// Arguments for `stellar-agent fees stats`.
#[derive(Debug, Args)]
pub struct FeesStatsArgs {
    /// Profile name whose RPC URL should be used.
    #[arg(long, value_name = "NAME")]
    pub profile: Option<String>,

    /// Stellar RPC endpoint override.
    #[arg(long, value_name = "URL", value_parser = EndpointUrlFlag)]
    pub rpc_url: Option<String>,

    /// Output format: `json` (default) or `table`.
    #[arg(long, default_value_t = OutputFormat::DEFAULT, value_name = "FORMAT")]
    pub output: OutputFormat,
}

/// The endpoint `fees stats` reads: a profile's primary endpoint, which
/// carries the profile's primary credential while `--rpc-url` leaves it
/// unchanged, or a bare URL without any credential.
enum FeeStatsEndpoint {
    /// The primary endpoint of the profile `--profile` names.
    Profile(NetworkContext),
    /// `--rpc-url`, or the testnet default, without a profile.
    Url(String),
}

impl FeeStatsEndpoint {
    fn client(&self) -> Result<StellarRpcClient, WalletError> {
        match self {
            Self::Profile(context) => context.primary_client(),
            Self::Url(url) => StellarRpcClient::new(url),
        }
    }
}

/// Runs `stellar-agent fees stats`.
pub async fn run(args: &FeesStatsArgs) -> i32 {
    let endpoint = match resolve_rpc_url(args) {
        Ok(endpoint) => endpoint,
        Err(err) => {
            let envelope = Envelope::<()>::err(&err);
            print_error(&envelope, args.output);
            return 1;
        }
    };

    let client = match endpoint.client() {
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

fn resolve_rpc_url(args: &FeesStatsArgs) -> Result<FeeStatsEndpoint, WalletError> {
    if let Some(name) = &args.profile {
        let profile = load_profile_reconciled(&ResolvedProfileName::from_flag(name))
            .map_err(|e| e.to_wallet_error())?;
        let context = crate::common::network::network_context_for_command(
            &profile,
            name,
            crate::common::network::EndpointFlags {
                network: None,
                rpc_url: args.rpc_url.as_deref(),
                secondary_rpc_url: None,
            },
        )?;
        return Ok(FeeStatsEndpoint::Profile(context));
    }
    let url = match args.rpc_url.as_deref() {
        Some(url) => {
            validate_rpc_url_for_cli(url)?;
            url.to_owned()
        }
        None => TESTNET_RPC_URL.to_owned(),
    };
    Ok(FeeStatsEndpoint::Url(url))
}

/// Refuses an `--rpc-url` without `--profile` that breaks the HTTPS-without-
/// credentials rule, naming the failed rule and never the URL.
fn validate_rpc_url_for_cli(url: &str) -> Result<(), WalletError> {
    validate_rpc_url(url).map_err(|err| {
        WalletError::Validation(ValidationError::ConfigInvalid {
            component: "--rpc-url",
            reason: err.to_string(),
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test-only assertions")]

    use super::*;

    /// Without `--profile` the endpoint is the bare URL variant, the one
    /// whose client is built without a credential: no profile is loaded and
    /// no keyring entry is read, with or without `--rpc-url`.
    #[test]
    fn fees_stats_without_a_profile_sends_no_credential() {
        let default = FeesStatsArgs {
            profile: None,
            rpc_url: None,
            output: OutputFormat::DEFAULT,
        };
        assert!(
            matches!(
                resolve_rpc_url(&default).unwrap(),
                FeeStatsEndpoint::Url(url) if url == TESTNET_RPC_URL
            ),
            "the testnet default without a profile"
        );
        let flag = FeesStatsArgs {
            profile: None,
            rpc_url: Some("https://custom-rpc.example".to_owned()),
            output: OutputFormat::DEFAULT,
        };
        assert!(
            matches!(
                resolve_rpc_url(&flag).unwrap(),
                FeeStatsEndpoint::Url(url) if url == "https://custom-rpc.example"
            ),
            "any HTTPS flag URL without credentials works without a profile"
        );
    }

    /// A rejected `--rpc-url` without `--profile` names the failed rule and
    /// never the URL or a host list.
    #[test]
    fn a_rejected_rpc_url_names_the_rule_not_the_url() {
        use stellar_agent_test_support::rejected_value::{CREDENTIAL_MARKER, assert_no_marker};
        for (url, expected_rule) in [
            (
                format!("http://custom-rpc.example/{CREDENTIAL_MARKER}"),
                "must use https",
            ),
            (
                format!("https://user:{CREDENTIAL_MARKER}@custom-rpc.example"),
                "embedded credentials",
            ),
            (format!("{CREDENTIAL_MARKER} %%"), "invalid RPC URL"),
        ] {
            let err = resolve_rpc_url(&FeesStatsArgs {
                profile: None,
                rpc_url: Some(url),
                output: OutputFormat::DEFAULT,
            })
            .err()
            .unwrap();
            assert_eq!(err.code(), "validation.config_invalid");
            let msg = err.to_string();
            assert!(msg.contains(expected_rule), "{msg}");
            assert!(!msg.contains("allow-list"), "{msg}");
            assert!(!msg.contains("custom-rpc.example"), "{msg}");
            assert_no_marker(&err, CREDENTIAL_MARKER);
            let envelope = serde_json::to_string(&Envelope::<()>::err(&err)).unwrap();
            assert!(!envelope.contains(CREDENTIAL_MARKER), "{envelope}");
        }
    }
}
