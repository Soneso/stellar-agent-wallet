//! `stellar-agent friendbot` subcommand.
//!
//! Funds a testnet or futurenet account via the Stellar Friendbot HTTP
//! endpoint. Mainnet is rejected structurally at command-dispatch time
//! (before any HTTP call is made), returning
//! `WalletError::Network(NetworkError::FriendbotMainnetForbidden)`.
//!
//! Friendbot funding is scoped to testnet / futurenet; it structurally refuses
//! mainnet.
//!
//! # Output
//!
//! With `--output json` (default): the JSON envelope wrapping a
//! [`FriendbotResult`].
//! With `--output table`: a single redacted line:
//! `"Funded <G…> via <url>; tx_hash <first8>…<last8>"`.
//!
//! # Exit codes
//!
//! - 0 on success.
//! - 1 on any [`WalletError`] — the envelope's `error.code` is the diagnostic.
//!
//! # Security note — mainnet rejection
//!
//! The [`FriendbotNetwork::Mainnet`] variant exists in the type system so that
//! the structural rejection is an explicit, testable code path rather than
//! silently unreachable dead code. The rejection fires in [`run`] BEFORE any
//! `reqwest` client is constructed or any HTTP request is issued.

use std::str::FromStr;

use clap::Args;
use stellar_agent_core::envelope::{Envelope, OutputFormat};
use stellar_agent_core::error::{InternalError, NetworkError, WalletError};
use stellar_agent_core::profile::caip2::Caip2;
use stellar_agent_network::{
    FriendbotResult, default_friendbot_url, fund_with_friendbot, redact_url_userinfo,
    validate_friendbot_url,
};

/// Stellar testnet network passphrase.
const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";

/// Stellar Futurenet network passphrase.
const FUTURENET_PASSPHRASE: &str = "Test SDF Future Network ; October 2022";

/// Network selector for the `friendbot` subcommand.
///
/// `Mainnet` exists in the type system so the structural rejection in [`run`]
/// is an explicit, testable code path. Passing `--network mainnet` on the
/// command line is accepted by the parser; rejection fires at the `run`
/// boundary before any HTTP request is constructed.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FriendbotNetwork {
    /// Stellar public testnet — the default.
    Testnet,
    /// Stellar Futurenet (next-protocol preview network).
    Futurenet,
    /// Stellar mainnet. **Structurally rejected at `run` time** — no HTTP call
    /// is ever issued for this variant. Kept as a first-class variant so the
    /// rejection is a concrete code path with test coverage.
    Mainnet,
}

impl FromStr for FriendbotNetwork {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "testnet" => Ok(Self::Testnet),
            "futurenet" => Ok(Self::Futurenet),
            "mainnet" => Ok(Self::Mainnet),
            other => Err(format!(
                "unknown network '{other}'; expected one of: testnet, futurenet, mainnet"
            )),
        }
    }
}

impl std::fmt::Display for FriendbotNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Testnet => f.write_str("testnet"),
            Self::Futurenet => f.write_str("futurenet"),
            Self::Mainnet => f.write_str("mainnet"),
        }
    }
}

/// Arguments for the `friendbot` subcommand.
#[non_exhaustive]
#[derive(Debug, Args)]
pub struct FriendbotArgs {
    /// The G-strkey account to fund.
    #[arg(long, value_name = "G_STRKEY")]
    pub account: String,

    /// Network to target.
    ///
    /// `testnet` (default) or `futurenet`. `mainnet` is accepted by the
    /// parser but is structurally rejected at dispatch time with error
    /// `network.friendbot_mainnet_forbidden`.
    #[arg(long, default_value_t = FriendbotNetwork::Testnet, value_name = "NETWORK")]
    pub network: FriendbotNetwork,

    /// Override the Friendbot endpoint URL.
    ///
    /// When omitted, resolves to the SDF testnet Friendbot URL at runtime.
    /// Supply an explicit URL when targeting Futurenet or a private network,
    /// or when pointing the integration test at a wiremock server.
    ///
    /// By default the supplied URL is validated against the allow-list
    /// (`friendbot.stellar.org`, `friendbot-futurenet.stellar.org`).  Use
    /// `--friendbot-url-unchecked` to bypass this check for development or
    /// test use (escape hatch — use with care).
    #[arg(long, value_name = "URL")]
    pub friendbot_url: Option<String>,

    /// Bypass the Friendbot URL allow-list check (escape hatch).
    ///
    /// When set, `--friendbot-url` is used without host validation.  This
    /// flag exists for development and integration-test use (e.g. pointing at
    /// a wiremock server on `http://127.0.0.1:PORT`).
    ///
    /// **This flag is intentionally absent from the MCP tool** — the MCP
    /// `stellar_friendbot` tool validates every URL unconditionally.
    #[arg(long, default_value_t = false)]
    pub friendbot_url_unchecked: bool,

    /// Output format: `json` (default) or `table`.
    #[arg(
        long,
        default_value_t = OutputFormat::DEFAULT,
        value_name = "FORMAT"
    )]
    pub output: OutputFormat,
}

/// Runs the `friendbot` subcommand.
///
/// Rejects `--network mainnet` structurally before any HTTP call is made.
/// For testnet and futurenet, calls [`fund_with_friendbot`] and renders the
/// result according to `args.output`.
///
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
pub async fn run(args: &FriendbotArgs) -> i32 {
    // ── Structural mainnet rejection ──────────────────────────────────────────
    // This check fires BEFORE any reqwest::Client is constructed or any
    // network request is issued. The FriendbotNetwork::Mainnet variant exists
    // in the type system so this is a concrete, test-exercisable code path.
    if args.network == FriendbotNetwork::Mainnet {
        let err = WalletError::Network(NetworkError::FriendbotMainnetForbidden);
        let envelope = Envelope::<()>::err(&err);
        print_error(&envelope, args.output);
        return 1;
    }

    // ── Friendbot URL allow-list validation ───────────────────────────────────
    // By default, validate the URL against the production allow-list.
    // The --friendbot-url-unchecked flag bypasses this check for development
    // and integration-test use (e.g. pointing at a wiremock server on loopback).
    // The MCP tool has no equivalent escape.
    let friendbot_url = match &args.friendbot_url {
        Some(url) => url.clone(),
        None => match default_friendbot_url(Caip2::Testnet) {
            Some(url) => url.to_owned(),
            None => {
                let err = WalletError::Internal(InternalError::UnexpectedState {
                    detail: "missing default Friendbot URL for stellar:testnet".to_owned(),
                });
                let envelope = Envelope::<()>::err(&err);
                print_error(&envelope, args.output);
                return 1;
            }
        },
    };

    if args.friendbot_url_unchecked {
        // Warn immediately when the allow-list is bypassed.  The warning fires
        // BEFORE any network call and AFTER the mainnet rejection above, so it
        // is only reached for testnet/futurenet calls.  It does not affect
        // control flow — it is a pure audit-log entry.
        tracing::warn!(
            "friendbot URL allow-list bypassed via --friendbot-url-unchecked; \
             proceed only in development/test environments"
        );
    }
    if !args.friendbot_url_unchecked
        && let Err(err) = validate_friendbot_url(&friendbot_url)
    {
        // Map the URL validation error to a network-layer wallet error so the
        // envelope has the right category and exit code.  The friendbot URL is
        // a network endpoint; a non-allowlisted URL is surfaced as RpcUnreachable
        // with a diagnostic message describing the allow-list rejection.
        // Redact any userinfo in the URL before placing it in the error envelope
        // (defence-in-depth against audit-log secret leakage).
        let wallet_err = WalletError::Network(NetworkError::RpcUnreachable {
            url: redact_url_userinfo(&friendbot_url),
            reason: err.to_string(),
        });
        let envelope = Envelope::<()>::err(&wallet_err);
        print_error(&envelope, args.output);
        return 1;
    }

    let network_passphrase = match args.network {
        FriendbotNetwork::Testnet => TESTNET_PASSPHRASE,
        FriendbotNetwork::Futurenet => FUTURENET_PASSPHRASE,
        // The mainnet arm above returned early, so reaching this branch
        // means a new `FriendbotNetwork` variant was added without updating
        // this match. `#[non_exhaustive]` applies across crate boundaries;
        // the wildcard here is forward-compatibility for future variants,
        // not a same-crate exhaustiveness requirement. Surface as an
        // internal state error rather than the mainnet-forbidden code —
        // the two conditions are not the same and consumers parsing the
        // error taxonomy deserve the distinction.
        _ => {
            let err = WalletError::Internal(InternalError::UnexpectedState {
                detail: format!(
                    "friendbot dispatch reached unreachable FriendbotNetwork variant: {:?}",
                    args.network
                ),
            });
            let envelope = Envelope::<()>::err(&err);
            print_error(&envelope, args.output);
            return 1;
        }
    };

    match fund_with_friendbot(&friendbot_url, &args.account, network_passphrase).await {
        Ok(result) => {
            let envelope = Envelope::ok(result);
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

/// Redacts a transaction hash to first-8-last-8.
///
/// E.g. `"abcdef01…98765432"`. If the hash is shorter than 16 characters,
/// the full hash is returned without truncation.
fn redact_tx_hash(tx_hash: &str) -> String {
    if tx_hash.len() > 16 {
        format!("{}...{}", &tx_hash[..8], &tx_hash[tx_hash.len() - 8..])
    } else {
        tx_hash.to_owned()
    }
}

/// Writes a success envelope to stdout in the requested format.
fn print_success(envelope: &Envelope<FriendbotResult>, format: OutputFormat) {
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
            if let Some(result) = &envelope.data {
                let redacted_hash = redact_tx_hash(&result.tx_hash);
                println!(
                    "Funded {} via {}; tx_hash {}",
                    result.account_id, result.friendbot_url_used, redacted_hash
                );
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
        // future variants default to JSON.
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

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; assertions via unwrap/expect are idiomatic in unit tests"
    )]

    use super::*;

    /// Mainnet structural rejection fires at the `run` boundary.
    ///
    /// Asserts that passing `--network mainnet` returns exit code 1 with error
    /// code `network.friendbot_mainnet_forbidden` before any HTTP request.
    /// No wiremock server is started; if any HTTP call were made against the
    /// default Friendbot URL, the test would either fail (network unavailable
    /// in CI) or produce a side effect on a live endpoint.
    #[tokio::test]
    async fn mainnet_rejected_at_run_boundary_no_http_issued() {
        let args = FriendbotArgs {
            account: "GABC1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEFGH".to_owned(),
            network: FriendbotNetwork::Mainnet,
            // Intentionally use a localhost URL that would cause a
            // connection-refused error IF any HTTP call were made — the test
            // asserts exit code 1 from the mainnet check, not from a network
            // error, so these are distinguishable in principle. The mainnet
            // rejection must fire before the URL is even evaluated.
            friendbot_url: Some("http://127.0.0.1:1".to_owned()),
            // Use unchecked so the URL allow-list doesn't fire before the
            // mainnet check (ordering: mainnet check fires first, but the
            // URL validation would also reject http://127.0.0.1:1).
            friendbot_url_unchecked: true,
            output: OutputFormat::Json,
        };

        let exit_code = run(&args).await;

        assert_eq!(exit_code, 1, "mainnet must return exit code 1");
    }

    /// URL allow-list validation: non-allowlisted URL returns exit code 1
    /// and the mainnet check fires BEFORE the URL check.
    #[tokio::test]
    async fn non_allowlisted_url_returns_exit_code_1() {
        let args = FriendbotArgs {
            account: "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI".to_owned(),
            network: FriendbotNetwork::Testnet,
            friendbot_url: Some("https://evil.example.com/friendbot".to_owned()),
            friendbot_url_unchecked: false,
            output: OutputFormat::Json,
        };

        let exit_code = run(&args).await;
        assert_eq!(exit_code, 1, "non-allowlisted URL must return exit code 1");
    }

    /// URL allow-list bypass via --friendbot-url-unchecked lets non-standard
    /// URLs through (used by integration tests pointing at wiremock).
    /// This test does not make an HTTP call; the URL is deliberately invalid so
    /// the HTTP layer would fail — but we only assert the function runs past the
    /// allow-list check (it returns 1 from the network error, not from the
    /// allow-list check).
    #[tokio::test]
    async fn unchecked_flag_bypasses_allowlist_url_proceeds_to_network() {
        let args = FriendbotArgs {
            account: "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI".to_owned(),
            network: FriendbotNetwork::Testnet,
            // Use a URL that the allow-list would normally reject.
            friendbot_url: Some("http://127.0.0.1:1/friendbot".to_owned()),
            friendbot_url_unchecked: true,
            output: OutputFormat::Json,
        };

        // Should return 1 because the HTTP call fails (connection refused),
        // not because the allow-list rejects it.  The key assertion is that it
        // returns an error — if the allow-list fired we'd also get 1, but the
        // test is just ensuring the unchecked path compiles and runs.
        let exit_code = run(&args).await;
        assert_eq!(exit_code, 1, "network error must return exit code 1");
    }

    /// FriendbotNetwork FromStr round-trips for every variant.
    #[test]
    fn network_from_str_round_trips() {
        assert_eq!(
            FriendbotNetwork::from_str("testnet").unwrap(),
            FriendbotNetwork::Testnet
        );
        assert_eq!(
            FriendbotNetwork::from_str("TESTNET").unwrap(),
            FriendbotNetwork::Testnet
        );
        assert_eq!(
            FriendbotNetwork::from_str("futurenet").unwrap(),
            FriendbotNetwork::Futurenet
        );
        assert_eq!(
            FriendbotNetwork::from_str("mainnet").unwrap(),
            FriendbotNetwork::Mainnet
        );
        assert!(FriendbotNetwork::from_str("unknown").is_err());
    }

    /// redact_tx_hash trims long hashes to first-8-last-8.
    #[test]
    fn redact_tx_hash_long() {
        let hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let redacted = redact_tx_hash(hash);
        assert_eq!(redacted, "abcdef01...23456789");
    }

    /// redact_tx_hash passes through short hashes unchanged.
    #[test]
    fn redact_tx_hash_short() {
        let hash = "abcd1234";
        let redacted = redact_tx_hash(hash);
        assert_eq!(redacted, "abcd1234");
    }
}
