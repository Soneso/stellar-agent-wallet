//! `stellar-agent counterparty` subcommand group.
//!
//! Parent module for all counterparty-resolution CLI subcommands.  Provides:
//!
//! - [`list`] — list cached `stellar.toml` bindings for a profile.
//! - [`refresh`] — force-refresh the cached `stellar.toml` for a home domain.
//! - [`evict`] — delete one cached home-domain binding.
//! - [`warm_up`] — refresh all HOME_DOMAIN policy allowlist entries.
//! - [`rotate_hmac_key`] — rotate the per-profile cache HMAC key.
//!
//! # Dispatch
//!
//! [`CounterpartyArgs`] is a `clap` [`Args`] struct with a nested
//! [`CounterpartySubcommand`] enum.  The top-level [`crate::main`] function
//! routes `Commands::Counterparty(args)` to [`run`], which delegates to the
//! appropriate subcommand handler.
//!
//! # Cache directory
//!
//! Cache files are stored at the OS-conventional path:
//! `~/.local/share/stellar-agent/counterparty/<profile>/` (Linux).  On macOS:
//! `~/Library/Application Support/Soneso.stellar-agent/counterparty/<profile>/`.
//! On Windows: `%LOCALAPPDATA%\Soneso\stellar-agent\data\counterparty\<profile>\`.
//!
//! Provides the CLI surface for counterparty resolution and HOME_DOMAIN
//! binding cache management, backing the counterparty allowlist policy.

pub(crate) mod envelope;
pub mod evict;
pub mod list;
pub mod refresh;
pub mod rotate_hmac_key;
pub mod warm_up;

use clap::{Args, Subcommand};

/// Arguments for the `counterparty` subcommand group.
#[derive(Debug, Args)]
#[non_exhaustive]
pub struct CounterpartyArgs {
    /// The counterparty subcommand to run.
    #[command(subcommand)]
    pub subcommand: CounterpartySubcommand,
}

/// Subcommands of `stellar-agent counterparty`.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum CounterpartySubcommand {
    /// List cached `stellar.toml` bindings for a profile.
    ///
    /// Reads the per-profile cache directory, verifies each entry's HMAC, and
    /// prints a JSON envelope with the list of valid cached home domains and
    /// their expiry timestamps.  Entries whose HMAC fails validation are
    /// silently skipped; run `stellar-agent counterparty refresh <domain>` to
    /// re-mint them.
    List(list::ListArgs),

    /// Force-refresh the cached `stellar.toml` for a home domain.
    ///
    /// Fetches `https://<home-domain>/.well-known/stellar.toml`, parses it,
    /// HMAC-protects the body with the per-profile cache key, and writes the
    /// result to the local cache.  Existing cache entries for the domain are
    /// replaced atomically.
    ///
    /// On success prints a JSON envelope with the refreshed binding.  On
    /// failure (network error, invalid TOML, keyring unavailable) prints a
    /// typed error envelope.
    Refresh(refresh::RefreshArgs),

    /// Delete a single cached `stellar.toml` binding.
    ///
    /// Removes only the cache file for the requested home domain and leaves
    /// other cached domains untouched.
    Evict(evict::EvictArgs),

    /// Refresh every HOME_DOMAIN entry currently configured in the policy
    /// counterparty allowlist.
    #[command(name = "warm-up")]
    WarmUp(warm_up::WarmUpArgs),

    /// Rotate the per-profile counterparty cache HMAC key.
    ///
    /// Existing cache files will fail HMAC verification after rotation and
    /// must be refreshed.
    #[command(name = "rotate-hmac-key")]
    RotateHmacKey(rotate_hmac_key::RotateHmacKeyArgs),
}

/// Runs the `counterparty` subcommand group.
///
/// Dispatches to the appropriate subcommand handler.
///
/// Returns an exit code: `0` on success, `1` on any error.
///
/// # Errors
///
/// Never returns `Err` — errors are captured into the exit code.
///
/// # Panics
///
/// Never panics.
pub async fn run(args: &CounterpartyArgs) -> i32 {
    match &args.subcommand {
        CounterpartySubcommand::List(a) => list::run(a).await,
        CounterpartySubcommand::Refresh(a) => refresh::run(a).await,
        CounterpartySubcommand::Evict(a) => evict::run(a).await,
        CounterpartySubcommand::WarmUp(a) => warm_up::run(a).await,
        CounterpartySubcommand::RotateHmacKey(a) => rotate_hmac_key::run(a).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Debug, Parser)]
    struct CounterpartyArgsHarness {
        #[command(flatten)]
        args: CounterpartyArgs,
    }

    #[test]
    fn parses_new_counterparty_subcommands() {
        let evict = CounterpartyArgsHarness::parse_from([
            "test",
            "evict",
            "circle.com",
            "--profile",
            "alice",
        ]);
        assert!(matches!(
            evict.args.subcommand,
            CounterpartySubcommand::Evict(_)
        ));

        let warm_up =
            CounterpartyArgsHarness::parse_from(["test", "warm-up", "--profile", "alice"]);
        assert!(matches!(
            warm_up.args.subcommand,
            CounterpartySubcommand::WarmUp(_)
        ));

        let rotate =
            CounterpartyArgsHarness::parse_from(["test", "rotate-hmac-key", "--profile", "alice"]);
        assert!(matches!(
            rotate.args.subcommand,
            CounterpartySubcommand::RotateHmacKey(_)
        ));
    }
}
