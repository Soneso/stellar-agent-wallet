//! `stellar-agent counterparty evict <home-domain> [--profile <name>]` —
//! delete one cached `stellar.toml` binding.
//!
//! This is a targeted incident-response command: it removes the single cache
//! file for a domain without deleting the rest of the per-profile cache.

use clap::Args;
use serde::Serialize;
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::{ValidationError, WalletError};
use stellar_agent_core::profile::loader;
use stellar_agent_network::counterparty::cache::cache_file_path;
use stellar_agent_network::counterparty::fetch::validate_home_domain;

use crate::commands::counterparty::envelope::to_counterparty_envelope;
use crate::commands::counterparty::list::counterparty_cache_dir;
use crate::common::render;

/// Arguments for `stellar-agent counterparty evict`.
#[derive(Debug, Args)]
#[non_exhaustive]
pub(crate) struct EvictArgs {
    /// The home domain whose cache file should be removed.
    #[arg(value_name = "HOME_DOMAIN")]
    pub(crate) home_domain: String,

    /// Profile name whose counterparty cache should be updated.
    #[arg(long, value_name = "NAME", default_value = "default")]
    pub(crate) profile: String,
}

#[derive(Debug, Serialize)]
struct EvictData {
    profile: String,
    home_domain: String,
    evicted: bool,
}

fn evict_envelope(profile: &str, home_domain: &str, evicted: bool) -> Envelope<EvictData> {
    Envelope::ok(EvictData {
        profile: profile.to_owned(),
        home_domain: home_domain.to_owned(),
        evicted,
    })
}

/// Runs `stellar-agent counterparty evict <home-domain> [--profile <name>]`.
///
/// Returns `0` on success, including when the target cache file was already
/// absent; returns `1` for profile, domain, or filesystem errors.
pub async fn run(args: &EvictArgs) -> i32 {
    let _profile = match loader::load(&args.profile, None) {
        Ok(p) => p,
        Err(loader::ProfileLoadError::NotFound { name, .. }) => {
            let err = WalletError::Validation(ValidationError::ProfileNotFound { name });
            render::render_json(&Envelope::err(&err));
            return 1;
        }
        Err(e) => {
            tracing::debug!(profile = %args.profile, error = %e, "profile load failed");
            let err = WalletError::Validation(ValidationError::ProfileNotFound {
                name: args.profile.clone(),
            });
            render::render_json(&Envelope::err(&err));
            return 1;
        }
    };

    if let Err(e) = validate_home_domain(&args.home_domain) {
        render::render_json(&to_counterparty_envelope(&e));
        return 1;
    }

    let cache_dir = match counterparty_cache_dir(&args.profile) {
        Ok(d) => d,
        Err(e) => {
            render::render_json(&Envelope::err(&e));
            return 1;
        }
    };
    let cache_path = cache_file_path(&cache_dir, &args.home_domain);
    let evicted = match std::fs::remove_file(&cache_path) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => {
            tracing::debug!(error = %e, "counterparty cache evict failed");
            render::render_json(&Envelope::<()>::err_raw(
                "counterparty.io",
                "could not remove counterparty cache file".to_owned(),
            ));
            return 1;
        }
    };

    render::render_json(&evict_envelope(&args.profile, &args.home_domain, evicted));
    0
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test-only")]

    use super::*;
    use clap::Parser;

    #[derive(Debug, Parser)]
    struct EvictArgsHarness {
        #[command(flatten)]
        args: EvictArgs,
    }

    #[test]
    fn parse_evict_args() {
        let parsed = EvictArgsHarness::parse_from(["test", "circle.com", "--profile", "alice"]);
        assert_eq!(parsed.args.home_domain, "circle.com");
        assert_eq!(parsed.args.profile, "alice");
    }

    #[test]
    fn evict_envelope_shape() {
        let env = evict_envelope("alice", "circle.com", true);
        assert!(env.ok);
        let data = env.data.unwrap();
        assert_eq!(data.profile, "alice");
        assert_eq!(data.home_domain, "circle.com");
        assert!(data.evicted);
    }
}
