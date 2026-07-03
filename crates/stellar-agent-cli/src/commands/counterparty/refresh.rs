//! `stellar-agent counterparty refresh <home-domain> [--profile <name>]` —
//! force-refresh the cached `stellar.toml` binding for a home domain.
//!
//! Instantiates a [`StellarTomlResolver`] for the profile's cache directory,
//! calls `CounterpartyResolver::refresh`, and emits a structured JSON
//! envelope.
//!
//! # Output (JSON envelope)
//!
//! On success:
//!
//! ```json
//! {
//!   "ok": true,
//!   "data": {
//!     "profile": "default",
//!     "home_domain": "circle.com",
//!     "fetched_at": "2026-04-30T12:34:56Z",
//!     "expires_at": "2026-04-30T13:34:56Z",
//!     "cached": true
//!   },
//!   "request_id": "..."
//! }
//! ```
//!
//! On error (e.g. network failure):
//!
//! ```json
//! {
//!   "ok": false,
//!   "error": { "code": "counterparty.fetch_failed", "message": "..." },
//!   "request_id": "..."
//! }
//! ```
//!
//! # Errors
//!
//! Returns exit code `1` when the profile cannot be loaded, the cache
//! directory cannot be created, the network fetch fails, or the TOML is
//! structurally invalid.
//!
//! Provides the CLI refresh surface for the counterparty cache, backing the
//! counterparty allowlist policy.

use std::time::Duration;

use clap::Args;
use serde::Serialize;
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::{ValidationError, WalletError};
use stellar_agent_core::profile::loader;
use stellar_agent_network::StellarTomlResolver;
use stellar_agent_network::counterparty::CounterpartyResolver as _;

use crate::commands::counterparty::envelope::to_counterparty_envelope;
use crate::commands::counterparty::list::{counterparty_cache_dir, format_system_time};
use crate::common::render;

/// Arguments for `stellar-agent counterparty refresh`.
#[derive(Debug, Args)]
#[non_exhaustive]
pub(crate) struct RefreshArgs {
    /// The home domain to refresh (e.g. `circle.com`).
    ///
    /// Must be strict ASCII (no Unicode), 1-32 characters.  Homoglyph or IDN
    /// domains are rejected to prevent counterparty-binding spoofing.
    #[arg(value_name = "HOME_DOMAIN")]
    pub(crate) home_domain: String,

    /// Profile name whose counterparty cache should be updated.
    ///
    /// Defaults to `"default"` when not supplied.
    #[arg(long, value_name = "NAME", default_value = "default")]
    pub(crate) profile: String,
}

/// Success payload for the `counterparty refresh` envelope.
#[derive(Debug, Serialize)]
struct RefreshData {
    /// Profile name whose cache was updated.
    profile: String,
    /// Home domain that was refreshed.
    home_domain: String,
    /// RFC 3339 UTC timestamp when the new binding was established.
    fetched_at: String,
    /// RFC 3339 UTC timestamp when the new binding expires.
    expires_at: String,
    /// Always `true` on success.
    cached: bool,
}

/// Runs `stellar-agent counterparty refresh <home-domain> [--profile <name>]`.
///
/// Returns `0` on success, `1` on error.
///
/// # Errors
///
/// Never returns `Err` — errors are captured into the exit code.
///
/// # Panics
///
/// Never panics.
pub async fn run(args: &RefreshArgs) -> i32 {
    // ── Step 1: load profile (fails fast on nonexistent profile).
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

    // ── Step 2: determine and create the cache directory.
    let cache_dir = match counterparty_cache_dir(&args.profile) {
        Ok(d) => d,
        Err(e) => {
            render::render_json(&Envelope::err(&e));
            return 1;
        }
    };

    if let Err(e) = std::fs::create_dir_all(&cache_dir) {
        tracing::debug!(
            error = %e,
            "failed to create counterparty cache directory"
        );
        render::render_json(&Envelope::err_raw(
            "counterparty.io",
            "could not create cache directory".to_owned(),
        ));
        return 1;
    }

    // Set cache directory mode to 0o700 on Unix so no other user on the
    // system can read HMAC-protected cache files.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if let Err(e) = std::fs::set_permissions(&cache_dir, std::fs::Permissions::from_mode(0o700))
        {
            tracing::debug!(error = %e, "failed to set 0o700 mode on cache directory");
            // Non-fatal: the files themselves are 0o600; directory mode is
            // best-effort hardening.
        }
    }

    // ── Step 3: construct the resolver.
    let resolver =
        match StellarTomlResolver::new(&args.profile, &cache_dir, Duration::from_secs(3600)) {
            Ok(r) => r,
            Err(e) => {
                render::render_json(&to_counterparty_envelope(&e));
                return 1;
            }
        };

    // ── Step 4: force-refresh the binding.
    match resolver.refresh(&args.home_domain).await {
        Ok(binding) => {
            tracing::info!(
                home_domain = %binding.home_domain,
                profile = %args.profile,
                "counterparty cache refreshed; after rotation run refresh for each cached domain"
            );
            render::render_json(&Envelope::ok(RefreshData {
                profile: args.profile.clone(),
                home_domain: binding.home_domain,
                fetched_at: format_system_time(binding.fetched_at),
                expires_at: format_system_time(binding.expires_at),
                cached: true,
            }));
            0
        }
        Err(e) => {
            tracing::warn!(
                home_domain = %args.home_domain,
                profile = %args.profile,
                error = %e,
                "counterparty refresh failed"
            );
            render::render_json(&to_counterparty_envelope(&e));
            1
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
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::*;

    #[tokio::test]
    async fn refresh_nonexistent_profile_returns_exit_1() {
        let args = RefreshArgs {
            home_domain: "example.com".to_owned(),
            profile: "__nonexistent_refresh_cpty__".to_owned(),
        };
        let code = run(&args).await;
        assert_eq!(code, 1);
    }
}
