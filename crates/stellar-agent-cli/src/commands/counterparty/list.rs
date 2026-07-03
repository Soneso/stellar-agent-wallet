//! `stellar-agent counterparty list [--profile <name>]` — list cached
//! `stellar.toml` bindings for the named profile.
//!
//! Instantiates a [`StellarTomlResolver`] for the profile's cache directory,
//! calls `CounterpartyResolver::list_cached`, and emits a structured JSON
//! envelope.
//!
//! # Output (JSON envelope)
//!
//! On success (including empty cache):
//!
//! ```json
//! {
//!   "ok": true,
//!   "data": {
//!     "profile": "default",
//!     "entries": [
//!       {
//!         "home_domain": "circle.com",
//!         "fetched_at": "2026-04-30T12:34:56Z",
//!         "expires_at": "2026-04-30T13:34:56Z"
//!       }
//!     ]
//!   },
//!   "request_id": "..."
//! }
//! ```
//!
//! Empty cache:
//!
//! ```json
//! { "ok": true, "data": { "profile": "default", "entries": [] }, "request_id": "..." }
//! ```
//!
//! # Errors
//!
//! Returns exit code `1` when the profile cannot be loaded, the cache
//! directory cannot be determined, the keyring is unavailable, or the cache
//! directory cannot be enumerated.
//!
//! Provides the CLI list surface for the counterparty cache, backing the
//! counterparty allowlist policy.

use std::path::PathBuf;
use std::time::Duration;

use clap::Args;
use serde::Serialize;
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::{InternalError, ValidationError, WalletError};
use stellar_agent_core::profile::loader;
use stellar_agent_network::StellarTomlResolver;
use stellar_agent_network::counterparty::CounterpartyResolver as _;

use crate::commands::counterparty::envelope::to_counterparty_envelope;
use crate::common::render;

/// Arguments for `stellar-agent counterparty list`.
#[derive(Debug, Args)]
#[non_exhaustive]
pub(crate) struct ListArgs {
    /// Emit the canonical JSON envelope.
    ///
    /// JSON is the default and only output shape for this command.  The flag is
    /// retained for explicit scripting compatibility and is therefore a no-op.
    #[arg(long)]
    pub(crate) json: bool,

    /// Profile name whose counterparty cache should be listed.
    ///
    /// Defaults to `"default"` when not supplied.
    #[arg(long, value_name = "NAME", default_value = "default")]
    pub(crate) profile: String,
}

/// A single cached binding entry in the list response.
#[derive(Debug, Serialize)]
struct CachedEntryView {
    /// Strict-ASCII home domain (e.g. `"circle.com"`).
    home_domain: String,
    /// RFC 3339 UTC timestamp when the binding was established.
    fetched_at: String,
    /// RFC 3339 UTC timestamp when the binding expires.
    expires_at: String,
}

/// Success payload for the `counterparty list` envelope.
#[derive(Debug, Serialize)]
struct ListData {
    /// Profile name whose cache was listed.
    profile: String,
    /// Verified cache entries, in arbitrary order.
    entries: Vec<CachedEntryView>,
}

/// Thin wrapper around [`stellar_agent_core::timefmt::format_rfc3339_utc`].
///
/// Formats a [`std::time::SystemTime`] as an RFC 3339 UTC string
/// (`YYYY-MM-DDThh:mm:ssZ`) using the shared implementation in
/// `stellar-agent-core::timefmt`.
///
/// # Panics
///
/// Never panics.
#[must_use]
pub(crate) fn format_system_time(t: std::time::SystemTime) -> String {
    stellar_agent_core::timefmt::format_rfc3339_utc(t)
}

/// Builds the OS-conventional counterparty cache directory for a profile.
///
/// Path: `<data_local_dir>/counterparty/<profile>`.
///
/// # Errors
///
/// Returns a [`WalletError`] when the OS-conventional state directory cannot
/// be determined.
pub(crate) fn counterparty_cache_dir(profile_name: &str) -> Result<PathBuf, WalletError> {
    directories::ProjectDirs::from("", "Soneso", "stellar-agent")
        .map(|dirs| {
            dirs.data_local_dir()
                .join("counterparty")
                .join(profile_name)
        })
        .ok_or_else(|| {
            WalletError::Internal(InternalError::UnexpectedState {
                detail: "OS-conventional state directory cannot be determined".to_owned(),
            })
        })
}

/// Runs `stellar-agent counterparty list [--profile <name>]`.
///
/// Returns `0` on success (including empty cache), `1` on error.
///
/// # Errors
///
/// Never returns `Err` — errors are captured into the exit code.
///
/// # Panics
///
/// Never panics.
pub async fn run(args: &ListArgs) -> i32 {
    let _json_output_requested = args.json;

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

    // ── Step 2: determine the cache directory.
    let cache_dir = match counterparty_cache_dir(&args.profile) {
        Ok(d) => d,
        Err(e) => {
            render::render_json(&Envelope::err(&e));
            return 1;
        }
    };

    // ── Step 3: if the cache dir does not exist yet, return an empty list
    // rather than an error — the operator has simply not yet run refresh.
    if !cache_dir.exists() {
        render::render_json(&Envelope::ok(ListData {
            profile: args.profile.clone(),
            entries: Vec::new(),
        }));
        return 0;
    }

    // ── Step 4: construct the resolver.
    let resolver =
        match StellarTomlResolver::new(&args.profile, &cache_dir, Duration::from_secs(3600)) {
            Ok(r) => r,
            Err(e) => {
                render::render_json(&to_counterparty_envelope(&e));
                return 1;
            }
        };

    // ── Step 5: list cached bindings.
    match resolver.list_cached().await {
        Ok(bindings) => {
            let entries: Vec<CachedEntryView> = bindings
                .into_iter()
                .map(|b| CachedEntryView {
                    home_domain: b.home_domain,
                    fetched_at: format_system_time(b.fetched_at),
                    expires_at: format_system_time(b.expires_at),
                })
                .collect();
            render::render_json(&Envelope::ok(ListData {
                profile: args.profile.clone(),
                entries,
            }));
            0
        }
        Err(e) => {
            tracing::warn!(
                profile = %args.profile,
                error = %e,
                "counterparty list_cached returned an error"
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
    use clap::Parser;

    #[derive(Debug, Parser)]
    struct ListArgsHarness {
        #[command(flatten)]
        args: ListArgs,
    }

    /// Verifies the wrapper delegates to timefmt correctly.
    #[test]
    fn format_system_time_unix_epoch() {
        use std::time::UNIX_EPOCH;
        assert_eq!(format_system_time(UNIX_EPOCH), "1970-01-01T00:00:00Z");
    }

    /// Verifies the wrapper delegates a known timestamp to
    /// `stellar_agent_core::timefmt::format_rfc3339_utc`.
    #[test]
    fn format_system_time_known_timestamp() {
        use std::time::{Duration, UNIX_EPOCH};
        // 2026-04-30T12:34:56Z = 1_777_552_496 s since epoch.
        let t = UNIX_EPOCH + Duration::from_secs(1_777_552_496);
        assert_eq!(format_system_time(t), "2026-04-30T12:34:56Z");
    }

    #[tokio::test]
    async fn list_nonexistent_profile_returns_exit_1() {
        let args = ListArgs {
            json: false,
            profile: "__nonexistent_list_cpty__".to_owned(),
        };
        let code = run(&args).await;
        assert_eq!(code, 1);
    }

    #[test]
    fn json_flag_is_accepted_for_explicit_scripting() {
        let parsed = ListArgsHarness::parse_from(["test", "--json", "--profile", "default"]);
        assert!(parsed.args.json);
        assert_eq!(parsed.args.profile, "default");
    }
}
