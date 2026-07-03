//! `stellar-agent profile show <name>` — print a profile's resolved configuration.
//!
//! Loads the named profile (applying env-var overlays) and prints its resolved
//! fields as a JSON envelope to stdout.  Keyring entry references are printed
//! as opaque `{service, account}` objects — never the secret itself.
//!
//! # Output
//!
//! On success:
//!
//! ```json
//! {
//!   "ok": true,
//!   "data": {
//!     "version": 1,
//!     "chain_id": "stellar:testnet",
//!     "rpc_url": "https://soroban-testnet.stellar.org",
//!     "network_passphrase": "Test SDF Network ; September 2015",
//!     "mcp_signer_default": { "service": "...", "account": "..." },
//!     "mcp_nonce_key_alias": { "service": "...", "account": "..." },
//!     "usd_threshold": 10000000000000,
//!     "audit_log_path": "...",
//!     "mcp_disabled": false
//!   },
//!   "request_id": "..."
//! }
//! ```
//!
//! # Errors
//!
//! Returns exit code `1` when the profile is not found or cannot be loaded.

use clap::Args;
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::{InternalError, ValidationError, WalletError};
use stellar_agent_core::profile::loader;

use crate::common::render;

/// Arguments for `stellar-agent profile show`.
#[derive(Debug, Args)]
#[non_exhaustive]
pub struct ShowArgs {
    /// The profile name to display.
    #[arg(value_name = "NAME")]
    pub name: String,
}

/// Runs `stellar-agent profile show <name>`.
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
pub async fn run(args: &ShowArgs) -> i32 {
    match loader::load(&args.name, None) {
        Ok(profile) => {
            render::render_json(&Envelope::ok(profile));
            0
        }
        Err(loader::ProfileLoadError::NotFound { name, .. }) => {
            let wallet_err = WalletError::Validation(ValidationError::ProfileNotFound { name });
            render::render_json(&Envelope::err(&wallet_err));
            1
        }
        Err(loader::ProfileLoadError::VersionUnsupported {
            name,
            found,
            supported,
        }) => {
            let wallet_err = WalletError::Internal(InternalError::UnexpectedState {
                detail: format!(
                    "profile '{name}' has unsupported version {found}; \
                     this wallet supports version {supported}"
                ),
            });
            render::render_json(&Envelope::err(&wallet_err));
            1
        }
        Err(err) => {
            let wallet_err = WalletError::Internal(InternalError::UnexpectedState {
                detail: format!("failed to load profile '{}': {err}", args.name),
            });
            render::render_json(&Envelope::err(&wallet_err));
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

    use stellar_agent_core::profile::schema::Profile;

    use super::*;

    #[tokio::test]
    async fn show_not_found_returns_exit_1() {
        // We test the run() function with a name that does not exist.
        // Since run() calls loader::load() which uses the default OS dir,
        // we can only test for a profile that definitively does not exist.
        // This is more of a smoke-test; the loader unit tests cover the full
        // load paths.
        let args = ShowArgs {
            name: "__nonexistent_profile_for_tests__".to_owned(),
        };
        let code = run(&args).await;
        assert_eq!(code, 1);
    }

    #[test]
    fn profile_serde_shows_no_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let profile = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
            .audit_log_path(dir.path().join("audit.log"))
            .build();
        let json = serde_json::to_string(&profile).unwrap();
        // Ensure the JSON does not contain anything that looks like a secret.
        // mcp_signer_default / mcp_nonce_key_alias expose service+account (opaque refs).
        assert!(json.contains("\"mcp_signer_default\""));
        assert!(json.contains("\"mcp_nonce_key_alias\""));
        // Verify only service+account appear, not any secret payload.
        assert!(json.contains("\"service\""));
        assert!(json.contains("\"account\""));
        // No raw key bytes (they wouldn't be here, but assert for documentation).
        assert!(!json.contains("seed"));
        assert!(!json.contains("secret"));
    }
}
