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
//!     "version": 2,
//!     "chain_id": "stellar:testnet",
//!     "rpc_url": "https://soroban-testnet.stellar.org",
//!     "network_passphrase": "Test SDF Network ; September 2015",
//!     "mcp_signer_default": { "service": "...", "account": "..." },
//!     "mcp_nonce_key_alias": { "service": "...", "account": "..." },
//!     "cross_check_threshold_stroops": 10000000000000,
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

use clap::{ArgGroup, Args};
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::{InternalError, ValidationError, WalletError};
use stellar_agent_core::profile::loader;

use crate::common::render;

/// Arguments for `stellar-agent profile show`.
#[derive(Debug, Args)]
#[non_exhaustive]
#[command(group(ArgGroup::new("profile_target").args(["name", "profile"]).required(true)))]
pub struct ShowArgs {
    /// Profile name to display, positional form.
    ///
    /// Exactly one of this positional `NAME` or the `--profile <NAME>` flag is
    /// required; supplying both, or neither, is a usage error.
    #[arg(value_name = "NAME")]
    pub name: Option<String>,

    /// Profile name to display, flag form; an alternative to the positional
    /// `NAME`.
    ///
    /// Exactly one of the positional `NAME` or this `--profile <NAME>` flag is
    /// required; supplying both, or neither, is a usage error.
    #[arg(long, value_name = "NAME")]
    pub profile: Option<String>,
}

impl ShowArgs {
    /// Returns the resolved profile name.
    ///
    /// The clap arg group over the positional `NAME` and `--profile` is
    /// `required` and mutually exclusive, so a parsed invocation sets exactly
    /// one of the two fields; this returns whichever was supplied.
    fn profile_name(&self) -> &str {
        self.name
            .as_deref()
            .or(self.profile.as_deref())
            .unwrap_or_default()
    }
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
    match loader::load(args.profile_name(), None) {
        Ok(profile) => {
            render::render_json(&Envelope::ok(profile));
            0
        }
        Err(loader::ProfileLoadError::NotFound { name, .. }) => {
            let wallet_err = WalletError::Validation(ValidationError::ProfileNotFound { name });
            render::render_json(&Envelope::err(&wallet_err));
            1
        }
        // A name that cannot be a path component is an input error, not a
        // missing profile: the loader refuses it before the path is built.
        // `ConfigInvalid` is the variant whose contract covers profile
        // resolution; `AddressInvalid` is reserved for Stellar account
        // addresses and would render the refusal as an address-parse failure.
        Err(loader::ProfileLoadError::InvalidName { name, reason }) => {
            let wallet_err = WalletError::Validation(ValidationError::ConfigInvalid {
                component: "profile",
                reason: format!("invalid profile name '{name}': {reason}"),
            });
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
                detail: format!("failed to load profile '{}': {err}", args.profile_name()),
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

    use clap::Parser;
    use clap::error::ErrorKind;
    use stellar_agent_core::profile::schema::Profile;

    use super::*;

    /// Local flatten wrapper so the `ShowArgs` clap contract can be parsed in
    /// isolation from the full command tree.
    #[derive(Debug, Parser)]
    struct Wrap {
        #[command(flatten)]
        args: ShowArgs,
    }

    #[tokio::test]
    async fn show_not_found_returns_exit_1() {
        // We test the run() function with a name that does not exist.
        // Since run() calls loader::load() which uses the default OS dir,
        // we can only test for a profile that definitively does not exist.
        // This is more of a smoke-test; the loader unit tests cover the full
        // load paths.
        let args = ShowArgs {
            name: Some("__nonexistent_profile_for_tests__".to_owned()),
            profile: None,
        };
        let code = run(&args).await;
        assert_eq!(code, 1);
    }

    #[test]
    fn positional_name_is_accepted() {
        let w = Wrap::try_parse_from(["prog", "acme"]).expect("positional parses");
        assert_eq!(w.args.profile_name(), "acme");
    }

    #[test]
    fn profile_flag_is_accepted() {
        let w = Wrap::try_parse_from(["prog", "--profile", "acme"]).expect("flag parses");
        assert_eq!(w.args.profile_name(), "acme");
    }

    #[test]
    fn both_positional_and_flag_is_a_conflict() {
        let err = Wrap::try_parse_from(["prog", "acme", "--profile", "other"]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn neither_positional_nor_flag_is_missing_required() {
        let err = Wrap::try_parse_from(["prog"]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument);
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
