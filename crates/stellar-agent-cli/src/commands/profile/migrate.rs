//! `stellar-agent profile migrate <name>` — migrate a profile to the current schema version.
//!
//! Reads the named profile, applies any pending schema migrations atomically
//! (temp-file + rename), and prints the outcome as a JSON envelope.
//!
//! If the profile is already at the current version, the command succeeds
//! without modifying the file.
//!
//! # Atomicity
//!
//! The migration writes to a temporary file in the same directory as the
//! profile, then atomically renames it to the profile path.  A failure during
//! migration leaves the original file in place.
//!
//! **NFS/SMB/FUSE caveat:** `rename(2)` is atomic on single-host POSIX
//! filesystems.  Networked filesystem mounts may have weaker rename semantics.
//! See `docs/runbooks/profile-migration.md` for operator guidance.
//!
//! # Output
//!
//! On no-op (already current):
//!
//! ```json
//! {"ok":true,"data":{"status":"no_op","version":1},"request_id":"..."}
//! ```
//!
//! On successful migration:
//!
//! ```json
//! {"ok":true,"data":{"status":"migrated","from_version":1,"to_version":2,"path":"..."},"request_id":"..."}
//! ```
//!
//! On error:
//!
//! ```json
//! {"ok":false,"error":{"code":"...","message":"..."},"request_id":"..."}
//! ```
//!
//! # Errors
//!
//! Returns exit code `1` on any migration failure.

use clap::{ArgGroup, Args};
use serde::Serialize;
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::{InternalError, ValidationError, WalletError};
use stellar_agent_core::profile::loader::default_profile_dir;
use stellar_agent_core::profile::migrate::{MigrateError, MigrateOutcome, migrate};

use crate::common::render;

/// Arguments for `stellar-agent profile migrate`.
#[derive(Debug, Args)]
#[non_exhaustive]
#[command(group(ArgGroup::new("profile_target").args(["name", "profile"]).required(true)))]
pub struct MigrateArgs {
    /// Profile name to migrate, positional form.
    ///
    /// Exactly one of this positional `NAME` or the `--profile <NAME>` flag is
    /// required; supplying both, or neither, is a usage error.
    #[arg(value_name = "NAME")]
    pub name: Option<String>,

    /// Profile name to migrate, flag form; an alternative to the positional
    /// `NAME`.
    ///
    /// Exactly one of the positional `NAME` or this `--profile <NAME>` flag is
    /// required; supplying both, or neither, is a usage error.
    #[arg(long, value_name = "NAME")]
    pub profile: Option<String>,
}

impl MigrateArgs {
    /// Returns the resolved profile name.
    ///
    /// The clap arg group over the positional `NAME` and `--profile` is
    /// `required` and mutually exclusive, so a parsed invocation sets exactly
    /// one of the two fields; this returns whichever was supplied.
    pub(super) fn profile_name(&self) -> &str {
        self.name
            .as_deref()
            .or(self.profile.as_deref())
            .unwrap_or_default()
    }
}

/// JSON payload returned by the migrate command on success.
#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
#[non_exhaustive]
pub enum MigrateResult {
    /// The profile was already at the current version; no file was written.
    NoOp {
        /// The current (already-latest) version.
        version: u32,
    },
    /// The profile was migrated from `from_version` to `to_version`.
    Migrated {
        /// The version before migration.
        from_version: u32,
        /// The version after migration.
        to_version: u32,
        /// The path of the migrated profile file.
        path: String,
    },
}

/// Runs `stellar-agent profile migrate <name>`.
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
pub async fn run(args: &MigrateArgs) -> i32 {
    let profile_dir = match default_profile_dir() {
        Ok(d) => d,
        Err(err) => {
            let wallet_err = WalletError::Internal(InternalError::UnexpectedState {
                detail: format!("could not determine profile directory: {err}"),
            });
            render::render_json(&Envelope::err(&wallet_err));
            return 1;
        }
    };

    match migrate(args.profile_name(), &profile_dir) {
        Ok(MigrateOutcome::NoOp { version }) => {
            render::render_json(&Envelope::ok(MigrateResult::NoOp { version }));
            0
        }
        Ok(MigrateOutcome::Migrated {
            from_version,
            to_version,
            path,
        }) => {
            render::render_json(&Envelope::ok(MigrateResult::Migrated {
                from_version,
                to_version,
                path: path.display().to_string(),
            }));
            0
        }
        // `#[non_exhaustive]` on MigrateOutcome requires a wildcard arm.
        // No other variants exist currently; this is a forward-compat guard.
        Ok(_) => {
            render::render_json(&Envelope::ok(MigrateResult::NoOp { version: 1 }));
            0
        }
        Err(MigrateError::Load { ref source, .. }) => {
            // Check if it was a profile-not-found error (source is Box<ProfileLoadError>).
            let wallet_err = if matches!(
                source.as_ref(),
                stellar_agent_core::profile::loader::ProfileLoadError::NotFound { .. }
            ) {
                WalletError::Validation(ValidationError::ProfileNotFound {
                    name: args.profile_name().to_owned(),
                })
            } else {
                WalletError::Internal(InternalError::UnexpectedState {
                    detail: format!(
                        "migration load failed for '{}': {source}",
                        args.profile_name()
                    ),
                })
            };
            render::render_json(&Envelope::err(&wallet_err));
            1
        }
        Err(err) => {
            let wallet_err = WalletError::Internal(InternalError::UnexpectedState {
                detail: format!("migration failed for '{}': {err}", args.profile_name()),
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

    use super::*;

    /// Local flatten wrapper so the `MigrateArgs` clap contract can be parsed
    /// in isolation from the full command tree.
    #[derive(Debug, Parser)]
    struct Wrap {
        #[command(flatten)]
        args: MigrateArgs,
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
}
