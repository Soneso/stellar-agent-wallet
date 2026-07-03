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

use clap::Args;
use serde::Serialize;
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::{InternalError, ValidationError, WalletError};
use stellar_agent_core::profile::loader::default_profile_dir;
use stellar_agent_core::profile::migrate::{MigrateError, MigrateOutcome, migrate};

use crate::common::render;

/// Arguments for `stellar-agent profile migrate`.
#[derive(Debug, Args)]
#[non_exhaustive]
pub struct MigrateArgs {
    /// The profile name to migrate.
    #[arg(value_name = "NAME")]
    pub name: String,
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

    match migrate(&args.name, &profile_dir) {
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
                    name: args.name.clone(),
                })
            } else {
                WalletError::Internal(InternalError::UnexpectedState {
                    detail: format!("migration load failed for '{}': {source}", args.name),
                })
            };
            render::render_json(&Envelope::err(&wallet_err));
            1
        }
        Err(err) => {
            let wallet_err = WalletError::Internal(InternalError::UnexpectedState {
                detail: format!("migration failed for '{}': {err}", args.name),
            });
            render::render_json(&Envelope::err(&wallet_err));
            1
        }
    }
}
