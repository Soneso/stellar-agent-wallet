//! `stellar-agent profile list` — list known profile names.
//!
//! Reads the OS-conventional profile directory and prints one profile name per
//! line in JSON envelope format.
//!
//! # Output
//!
//! On success: a JSON array of profile names, sorted alphabetically.
//!
//! ```json
//! {"ok":true,"data":["default","mainnet-ops"],"request_id":"..."}
//! ```
//!
//! On empty directory:
//!
//! ```json
//! {"ok":true,"data":[],"request_id":"..."}
//! ```
//!
//! # Errors
//!
//! Returns exit code `1` when the OS-conventional state directory cannot be
//! determined.  The error is emitted as a JSON envelope on stdout.

use clap::Args;
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::{InternalError, WalletError};
use stellar_agent_core::profile::loader;

use crate::common::render;

/// Arguments for `stellar-agent profile list`.
#[derive(Debug, Args)]
#[non_exhaustive]
pub struct ListArgs;

/// Runs `stellar-agent profile list`.
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
pub async fn run(_args: &ListArgs) -> i32 {
    match loader::list_profiles() {
        Ok(names) => {
            render::render_json(&Envelope::ok(names));
            0
        }
        Err(err) => {
            let wallet_err = WalletError::Internal(InternalError::UnexpectedState {
                detail: format!("profile list failed: {err}"),
            });
            render::render_json(&Envelope::err(&wallet_err));
            1
        }
    }
}
