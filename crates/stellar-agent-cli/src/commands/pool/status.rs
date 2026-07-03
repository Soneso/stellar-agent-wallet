//! `stellar-agent pool status` subcommand.
//!
//! Displays pool utilisation: pool_size, free, and in_flight counts.  The
//! free / in_flight split reflects the in-memory runtime state; since the CLI
//! is a single-process, single-invocation tool (no persistent in-memory pool
//! across calls), free = pool_size and in_flight = 0 for all channels not
//! currently inside an active submission.  The primary utility is verifying
//! the pool is initialised and how many channels exist.
//!
//! # Output
//!
//! JSON object with `initialised`, `pool_size`, `free`, `in_flight`.

use clap::Args;
use serde::{Deserialize, Serialize};
use stellar_agent_core::envelope::{Envelope, OutputFormat};
use stellar_agent_core::error::{ValidationError, WalletError};
use stellar_agent_core::profile::loader::{self, ProfileLoadError};

use crate::common::render::render_json;

/// Arguments for `stellar-agent pool status`.
#[derive(Debug, Args)]
pub struct PoolStatusArgs {
    /// Profile name.  Defaults to `"default"`.
    #[arg(long, value_name = "NAME")]
    pub profile: Option<String>,

    /// Output format: `json` (default) or `table`.
    #[arg(long, default_value_t = OutputFormat::DEFAULT, value_name = "FORMAT")]
    pub output: OutputFormat,
}

/// Result of `pool status`.
#[derive(Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PoolStatusResult {
    /// Whether the pool has been initialised (`pool init` completed).
    pub initialised: bool,
    /// Total pool size from the persisted `PoolConfig`.
    pub pool_size: usize,
    /// Number of free channels.
    ///
    /// Reflects the persisted config of a stateless CLI process.
    /// In a fresh CLI invocation (no concurrent in-flight submissions),
    /// `free == pool_size`.  Live utilisation during concurrent submission
    /// is reported by the concurrent-submission allocator; `free` here is not
    /// a live counter.
    pub free: usize,
    /// Number of in-flight channels.
    ///
    /// Always `0` in a fresh CLI invocation.  This field reflects the
    /// persisted config of a stateless CLI process — do NOT interpret
    /// `in_flight: 0` as "safe to flood"; live utilisation is tracked
    /// by the concurrent-submission allocator.
    pub in_flight: usize,
    /// Interpretation note.
    ///
    /// `free` and `in_flight` reflect the persisted channel config of a
    /// stateless CLI process, not a live allocator.  Live utilisation
    /// arrives with the concurrent-submission allocator.
    pub note: &'static str,
}

/// Runs `stellar-agent pool status`.
///
/// Returns `0` on success, `1` on error.
///
/// # Errors
///
/// Never returns `Err`; errors are captured in the exit code.
///
/// # Panics
///
/// Never panics.
pub async fn run(args: &PoolStatusArgs) -> i32 {
    let profile_name = args.profile.as_deref().unwrap_or("default");
    let profile = match loader::load(profile_name, None) {
        Ok(p) => p,
        Err(e) => {
            let err = match e {
                ProfileLoadError::NotFound { name, .. } => {
                    WalletError::Validation(ValidationError::ProfileNotFound { name })
                }
                _ => WalletError::Validation(ValidationError::ProfileNotFound {
                    name: profile_name.to_owned(),
                }),
            };
            render_json(&Envelope::<()>::err(&err));
            return 1;
        }
    };

    let (initialised, pool_size) = match &profile.pool_config {
        Some(cfg) => (true, cfg.pool_size),
        None => (false, 0),
    };

    let result = PoolStatusResult {
        initialised,
        pool_size,
        free: pool_size, // no in-flight channels in a fresh CLI invocation
        in_flight: 0,
        note: "free/in_flight reflect the persisted config of a stateless CLI process, \
               not a live allocator; live utilisation arrives with the \
               concurrent-submission allocator",
    };

    render_json(&Envelope::ok(result));
    0
}
