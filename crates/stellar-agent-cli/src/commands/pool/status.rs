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
//! JSON object with `initialised`, `pool_size`, `free`, `in_flight`, and an
//! optional `pending` checkpoint naming the transaction hash and resume command.
//! A pending checkpoint whose receipt is ambiguous also names the
//! acknowledgement command that releases it.

use clap::Args;
use serde::{Deserialize, Serialize};
use stellar_agent_core::envelope::{Envelope, OutputFormat};
use stellar_agent_core::profile::receipt::{ReceiptStatus, ReceiptStore};
use stellar_agent_core::profile::schema::PoolInitialization;

use crate::common::profile_access::{load_profile_reconciled, profile_access_envelope};
use crate::common::render::render_json;
use crate::common::resolve_profile_name;

/// Arguments for `stellar-agent pool status`.
#[derive(Debug, Args)]
pub struct PoolStatusArgs {
    /// Profile name.
    ///
    /// Defaults to the `STELLAR_AGENT_PROFILE` env var, then `"default"`.
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
    /// Recovery checkpoint, including the transaction hash when recorded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending: Option<serde_json::Value>,
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
/// The acknowledgement command for a pending initialization whose submission
/// receipt reconciliation records as ambiguous.
///
/// `pool init --resume` retries such an attempt only once an operator states
/// out of band that it did not apply, so the one state that needs the
/// statement names the verb that makes it. Every other receipt state, and a
/// receipt store this process cannot read, yield no command: the reader is a
/// diagnostic and answers with what it has.
fn operator_clear_command(profile_name: &str, pending: &PoolInitialization) -> Option<String> {
    let submission = pending.submission.as_ref()?;
    let receipt = ReceiptStore::open(profile_name)
        .ok()?
        .get(&submission.envelope_hash)
        .ok()??;
    (receipt.status == ReceiptStatus::Ambiguous).then(|| {
        format!(
            "stellar-agent tx receipt clear {} --acknowledge --profile {profile_name}",
            submission.envelope_hash
        )
    })
}

pub async fn run(args: &PoolStatusArgs) -> i32 {
    // `--profile`, then `STELLAR_AGENT_PROFILE`, then `"default"`.
    let resolved_profile = resolve_profile_name(args.profile.as_deref());
    let profile_name = resolved_profile.name.clone();
    // Reconciled: a profile file whose owner-key coordinate names a different
    // profile is refused rather than used under this name.
    let profile = match load_profile_reconciled(&resolved_profile, None) {
        Ok(p) => p,
        Err(e) => {
            tracing::debug!(profile = %profile_name, error = %e, "profile access refused");
            render_json(&profile_access_envelope(&e, &profile_name));
            return 1;
        }
    };

    let pending = profile.pool_initialization.as_ref().map(|pending| {
        let mut fields = serde_json::json!({
            "channel_count": pending.channels.len(),
            "tx_hash": pending.submission.as_ref().map(|submission| &submission.tx_hash),
            "seed_ready": pending.seed_ready,
            "resume_with": format!("stellar-agent pool init --resume --profile {profile_name}")
        });
        if let Some(command) = operator_clear_command(&profile_name, pending)
            && let Some(object) = fields.as_object_mut()
        {
            object.insert("clear_with".to_owned(), command.into());
        }
        fields
    });
    let (initialised, pool_size) = match &profile.pool_config {
        Some(cfg) => (true, cfg.pool_size),
        None => (false, 0),
    };

    let result = PoolStatusResult {
        initialised: initialised && pending.is_none(),
        pending,
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
