//! `stellar-agent pool list` subcommand.
//!
//! Lists all pool channels with BIP-44 index, G-strkey public key, and the
//! current on-chain sequence number fetched via `fetch_account`.  Reads the
//! pool configuration from the profile TOML (persisted by `pool init`).
//!
//! # Output
//!
//! JSON array of per-channel objects.

use clap::Args;
use serde::{Deserialize, Serialize};
use stellar_agent_core::envelope::{Envelope, OutputFormat};
use stellar_agent_core::error::{InternalError, ValidationError, WalletError};
use stellar_agent_core::profile::loader::{self, ProfileLoadError};
use stellar_agent_network::{StellarRpcClient, fetch_account};
use stellar_agent_pool::PoolError;

use crate::common::render::render_json;

/// Arguments for `stellar-agent pool list`.
#[derive(Debug, Args)]
pub struct PoolListArgs {
    /// Profile name.  Defaults to `"default"`.
    #[arg(long, value_name = "NAME")]
    pub profile: Option<String>,

    /// Output format: `json` (default) or `table`.
    #[arg(long, default_value_t = OutputFormat::DEFAULT, value_name = "FORMAT")]
    pub output: OutputFormat,
}

/// Per-channel entry in the `pool list` output.
#[derive(Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PoolChannelEntry {
    /// BIP-44 derivation index (`m/44'/148'/index'`).
    pub index: u32,
    /// `G...` Stellar strkey (public; no secret).
    pub public_key: String,
    /// Current on-chain sequence number, or `null` if the RPC fetch failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequence_number: Option<i64>,
}

/// Result of `pool list`.
#[derive(Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PoolListResult {
    /// Total pool size.
    pub pool_size: usize,
    /// Per-channel entries.
    ///
    /// Sequence numbers are fetched live from the network; `in_flight` is
    /// always `false` in a stateless CLI invocation.  Live per-channel
    /// in-flight status is available from the concurrent-submission allocator.
    pub channels: Vec<PoolChannelEntry>,
    /// Interpretation note.
    ///
    /// Channel sequence numbers reflect the live on-chain state fetched at
    /// list time.  In-flight status reflects the persisted config of a
    /// stateless CLI process — `in_flight: false` does NOT mean "safe to
    /// flood"; live utilisation is tracked by the concurrent-submission
    /// allocator.
    pub note: &'static str,
}

fn pool_err_to_wallet_err(e: &PoolError) -> WalletError {
    WalletError::Internal(InternalError::UnexpectedState {
        detail: e.to_string(),
    })
}

/// Runs `stellar-agent pool list`.
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
pub async fn run(args: &PoolListArgs) -> i32 {
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

    let pool_cfg = match &profile.pool_config {
        Some(c) => c,
        None => {
            let err = pool_err_to_wallet_err(&PoolError::NotInitialised);
            render_json(&Envelope::<()>::err(&err));
            return 1;
        }
    };

    let client = match StellarRpcClient::new(&profile.rpc_url) {
        Ok(c) => c,
        Err(e) => {
            render_json(&Envelope::<()>::err(&e));
            return 1;
        }
    };

    let mut channels: Vec<PoolChannelEntry> = Vec::with_capacity(pool_cfg.channels.len());
    for rec in &pool_cfg.channels {
        let seq = fetch_account(&client, &rec.public_key, &[])
            .await
            .ok()
            .map(|v| v.sequence_number);
        channels.push(PoolChannelEntry {
            index: rec.index,
            public_key: rec.public_key.clone(),
            sequence_number: seq,
        });
    }

    let result = PoolListResult {
        pool_size: pool_cfg.pool_size,
        channels,
        note: "sequence numbers are live on-chain; in_flight status reflects persisted \
               config of a stateless CLI process (live utilisation arrives with the \
               concurrent-submission allocator)",
    };

    render_json(&Envelope::ok(result));
    0
}
