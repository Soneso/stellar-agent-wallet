//! Read-only approval inspection by public nonce.

use clap::Args;
use stellar_agent_core::{
    envelope::Envelope,
    error::{WalletError, WalletStateError},
    profile::schema::Profile,
};
use stellar_agent_network::policy_state::{
    PersistedWindowStore,
    approvals::status::{ApprovalStatusSnapshot, status_read_error},
};

use crate::common::{
    profile_access::{load_profile_reconciled, profile_access_envelope},
    render::render_json,
    resolve_profile_name,
};

/// Arguments for `approve status`.
#[derive(Debug, Args)]
pub struct StatusArgs {
    /// The public approval nonce returned during preparation.
    #[arg(value_name = "APPROVAL_ID", allow_hyphen_values = true)]
    pub approval_id: String,
    /// The profile that owns the approval.
    #[arg(long, value_name = "NAME")]
    pub profile: Option<String>,
}

/// Prints the shared JSON status view. Returns one on a typed refusal.
pub async fn run(args: StatusArgs) -> i32 {
    let resolved = resolve_profile_name(args.profile.as_deref());
    let profile = match load_profile_reconciled(&resolved) {
        Ok(profile) => profile,
        Err(error) => {
            render_json(&profile_access_envelope(&error));
            return 1;
        }
    };
    let result = crate::commands::smart_account::common::ensure_keyring_store()
        .and_then(|()| {
            stellar_agent_core::timefmt::now_unix_ms()
                .map_err(|error| WalletError::WalletState(WalletStateError::clock_error(&error)))
        })
        .and_then(|now| inspect(&resolved.name, &profile, &args.approval_id, now));
    match result {
        Ok(view) => {
            render_json(&Envelope::ok(view));
            0
        }
        Err(error) => {
            render_json(&Envelope::<()>::err(&error));
            1
        }
    }
}

fn inspect(
    name: &str,
    profile: &Profile,
    nonce: &str,
    now: u64,
) -> Result<serde_json::Value, WalletError> {
    let store = PersistedWindowStore::for_profile(name);
    let snapshot = ApprovalStatusSnapshot::read(&store, profile, name, now)
        .map_err(|error| status_read_error(&error))?;
    snapshot.inspect(
        nonce,
        &super::approval_store_dir()?.join(format!("{name}.toml")),
    )
}

#[cfg(test)]
mod tests;
