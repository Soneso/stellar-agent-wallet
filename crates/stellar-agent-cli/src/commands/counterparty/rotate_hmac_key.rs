//! `stellar-agent counterparty rotate-hmac-key [--profile <name>]` — rotate the
//! per-profile counterparty cache HMAC key.
//!
//! After rotation, existing cache files will fail HMAC verification and should
//! be refreshed with `stellar-agent counterparty warm-up` or targeted
//! `stellar-agent counterparty refresh <home-domain>` calls.

use clap::Args;
use serde::Serialize;
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::{ValidationError, WalletError};
use stellar_agent_core::profile::loader;
use stellar_agent_network::keyring::{init_platform_keyring_store, rotate_keyring_secret_32};

use crate::common::render;

/// Arguments for `stellar-agent counterparty rotate-hmac-key`.
#[derive(Debug, Args)]
#[non_exhaustive]
pub(crate) struct RotateHmacKeyArgs {
    /// Profile name whose counterparty cache HMAC key should be rotated.
    #[arg(long, value_name = "NAME", default_value = "default")]
    pub(crate) profile: String,
}

#[derive(Debug, Serialize)]
struct RotateHmacKeyData {
    profile: String,
    rotated: bool,
    key_kind: &'static str,
    cache_invalidated: bool,
    note: &'static str,
}

fn rotate_hmac_key_envelope(profile: &str) -> Envelope<RotateHmacKeyData> {
    Envelope::ok(RotateHmacKeyData {
        profile: profile.to_owned(),
        rotated: true,
        key_kind: "hmac_32_bytes",
        cache_invalidated: true,
        note: "existing counterparty cache files must be refreshed",
    })
}

/// Runs `stellar-agent counterparty rotate-hmac-key [--profile <name>]`.
///
/// Returns `0` on success, `1` when the profile cannot be loaded, the platform
/// keyring cannot be initialized, or the keyring write fails.
pub async fn run(args: &RotateHmacKeyArgs) -> i32 {
    let profile = match loader::load(&args.profile, None) {
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

    if let Err(e) = init_platform_keyring_store() {
        render::render_json(&Envelope::err(&e));
        return 1;
    }

    let entry_ref = &profile.counterparty_cache_key_id;
    match rotate_keyring_secret_32(&entry_ref.service, &entry_ref.account) {
        Ok(()) => {
            tracing::info!(
                "counterparty HMAC key rotated; cached stellar.toml entries must be refreshed"
            );
            render::render_json(&rotate_hmac_key_envelope(&args.profile));
            0
        }
        Err(e) => {
            // The shared helper classifies keyring failures — surface its
            // error unchanged so environmental causes (a non-interactive
            // Windows session) keep their typed code instead of collapsing
            // into "not found".
            tracing::debug!(error = %e, "counterparty HMAC key rotation failed");
            render::render_json(&Envelope::err(&e));
            1
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test-only")]

    use super::*;
    use clap::Parser;

    #[derive(Debug, Parser)]
    struct RotateHmacKeyArgsHarness {
        #[command(flatten)]
        args: RotateHmacKeyArgs,
    }

    #[test]
    fn parse_rotate_hmac_key_args() {
        let parsed = RotateHmacKeyArgsHarness::parse_from(["test", "--profile", "alice"]);
        assert_eq!(parsed.args.profile, "alice");
    }

    #[test]
    fn rotate_hmac_key_envelope_shape() {
        let env = rotate_hmac_key_envelope("alice");
        assert!(env.ok);
        let data = env.data.unwrap();
        assert_eq!(data.profile, "alice");
        assert!(data.rotated);
        assert_eq!(data.key_kind, "hmac_32_bytes");
        assert!(data.cache_invalidated);
    }
}
