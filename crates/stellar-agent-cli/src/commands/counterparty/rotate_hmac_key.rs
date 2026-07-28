//! `stellar-agent counterparty rotate-hmac-key [--profile <name>]` — rotate the
//! per-profile counterparty cache HMAC key.
//!
//! After rotation, existing cache files will fail HMAC verification and should
//! be refreshed with `stellar-agent counterparty warm-up` or targeted
//! `stellar-agent counterparty refresh <home-domain>` calls.

use clap::Args;
use serde::Serialize;
use stellar_agent_core::envelope::Envelope;
use stellar_agent_network::keyring::{init_platform_keyring_store, rotate_keyring_secret_32};

use crate::common::profile_access::{load_profile_reconciled, profile_access_envelope};
use crate::common::{render, resolve_profile_name};

/// Arguments for `stellar-agent counterparty rotate-hmac-key`.
#[derive(Debug, Args)]
#[non_exhaustive]
pub(crate) struct RotateHmacKeyArgs {
    /// Profile name whose counterparty cache HMAC key should be rotated.
    ///
    /// Defaults to the `STELLAR_AGENT_PROFILE` env var, then `"default"`.
    #[arg(long = "profile", value_name = "NAME")]
    pub(crate) profile: Option<String>,
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
    // `--profile`, then `STELLAR_AGENT_PROFILE`, then `"default"`.
    let resolved_profile = resolve_profile_name(args.profile.as_deref());
    let profile_name = resolved_profile.name.clone();

    // Reconciled: a profile file whose owner-key coordinate names a
    // different profile is refused rather than used under this name.
    let profile = match load_profile_reconciled(&resolved_profile, None) {
        Ok(p) => p,
        Err(e) => {
            tracing::debug!(profile = %profile_name, error = %e, "profile access refused");
            render::render_json(&profile_access_envelope(&e, &profile_name));
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
            render::render_json(&rotate_hmac_key_envelope(&profile_name));
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
        assert_eq!(parsed.args.profile.as_deref(), Some("alice"));
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
