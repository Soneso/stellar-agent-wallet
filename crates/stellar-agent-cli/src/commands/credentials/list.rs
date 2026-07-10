//! `stellar-agent credentials list` — list registered passkeys.
//!
//! Prints a JSON envelope with the list of credential metadata records for
//! the resolved profile. `credential_id` values are redacted to
//! first-5-last-5 base64url before display.
//!
//! # Output envelope
//!
//! ```json
//! {"ok":true,"data":{"credentials":[{"credential_id":"<redacted>","credential_name":"<name>","rp_id":"<rp-id>","registered_at_unix_ms":0}]},"request_id":"..."}
//! ```

use clap::Args;
use serde::Serialize;
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::redact_first5_last5;
use stellar_agent_smart_account::managers::credentials::CredentialsManager;

use crate::commands::credentials::credentials_error_code;
use crate::common::render::render_json;
use crate::common::{resolve_profile_name, validate_path_component_ascii_safe};

// ─────────────────────────────────────────────────────────────────────────────
// Wire types
// ─────────────────────────────────────────────────────────────────────────────

/// Output envelope for `credentials list`.
#[derive(Debug, Serialize)]
struct ListEnvelope {
    credentials: Vec<CredentialListItem>,
}

/// Per-credential item in the `list` output.
///
/// `credential_id` is redacted to first-5-last-5 base64url.
#[derive(Debug, Serialize)]
struct CredentialListItem {
    credential_id: String,
    credential_name: String,
    rp_id: String,
    registered_at_unix_ms: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Args
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for `credentials list`.
#[derive(Debug, Args)]
#[non_exhaustive]
pub struct ListArgs {
    /// Profile name override. Defaults to `STELLAR_AGENT_PROFILE` env var,
    /// then `"default"`.
    #[arg(long = "profile", value_name = "NAME")]
    pub profile: Option<String>,

    /// RP-ID for the passkeys registry (defaults to `"localhost"`).
    ///
    /// Must be a valid DNS domain string per WebAuthn Level 2 §5.1.2.
    #[arg(long = "rp-id", value_name = "DOMAIN", default_value = "localhost")]
    pub rp_id: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Dispatch
// ─────────────────────────────────────────────────────────────────────────────

/// Runs `credentials list`.
///
/// Returns `0` on success, `1` on any error.
pub fn run(args: &ListArgs) -> i32 {
    let profile = resolve_profile_name(args.profile.as_deref());

    // Validate profile name as a path component.
    if let Err(reason) = validate_path_component_ascii_safe(&profile) {
        return emit_error(
            "credentials.invalid_profile_name",
            format!("invalid profile name '{profile}': {reason}"),
        );
    }

    let mgr = match CredentialsManager::from_defaults_readonly(&profile, &args.rp_id) {
        Ok(m) => m,
        Err(e) => return emit_error(credentials_error_code(&e), e.to_string()),
    };

    let creds = match mgr.list() {
        Ok(c) => c,
        Err(e) => return emit_error(credentials_error_code(&e), e.to_string()),
    };

    // Redact credential_id before display.
    let items: Vec<CredentialListItem> = creds
        .into_iter()
        .map(|c| CredentialListItem {
            credential_id: redact_first5_last5(&c.credential_id_b64url),
            credential_name: c.credential_name,
            rp_id: c.rp_id,
            registered_at_unix_ms: c.registered_at_unix_ms,
        })
        .collect();

    render_json(&Envelope::ok(ListEnvelope { credentials: items }));
    0
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn emit_error(code: &'static str, message: String) -> i32 {
    render_json(&Envelope::<()>::err_raw(code, message));
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_credential_id_typical() {
        let id = "AABBCCDDEEFFGGHHIIJJKK"; // 22 chars
        let redacted = redact_first5_last5(id);
        assert_eq!(redacted, "AABBC...IJJKK");
    }

    #[test]
    fn redact_credential_id_short_passthrough() {
        let short = "ABCDE";
        assert_eq!(redact_first5_last5(short), "ABCDE");
    }
}
