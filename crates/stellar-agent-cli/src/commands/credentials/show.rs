//! `stellar-agent credentials show <name>` — show passkey metadata.
//!
//! Prints a JSON envelope with the credential metadata for the named passkey.
//! No secret material is included — the passkeys registry stores only public
//! metadata (credential name, redacted credential ID, RP-ID, transports,
//! registration timestamp). The private-key bytes never leave the
//! authenticator.
//!
//! `credential_id` is redacted to first-5-last-5 base64url in the JSON output.
//! The full ID is not logged or displayed.
//!
//! # Output envelope
//!
//! ```json
//! {"ok":true,"data":{"credential_id":"<redacted>","credential_name":"<name>","rp_id":"<rp-id>","transports":"usb","registered_at_unix_ms":0},"request_id":"..."}
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

/// Output envelope for `credentials show`.
#[derive(Debug, Serialize)]
struct ShowEnvelope {
    /// Credential ID, redacted to first-5-last-5 base64url.
    credential_id: String,
    credential_name: String,
    rp_id: String,
    transports: String,
    registered_at_unix_ms: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Args
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for `credentials show`.
#[derive(Debug, Args)]
#[non_exhaustive]
pub struct ShowArgs {
    /// The credential name to show.
    #[arg(value_name = "NAME")]
    pub name: String,

    /// Profile name override. Defaults to `STELLAR_AGENT_PROFILE` env var,
    /// then `"default"`.
    #[arg(long = "profile", value_name = "PROFILE")]
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

/// Runs `credentials show`.
///
/// Returns `0` on success, `1` on any error.
pub fn run(args: &ShowArgs) -> i32 {
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

    let meta = match mgr.show(&args.name) {
        Ok(m) => m,
        Err(e) => return emit_error(credentials_error_code(&e), e.to_string()),
    };

    render_json(&Envelope::ok(ShowEnvelope {
        credential_id: redact_first5_last5(&meta.credential_id_b64url),
        credential_name: meta.credential_name,
        rp_id: meta.rp_id,
        transports: meta.transports,
        registered_at_unix_ms: meta.registered_at_unix_ms,
    }));
    0
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn emit_error(code: &'static str, message: String) -> i32 {
    render_json(&Envelope::<()>::err_raw(code, message));
    1
}
