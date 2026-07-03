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
//! {"credential_id":"<redacted>","credential_name":"<name>","rp_id":"<rp-id>","transports":"usb","registered_at_unix_ms":0}
//! ```

use clap::Args;
use serde::Serialize;
use stellar_agent_core::redact_first5_last5;
use stellar_agent_smart_account::managers::credentials::{CredentialsError, CredentialsManager};

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
        return emit_error(&format!("invalid profile name '{profile}': {reason}"));
    }

    let mgr = match CredentialsManager::from_defaults_readonly(&profile, &args.rp_id) {
        Ok(m) => m,
        Err(e) => return emit_error(&e.to_string()),
    };

    let meta = match mgr.show(&args.name) {
        Ok(m) => m,
        Err(CredentialsError::NotFound { name }) => {
            return emit_error(&format!("credential '{name}' not found"));
        }
        Err(e) => return emit_error(&e.to_string()),
    };

    let envelope = ShowEnvelope {
        credential_id: redact_first5_last5(&meta.credential_id_b64url),
        credential_name: meta.credential_name,
        rp_id: meta.rp_id,
        transports: meta.transports,
        registered_at_unix_ms: meta.registered_at_unix_ms,
    };
    print_json(&envelope);
    0
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

#[allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "CLI binary intentional JSON output; errors to stderr"
)]
fn print_json<T: Serialize>(value: &T) {
    match serde_json::to_string(value) {
        Ok(s) => println!("{s}"),
        Err(e) => eprintln!("stellar-agent: JSON serialisation error: {e}"),
    }
}

#[allow(clippy::print_stdout, reason = "CLI binary intentional JSON output")]
fn emit_error(detail: &str) -> i32 {
    let envelope = serde_json::json!({ "status": "error", "error": detail });
    println!(
        "{}",
        serde_json::to_string(&envelope).unwrap_or_else(|_| String::from(
            r#"{"status":"error","error":"serialisation_failed"}"#
        ))
    );
    1
}
