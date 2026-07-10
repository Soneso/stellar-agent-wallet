//! `stellar-agent credentials delete <name>` — delete a registered passkey.
//!
//! Removes the named credential from the per-profile passkeys registry after
//! an optional confirmation prompt. Use `--yes` to skip the prompt in
//! non-interactive contexts.
//!
//! # Output envelope (success)
//!
//! ```json
//! {"ok":true,"data":{"credential_name":"<name>"},"request_id":"..."}
//! ```
//!
//! # Output envelope (not found)
//!
//! ```json
//! {"ok":false,"error":{"code":"credentials.not_found","message":"credential '<name>' not found"},"request_id":"..."}
//! ```

use std::io::{self, BufRead as _, Write as _};

use clap::Args;
use serde::Serialize;
use stellar_agent_core::envelope::Envelope;
use stellar_agent_smart_account::managers::credentials::CredentialsManager;

use crate::commands::credentials::credentials_error_code;
use crate::common::render::render_json;
use crate::common::{resolve_profile_name, validate_path_component_ascii_safe};

// ─────────────────────────────────────────────────────────────────────────────
// Wire types
// ─────────────────────────────────────────────────────────────────────────────

/// JSON success payload for `credentials delete`, carried under the envelope
/// `data` field.
#[derive(Debug, Serialize)]
struct DeleteSuccess {
    credential_name: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Args
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for `credentials delete`.
#[derive(Debug, Args)]
#[non_exhaustive]
pub struct DeleteArgs {
    /// The credential name to delete.
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

    /// Skip the confirmation prompt.
    #[arg(long = "yes", short = 'y')]
    pub yes: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// Dispatch
// ─────────────────────────────────────────────────────────────────────────────

/// Runs `credentials delete`.
///
/// Returns `0` on success, `1` on any error or user cancellation.
pub fn run(args: &DeleteArgs) -> i32 {
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

    // Verify the credential exists before asking for confirmation.
    if let Err(e) = mgr.show(&args.name) {
        return emit_error(credentials_error_code(&e), e.to_string());
    }

    // Confirmation prompt (skipped with --yes).
    if !args.yes && !confirm_delete(&args.name) {
        return emit_error(
            "credentials.delete_canceled",
            format!("deletion of '{}' was canceled by the operator", args.name),
        );
    }

    match mgr.delete(&args.name) {
        Ok(()) => {
            render_json(&Envelope::ok(DeleteSuccess {
                credential_name: args.name.clone(),
            }));
            0
        }
        Err(e) => emit_error(credentials_error_code(&e), e.to_string()),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Prompts the user to confirm deletion of a credential.
///
/// Returns `true` if the user typed `y` or `yes` (case-insensitive).
fn confirm_delete(name: &str) -> bool {
    #[allow(clippy::print_stdout, reason = "CLI binary intentional prompt output")]
    {
        print!("Delete passkey '{name}'? This cannot be undone. [y/N]: ");
    }
    let _ = io::stdout().flush();
    let mut line = String::new();
    match io::stdin().lock().read_line(&mut line) {
        Ok(0) | Err(_) => false,
        Ok(_) => {
            let trimmed = line.trim().to_ascii_lowercase();
            trimmed == "y" || trimmed == "yes"
        }
    }
}

fn emit_error(code: &'static str, message: String) -> i32 {
    render_json(&Envelope::<()>::err_raw(code, message));
    1
}
