//! `stellar-agent credentials delete <name>` — delete a registered passkey.
//!
//! Removes the named credential from the per-profile passkeys registry after
//! an optional confirmation prompt. Use `--yes` to skip the prompt in
//! non-interactive contexts.
//!
//! # Output envelope (success)
//!
//! ```json
//! {"status":"deleted","credential_name":"<name>"}
//! ```
//!
//! # Output envelope (not found)
//!
//! ```json
//! {"status":"error","error":"credential '<name>' not found"}
//! ```

use std::io::{self, BufRead as _, Write as _};

use clap::Args;
use serde::Serialize;
use stellar_agent_smart_account::managers::credentials::{CredentialsError, CredentialsManager};

use crate::common::{resolve_profile_name, validate_path_component_ascii_safe};

// ─────────────────────────────────────────────────────────────────────────────
// Wire types
// ─────────────────────────────────────────────────────────────────────────────

/// Output envelope for `credentials delete`.
#[derive(Debug, Serialize)]
struct DeleteEnvelope {
    status: &'static str,
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
        return emit_error(&format!("invalid profile name '{profile}': {reason}"));
    }

    let mgr = match CredentialsManager::from_defaults_readonly(&profile, &args.rp_id) {
        Ok(m) => m,
        Err(e) => return emit_error(&e.to_string()),
    };

    // Verify the credential exists before asking for confirmation.
    match mgr.show(&args.name) {
        Ok(_) => {}
        Err(CredentialsError::NotFound { name }) => {
            return emit_error(&format!("credential '{name}' not found"));
        }
        Err(e) => return emit_error(&e.to_string()),
    }

    // Confirmation prompt (skipped with --yes).
    if !args.yes && !confirm_delete(&args.name) {
        #[allow(clippy::print_stdout, reason = "CLI binary intentional output")]
        {
            println!(
                "{}",
                serde_json::to_string(&serde_json::json!({
                    "status": "canceled",
                    "credential_name": &args.name
                }))
                .unwrap_or_default()
            );
        }
        return 1;
    }

    match mgr.delete(&args.name) {
        Ok(()) => {
            let envelope = DeleteEnvelope {
                status: "deleted",
                credential_name: args.name.clone(),
            };
            print_json(&envelope);
            0
        }
        Err(CredentialsError::NotFound { name }) => {
            emit_error(&format!("credential '{name}' not found"))
        }
        Err(e) => emit_error(&e.to_string()),
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
