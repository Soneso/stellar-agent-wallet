//! `stellar-agent credentials` subcommand group.
//!
//! Passkey credential lifecycle for the Stellar agent wallet — registration,
//! listing, deletion, and show.
//!
//! # Subcommands
//!
//! - `credentials add-passkey <name>` — register a new WebAuthn passkey via
//!   browser handoff. Opens the OS default browser to the bridge's registration
//!   URL, polls the approval store until the ceremony completes (or times out),
//!   and writes the credential metadata to the passkeys registry.
//! - `credentials list [--profile <name>]` — list registered passkeys for a
//!   profile. Redacts `credential_id` before display.
//! - `credentials delete <name> [--profile <name>] [--yes]` — delete a
//!   named passkey after a confirmation prompt (suppressed with `--yes`).
//! - `credentials show <name> [--profile <name>]` — show metadata for a
//!   named passkey (no secret material).
//!
//! # First-registration RP-ID binding warning
//!
//! `add-passkey` warns before the first registration ceremony that the
//! passkey will be bound to the RP-ID and is unrecoverable if the RP-ID is
//! lost. Prompts `[y/N]` before proceeding. If the user declines, directs
//! them to `docs/runbooks/passkey-rp-id-recovery.md`.

pub mod add_passkey;
pub mod delete;
pub mod list;
pub mod show;

use clap::{Args, Subcommand};

/// Arguments for the `credentials` subcommand group.
#[derive(Debug, Args)]
#[non_exhaustive]
pub struct CredentialsArgs {
    /// The credentials subcommand to run.
    #[command(subcommand)]
    pub subcommand: CredentialsSubcommand,
}

/// Subcommands of `stellar-agent credentials`.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum CredentialsSubcommand {
    /// Register a new WebAuthn passkey via browser handoff.
    ///
    /// Generates a registration nonce, opens the OS default browser to the
    /// wallet-owned bridge registration URL, and polls the approval store until
    /// the browser-side WebAuthn ceremony completes. On success, stores the
    /// credential metadata in the per-profile passkeys registry.
    ///
    /// Prints a JSON envelope on completion:
    ///
    /// ```json
    /// {"status":"registered","credential_id":"<redacted>","credential_name":"<name>","rp_id":"<rp-id>","registered_at_unix_ms":0}
    /// ```
    ///
    /// When the browser cannot be launched, prints the URL to stderr and
    /// continues polling normally. Non-success outcomes are surfaced as
    /// `"status":"timeout" | "user_canceled" | "entry_missing"` in the
    /// envelope.
    AddPasskey(add_passkey::AddPasskeyArgs),

    /// List registered passkeys for a profile.
    ///
    /// Prints a JSON envelope with the list of credential metadata records.
    /// `credential_id` values are redacted to first-5-last-5 base64url.
    List(list::ListArgs),

    /// Delete a named passkey from the passkeys registry.
    ///
    /// Prompts for confirmation unless `--yes` is supplied.
    Delete(delete::DeleteArgs),

    /// Show metadata for a named passkey (no secret material).
    ///
    /// Prints a JSON envelope with credential metadata.
    Show(show::ShowArgs),
}

/// Runs the `credentials` subcommand group.
///
/// Returns an exit code: `0` on success, `1` on any error.
///
/// # Errors
///
/// Never returns `Err` — errors are captured into the exit code.
///
/// # Panics
///
/// Never panics.
pub async fn run(args: &CredentialsArgs) -> i32 {
    match &args.subcommand {
        CredentialsSubcommand::AddPasskey(a) => add_passkey::run(a).await,
        CredentialsSubcommand::List(a) => list::run(a),
        CredentialsSubcommand::Delete(a) => delete::run(a),
        CredentialsSubcommand::Show(a) => show::run(a),
    }
}
