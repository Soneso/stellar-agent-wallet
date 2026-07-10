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
use stellar_agent_smart_account::managers::credentials::CredentialsError;

/// Maps a [`CredentialsError`] to a stable dotted wire code in the
/// `credentials.*` namespace, shared by every `credentials` subcommand so the
/// same underlying failure always carries the same code regardless of which
/// verb surfaced it.
pub(crate) fn credentials_error_code(err: &CredentialsError) -> &'static str {
    match err {
        CredentialsError::Io { .. } => "credentials.io_error",
        CredentialsError::RegistryParse { .. } => "credentials.registry_parse_failed",
        CredentialsError::RegistrySerialise { .. } => "credentials.registry_serialise_failed",
        CredentialsError::StateDirUnavailable => "credentials.state_dir_unavailable",
        CredentialsError::NotFound { .. } => "credentials.not_found",
        CredentialsError::DuplicateName { .. } => "credentials.duplicate_name",
        CredentialsError::InvalidName { .. } => "credentials.invalid_name",
        CredentialsError::ApprovalStore { .. } => "credentials.approval_store_error",
        CredentialsError::BridgeStart { .. } => "credentials.bridge_start_failed",
        CredentialsError::BridgeShutdown { .. } => "credentials.bridge_shutdown_failed",
        CredentialsError::ApprovalStoreUnavailable => "credentials.approval_store_unavailable",
        CredentialsError::AtomicWrite { .. } => "credentials.atomic_write_failed",
        CredentialsError::Signing { .. } => "credentials.signing_failed",
        CredentialsError::MissingPublicKey { .. } => "credentials.missing_public_key",
        CredentialsError::MalformedPublicKey { .. } => "credentials.malformed_public_key",
        // Forward-compatibility wildcard: future variants (e.g. the
        // divergence-check family) default to a generic code rather than
        // failing to compile on every new variant added upstream.
        _ => "credentials.error",
    }
}

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
    /// Prints the standard result envelope on completion:
    ///
    /// ```json
    /// {"ok":true,"data":{"credential_id":"<redacted>","credential_name":"<name>","rp_id":"<rp-id>","registered_at_unix_ms":0},"request_id":"..."}
    /// ```
    ///
    /// When the browser cannot be launched, prints the URL to stderr and
    /// continues polling normally. Non-success outcomes (timeout, user
    /// cancellation, missing approval-store entry) surface as `ok:false` with
    /// a `credentials.registration_*` wire code.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Every `credentials` subcommand routes its `CredentialsError` through
    /// this single mapping, so the same underlying failure carries the same
    /// dotted `credentials.*` code everywhere it can surface.
    #[test]
    fn credentials_error_code_covers_common_variants() {
        let cases: &[(CredentialsError, &str)] = &[
            (
                CredentialsError::NotFound {
                    name: "x".to_owned(),
                },
                "credentials.not_found",
            ),
            (
                CredentialsError::DuplicateName {
                    name: "x".to_owned(),
                },
                "credentials.duplicate_name",
            ),
            (
                CredentialsError::InvalidName {
                    name: "x".to_owned(),
                    reason: "too long",
                },
                "credentials.invalid_name",
            ),
            (
                CredentialsError::StateDirUnavailable,
                "credentials.state_dir_unavailable",
            ),
        ];
        for (err, expected_code) in cases {
            assert_eq!(
                credentials_error_code(err),
                *expected_code,
                "wire code mismatch for {err:?}"
            );
        }
    }
}
