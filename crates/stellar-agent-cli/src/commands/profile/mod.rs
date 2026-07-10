//! `stellar-agent profile` subcommand group.
//!
//! Parent module for all profile-management subcommands.  Provides:
//!
//! - [`list`] — list known profile names from the OS-conventional profile directory.
//! - [`show`] — print a profile's resolved configuration (excluding keyring
//!   secrets, which are never stored in the TOML).
//! - [`migrate`] — invoke the schema migration for a named profile.
//! - [`enroll_signer`] — import an operator-held ed25519 seed into the
//!   profile's MCP signer keyring entry.
//! - [`enroll_owner_key`] — enroll the policy-file owner ed25519 PUBLIC key.
//! - [`sign_policy`] — sign a V1 policy file with the owner key.
//! - [`rotate_nonce_key`] — rotate the HMAC nonce key for a profile.
//! - [`rotate_attestation_key`] — rotate the approval-spine attestation HMAC
//!   key.
//! - [`rotate_audit_key`] — rotate the hash-chain audit-log root-signature
//!   HMAC key.
//! - [`rotate_counterparty_key`] — rotate the `stellar.toml` cache-integrity
//!   HMAC key.
//!
//! # Dispatch
//!
//! [`ProfileArgs`] is a `clap` [`Args`] struct with a nested [`ProfileSubcommand`]
//! enum.  The top-level [`crate::main`] function routes `Commands::Profile(args)`
//! to [`run`], which delegates to the appropriate subcommand handler.

pub mod audit_emit;
pub mod enroll_owner_key;
pub mod enroll_signer;
pub mod key_ops;
pub mod list;
pub mod migrate;
pub mod reset_window_state;
pub mod rotate_attestation_key;
pub mod rotate_audit_key;
pub mod rotate_counterparty_key;
pub mod rotate_nonce_key;
pub mod rotate_policy_state_key;
pub mod show;
pub mod sign_policy;

use clap::{Args, Subcommand};

/// Arguments for the `profile` subcommand group.
#[derive(Debug, Args)]
#[non_exhaustive]
pub struct ProfileArgs {
    /// The profile subcommand to run.
    #[command(subcommand)]
    pub subcommand: ProfileSubcommand,
}

/// Subcommands of `stellar-agent profile`.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum ProfileSubcommand {
    /// List known profile names.
    ///
    /// Reads the OS-conventional profile directory and prints one profile
    /// name per line.
    List(list::ListArgs),
    /// Print a profile's resolved configuration.
    ///
    /// Outputs the profile as JSON to stdout.  Keyring secrets are never
    /// stored in the TOML and therefore never printed here.
    Show(show::ShowArgs),
    /// Migrate a profile's schema to the current version.
    ///
    /// Reads the named profile, applies any pending migrations atomically
    /// (temp-file + rename), and prints the outcome.
    Migrate(migrate::MigrateArgs),
    /// Enroll the MCP signer seed for a profile.
    ///
    /// Reads an `S...` ed25519 secret-key strkey from the environment variable
    /// named by `--secret-env`, derives its public address, and stores it at the
    /// profile's `mcp_signer_default` keyring coordinate so MCP tools and the
    /// keyring-signing CLI verbs can resolve a working signer.  The seed is never
    /// printed; only the derived public address and keyring coordinate are
    /// reported.
    EnrollSigner(enroll_signer::EnrollSignerArgs),
    /// Enroll the policy-file owner PUBLIC key for a profile.
    ///
    /// Derives the owner ed25519 public key from an operator-held `S...` seed
    /// (read from a named environment variable through the mlock-protected
    /// ceremony) and stores the PUBLIC key in the platform keyring entry the V1
    /// policy engine verifies against.  The seed is never stored; the operator
    /// keeps it offline and signs policy files with `sign-policy`.
    EnrollOwnerKey(enroll_owner_key::EnrollOwnerKeyArgs),
    /// Sign a V1 policy file with the owner key.
    ///
    /// Computes the canonical digest the engine verifies, signs it with the
    /// owner seed (read from a named environment variable), and writes the
    /// `[signature]` table into the policy file.  Refuses when the seed does
    /// not match the enrolled owner key.
    SignPolicy(sign_policy::SignPolicyArgs),
    /// Rotate the HMAC nonce key for a profile.
    ///
    /// Generates 32 bytes from `OsRng` and stores them in the platform
    /// keyring entry for the profile's `mcp_nonce_key_alias`.  All
    /// outstanding nonces minted with the old key are invalidated.
    RotateNonceKey(rotate_nonce_key::RotateNonceKeyArgs),
    /// Rotate the approval-spine attestation HMAC key for a profile.
    ///
    /// Generates 32 bytes from `OsRng` and stores them in the platform
    /// keyring entry for `attestation_key_id`.  All pending approvals
    /// (outstanding `stellar-agent approve` sessions) are immediately
    /// invalidated.
    RotateAttestationKey(rotate_attestation_key::RotateAttestationKeyArgs),
    /// Rotate the hash-chain audit-log chain-root HMAC key for a profile.
    ///
    /// Generates 32 bytes from `OsRng` and stores them in the platform
    /// keyring entry for `audit_log_hash_chain_key_id`.  New audit log files
    /// opened after rotation use the new key for their chain-root signature.
    RotateAuditKey(rotate_audit_key::RotateAuditKeyArgs),
    /// Rotate the `stellar.toml` cache-integrity HMAC key for a profile.
    ///
    /// Generates 32 bytes from `OsRng` and stores them in the platform
    /// keyring entry for `counterparty_cache_key_id`.  All cached
    /// `stellar.toml` entries are immediately invalidated; the wallet
    /// re-fetches on the next counterparty-allowlist check.
    ///
    /// See `docs/runbooks/counterparty-cache-rotation.md` for operator
    /// guidance on coordinating cache invalidation.
    RotateCounterpartyKey(rotate_counterparty_key::RotateCounterpartyKeyArgs),
    /// Rotate the persisted policy-window-state HMAC key for a profile.
    ///
    /// Generates 32 bytes from `OsRng` and stores them in the platform
    /// keyring entry for `policy_window_state_key_id`. The accumulated
    /// `per_period_cap` / `rate_limit` window-state store is re-signed under
    /// the new key so its history is preserved (not invalidated) by
    /// rotation.
    RotatePolicyStateKey(rotate_policy_state_key::RotatePolicyStateKeyArgs),
    /// Re-initialise the persisted policy-window-state store to empty.
    ///
    /// Recovery path for an unreadable, tampered, or unparseable window-state
    /// store: the stateful criteria (`per_period_cap`, `rate_limit`,
    /// `bundle_per_period_cap`, `bundle_rate_limit`) fail closed until reset.
    /// Discards accumulated history for the profile; the reset is audited.
    ResetWindowState(reset_window_state::ResetWindowStateArgs),
}

/// Runs the `profile` subcommand group.
///
/// Dispatches to the appropriate subcommand handler.
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
pub async fn run(args: &ProfileArgs) -> i32 {
    match &args.subcommand {
        ProfileSubcommand::List(a) => list::run(a).await,
        ProfileSubcommand::Show(a) => show::run(a).await,
        ProfileSubcommand::Migrate(a) => migrate::run(a).await,
        ProfileSubcommand::EnrollSigner(a) => enroll_signer::run(a).await,
        ProfileSubcommand::EnrollOwnerKey(a) => enroll_owner_key::run(a).await,
        ProfileSubcommand::SignPolicy(a) => sign_policy::run(a).await,
        ProfileSubcommand::RotateNonceKey(a) => rotate_nonce_key::run(a).await,
        ProfileSubcommand::RotateAttestationKey(a) => rotate_attestation_key::run(a).await,
        ProfileSubcommand::RotateAuditKey(a) => rotate_audit_key::run(a).await,
        ProfileSubcommand::RotateCounterpartyKey(a) => rotate_counterparty_key::run(a).await,
        ProfileSubcommand::RotatePolicyStateKey(a) => rotate_policy_state_key::run(a).await,
        ProfileSubcommand::ResetWindowState(a) => reset_window_state::run(a).await,
    }
}
