//! `stellar-agent wallet sa` subcommand group — smart-account infrastructure.
//!
//! Provides CLI verbs for smart-account infrastructure operations that are NOT
//! covered by `wallet rules` (which handles OZ context-rule lifecycle). This group
//! covers the deploy-time, registry-management, and migration operations.
//!
//! # Subcommands
//!
//! - [`deploy_webauthn_verifier`] — deploy the vendored OZ WebAuthn-verifier WASM
//!   contract and record the address in `~/.config/stellar-agent/networks.toml`.
//! - [`migrate_verifier`] — construct a [`MigrationPlan`] for migrating all
//!   `External` signers from one verifier to another. Currently `--dry-run` only.
//! - [`list_verifiers`] — enumerate [`VERIFIER_ALLOWLIST`] with audit-status taxonomy.
//!   Default output: JSON. Table mode deferred.
//! - [`list_rules`] — enumerate active context rules on a smart account with on-chain
//!   scan. Default output: JSON.
//! - [`register_multicall`] — register a deployed multicall router address in the
//!   local registry (`~/.config/stellar-agent/networks.toml`).
//! - [`unregister_multicall`] — remove the multicall router registry entry for a
//!   network. Supports `--force` for registry-file corruption recovery.
//! - [`timelock`] — `wallet sa timelock` subcommand group: schedule, cancel,
//!   execute, and list-pending OZ upgrade-timelock operations.
//!
//! # Dispatch
//!
//! [`SaArgs`] is a `clap` [`Args`] struct with a nested [`SaSubcommand`] enum.
//! The parent [`super::run`] function routes `WalletSubcommand::Sa(args)` to
//! [`run`], which delegates to the appropriate subcommand handler.
//!
//! [`MigrationPlan`]: stellar_agent_smart_account::managers::migration::MigrationPlan
//! [`VERIFIER_ALLOWLIST`]: stellar_agent_smart_account::verifier_allowlist::VERIFIER_ALLOWLIST

pub mod deploy_webauthn_verifier;
pub mod list_rules;
pub mod list_verifiers;
pub mod migrate_verifier;
pub mod register_multicall;
pub mod timelock;
pub mod unregister_multicall;

use clap::{Args, Subcommand};

/// Arguments for the `wallet sa` subcommand group.
#[derive(Debug, Args)]
#[non_exhaustive]
pub struct SaArgs {
    /// The `sa` subcommand to run.
    #[command(subcommand)]
    pub subcommand: SaSubcommand,
}

/// Subcommands of `stellar-agent wallet sa`.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum SaSubcommand {
    /// Deploy the OZ WebAuthn-verifier WASM contract and record the address in the
    /// verifier registry (`~/.config/stellar-agent/networks.toml`).
    ///
    /// Supports two mutually-exclusive deployer-source modes:
    ///
    /// - `--deployer-secret-env <VAR>` — read deployer S-strkey from an env var.
    /// - `--sign-with-ledger` — use a connected Ledger hardware wallet.
    ///
    /// Mainnet is structurally refused. Use `--dry-run` to derive the
    /// deterministic verifier address without any network access.
    ///
    /// The verifier SHA-256 is re-verified at runtime before any submission.
    /// The command is idempotent: if the registry already has an entry for the
    /// target network with the same WASM sha256, no RPC traffic is issued and
    /// `status: "already_deployed"` is returned.
    #[command(name = "deploy-webauthn-verifier")]
    DeployWebAuthnVerifier(Box<deploy_webauthn_verifier::DeployWebAuthnVerifierArgs>),

    /// Construct a migration plan for moving `External` signers from one verifier
    /// contract to another across all context rules on a smart account.
    ///
    /// Pass `--dry-run` to render the plan as a JSON envelope without submitting
    /// any transactions. Without `--dry-run`, transactions are submitted in
    /// `remove_signer` + `add_signer` pairs per affected External signer per rule.
    ///
    /// Pre-flight gates (fail-CLOSED):
    ///
    /// 1. Destination verifier hash MUST be in `VERIFIER_ALLOWLIST`.
    /// 2. Destination audit status MUST be `Audited` or `Unaudited`.
    /// 3. Destination contract MUST be immutable (no admin/owner key).
    ///
    /// Mainnet submit requires `--confirm-mainnet-migrate`.
    #[command(name = "migrate-verifier")]
    MigrateVerifier(Box<migrate_verifier::MigrateVerifierArgs>),

    /// Enumerate the compile-time verifier allowlist with audit-status taxonomy.
    ///
    /// Default output: JSON. Pass `--output table` for human-readable columns.
    ///
    /// Read-only: no signing, no network calls, no mainnet refusal needed.
    #[command(name = "list-verifiers")]
    ListVerifiers(list_verifiers::ListVerifiersArgs),

    /// Enumerate all active context rules on a smart account via on-chain scan.
    ///
    /// Scans `[0, max_scan_id)` OZ rule-ID space and returns every active rule
    /// in monotonic `rule_id` order.  Sparse IDs (deleted rules) are skipped
    /// silently; the scan early-exits when `active_count` rules are collected.
    ///
    /// Default output: JSON.  Table mode is deferred.
    ///
    /// Read-only: no signing required.  No mainnet refusal (query only).
    #[command(name = "list-rules")]
    ListRules(list_rules::ListRulesArgs),

    /// Register a deployed multicall router contract in the local registry.
    ///
    /// Records the address and WASM SHA-256 in
    /// `~/.config/stellar-agent/networks.toml` under
    /// `[multicall.<network_safename>]`. The `--wasm-sha256` MUST equal the
    /// `MULTICALL_WASM_SHA256` binary constant compiled into this wallet binary —
    /// any mismatch is refused at the CLI layer before writing to disk (typo and
    /// filesystem-attacker config-plant defence).
    ///
    /// Idempotent: re-registering the same address + SHA is a no-op.
    ///
    /// Emits `SaMulticallRegistered` on success or
    /// `SaMulticallRegistrationRefused` on any refusal.
    #[command(name = "register-multicall")]
    RegisterMulticall(Box<register_multicall::RegisterMulticallArgs>),

    /// Remove the multicall router registry entry for a network.
    ///
    /// Normal path: validates the stored entry and removes it. Emits
    /// `SaMulticallUnregistered` on success.
    ///
    /// `--force` path: corruption-recovery bypass. Locates entries by
    /// network-safename without strkey/hex validation. Emits
    /// `SaMulticallUnregisteredForce` BEFORE file mutation (audit-emission
    /// discipline). Requires interactive `[y/N]` confirmation on a TTY or
    /// `--yes-i-have-verified-the-prior-values` for non-TTY invocations.
    #[command(name = "unregister-multicall")]
    UnregisterMulticall(Box<unregister_multicall::UnregisterMulticallArgs>),

    /// OZ upgrade-timelock operations: schedule, cancel, execute, list-pending.
    ///
    /// Wraps the off-chain `stellar_agent_smart_account::timelock` primitives.
    /// The signer must hold the appropriate timelock role (PROPOSER, CANCELLER,
    /// or EXECUTOR) for write operations. `list-pending` is read-only.
    #[command(name = "timelock")]
    Timelock(Box<timelock::TimelockArgs>),
}

/// Runs the `wallet sa` subcommand group.
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
pub async fn run(args: &SaArgs) -> i32 {
    match &args.subcommand {
        SaSubcommand::DeployWebAuthnVerifier(deploy_args) => {
            deploy_webauthn_verifier::run(deploy_args).await
        }
        SaSubcommand::MigrateVerifier(migrate_args) => migrate_verifier::run(migrate_args).await,
        SaSubcommand::ListVerifiers(list_args) => list_verifiers::run(list_args).await,
        SaSubcommand::ListRules(list_args) => list_rules::run(list_args).await,
        SaSubcommand::RegisterMulticall(args) => register_multicall::run(args).await,
        SaSubcommand::UnregisterMulticall(args) => unregister_multicall::run(args).await,
        SaSubcommand::Timelock(args) => timelock::run(args).await,
    }
}
