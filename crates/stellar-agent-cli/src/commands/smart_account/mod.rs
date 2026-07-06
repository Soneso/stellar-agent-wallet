//! `stellar-agent smart-account` subcommand group (alias `sa`).
//!
//! Administers an OpenZeppelin smart-account contract: context-rule and
//! signer-set lifecycle, multicall-router bundle submission, verifier
//! deployment/migration, and upgrade-timelock operations. Every verb here
//! operates against a deployed smart-account contract address.
//!
//! Invoke either as `stellar-agent smart-account <verb>` or via the shorter
//! `stellar-agent sa <verb>` alias; the two are identical.
//!
//! # Subcommands
//!
//! - [`rules`] — context-rule lifecycle
//!   (`smart-account rules create / get / set-name / set-valid-until / delete /
//!   add-policy / remove-policy / list`).
//!   **`smart-account rules list`** is the canonical name for enumerating active
//!   context rules. `smart-account list-rules` is retained as an alias for it
//!   (no deprecation warning).
//! - [`signers`] — signer-set lifecycle
//!   (`smart-account signers list / refresh / add / remove / set-threshold`).
//! - [`multicall`] — submit a batched invocation bundle through the deployed
//!   multicall router contract.
//! - [`deploy_webauthn_verifier`] — `smart-account deploy-webauthn-verifier` —
//!   deploy the vendored OZ WebAuthn-verifier WASM contract and record the
//!   address in `~/.config/stellar-agent/networks.toml`.
//! - [`deploy_ed25519_verifier`] — `smart-account deploy-ed25519-verifier` —
//!   deploy the vendored OZ Ed25519-verifier WASM contract and record the
//!   address in `~/.config/stellar-agent/networks.toml`.
//! - [`deploy_spending_limit_policy`] — `smart-account deploy-spending-limit-policy`
//!   — deploy the vendored OZ spending-limit-policy WASM contract (per-network
//!   singleton) and record the address in `~/.config/stellar-agent/networks.toml`.
//! - [`migrate_verifier`] — `smart-account migrate-verifier` — construct a
//!   [`MigrationPlan`] for moving all `External` signers from one verifier to
//!   another. Currently `--dry-run` only.
//! - [`list_verifiers`] — `smart-account list-verifiers` — enumerate
//!   [`VERIFIER_ALLOWLIST`] with audit-status taxonomy.
//! - [`list_rules`] — `smart-account list-rules` — enumerate active context
//!   rules on a smart account via on-chain scan (alias for
//!   `smart-account rules list`).
//! - [`register_multicall`] — `smart-account register-multicall` — register a
//!   deployed multicall router address in the local registry.
//! - [`unregister_multicall`] — `smart-account unregister-multicall` — remove
//!   the multicall router registry entry for a network.
//! - [`timelock`] — `smart-account timelock` subcommand group: schedule,
//!   cancel, execute, and list-pending OZ upgrade-timelock operations.
//!
//! # Dispatch
//!
//! [`SmartAccountArgs`] is a `clap` [`Args`] struct with a nested
//! [`SmartAccountSubcommand`] enum. The top-level [`crate::main`] function
//! routes `Commands::SmartAccount(args)` to [`run`], which delegates to the
//! appropriate subcommand handler.
//!
//! [`MigrationPlan`]: stellar_agent_smart_account::managers::migration::MigrationPlan
//! [`VERIFIER_ALLOWLIST`]: stellar_agent_smart_account::verifier_allowlist::VERIFIER_ALLOWLIST

pub mod common;
pub mod deploy_ed25519_verifier;
pub mod deploy_policy;
pub mod deploy_spending_limit_policy;
pub mod deploy_webauthn_verifier;
pub mod list_rules;
pub mod list_verifiers;
pub mod migrate_verifier;
pub mod multicall;
pub mod register_multicall;
pub mod rules;
pub mod signers;
pub mod timelock;
pub mod unregister_multicall;

use clap::{Args, Subcommand};

/// Arguments for the `smart-account` subcommand group.
#[derive(Debug, Args)]
#[non_exhaustive]
pub struct SmartAccountArgs {
    /// The smart-account subcommand to run.
    #[command(subcommand)]
    pub subcommand: SmartAccountSubcommand,
}

/// Subcommands of `stellar-agent smart-account`.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum SmartAccountSubcommand {
    /// Submit a batched invocation bundle through a deployed multicall router contract.
    ///
    /// Each `--invocation` argument takes the form `<target>:<fn>:<json-args>` where:
    ///
    /// - `<target>` is the C-strkey of the contract to invoke.
    /// - `<fn>` is the function name on that contract.
    /// - `<json-args>` is a JSON array of Soroban XDR-encoded arguments.
    ///
    /// The bundle is submitted via `submit_multicall_bundle` using the registered
    /// multicall router for the target network. The router address is resolved from
    /// `~/.config/stellar-agent/networks.toml`.
    ///
    /// The cardinality gate (1–50 invocations per bundle) is enforced at the CLI
    /// layer before any RPC traffic is issued.
    ///
    /// Requires `--secondary-rpc-url` (or `profile.secondary_rpc_url`) to resolve
    /// the secondary RPC endpoint used for contract-data reads.
    Multicall(Box<multicall::MulticallArgs>),

    /// Context-rule lifecycle for an existing OZ smart-account.
    ///
    /// Provides:
    /// - `smart-account rules create` — install a new context rule via OZ
    ///   `add_context_rule`. Mints a new `rule_id` on success.
    /// - `smart-account rules get <id>` — read a single rule by `rule_id`. Read-only,
    ///   no signing.
    /// - `smart-account rules set-name <id> <name>` — rename an existing rule via
    ///   OZ `update_context_rule_name`.
    /// - `smart-account rules set-valid-until <id> <ledger | none>` — change the
    ///   rule's expiry via OZ `update_context_rule_valid_until`. `none`
    ///   clears the expiry → permanent rule.
    /// - `smart-account rules delete <id>` — remove a rule via OZ
    ///   `remove_context_rule`.
    /// - `smart-account rules add-policy` — add a policy contract to an existing rule
    ///   via OZ `add_policy`. Enforces the per-rule cap (≤5 policies).
    /// - `smart-account rules remove-policy` — remove a policy from an existing rule
    ///   via OZ `remove_policy`.
    /// - **`smart-account rules list`** — enumerate all active context rules (canonical
    ///   name). Delegates to `smart-account list-rules`; both produce identical
    ///   JSON envelopes. `smart-account list-rules` is retained for
    ///   backwards-compat (no deprecation warning).
    ///
    /// All write subcommands invoke `Signer::sign_auth_digest` exclusively
    /// (inverse-bypass discipline) and emit
    /// `EventKind::SaRawInvocation` audit-log rows in addition to the
    /// domain-row pair on the `create` / `delete` paths
    /// (`SaContextRuleCreated` / `SaContextRuleDeleted`).
    Rules(Box<rules::RulesArgs>),

    /// Signer-set lifecycle for an existing OZ smart-account.
    ///
    /// Provides:
    /// - `smart-account signers list` — reads on-chain signer set; emits
    ///   `SaSignerSetBaselined` on first observation (divergence anchor).
    /// - `smart-account signers refresh` — unconditionally writes a fresh
    ///   `SaSignerSetBaselined` row (re-anchor after intentional out-of-band
    ///   mutation).
    /// - `smart-account signers add` — adds one signer to a context rule via OZ
    ///   `add_signer`; emits `SaSignerAdded`. Accepts exactly one of
    ///   `--signer-delegated` (G-key), `--signer-ed25519` (raw Ed25519 pubkey
    ///   verified by the registered Ed25519 verifier; optional `--verifier`
    ///   override), `--signer-webauthn` (passkey), or `--signer-external`
    ///   (raw External escape hatch). Refuses if adding would exceed internal
    ///   counters (upstream guard).
    /// - `smart-account signers remove` — removes one signer by `signer_id` via OZ
    ///   `remove_signer`; emits `SaSignerRemoved`. Refuses if removing would
    ///   drop `signer_count` below `threshold` (brick-prevention).
    /// - `smart-account signers set-threshold` — changes the threshold via the
    ///   threshold-policy contract's `set_threshold`; emits `SaThresholdChanged`.
    ///   Refuses if `new_threshold > signer_count`.
    ///
    /// All subcommands structurally refuse mainnet and invoke
    /// `Signer::sign_auth_digest` exclusively.
    Signers(Box<signers::SignersArgs>),

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

    /// Deploy the OZ Ed25519-verifier WASM contract and record the address in the
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
    /// The command is idempotent: if the registry already has an Ed25519-verifier
    /// entry for the target network with the same WASM sha256, no RPC traffic is
    /// issued and `status: "already_deployed"` is returned.
    ///
    /// Bootstraps first-class Ed25519 external signers
    /// (`smart-account signers add --signer-ed25519`).
    #[command(name = "deploy-ed25519-verifier")]
    DeployEd25519Verifier(Box<deploy_ed25519_verifier::DeployEd25519VerifierArgs>),

    /// Deploy the OZ spending-limit-policy WASM contract (per-network singleton)
    /// and record the address in the verifier registry
    /// (`~/.config/stellar-agent/networks.toml`).
    ///
    /// Supports two mutually-exclusive deployer-source modes:
    ///
    /// - `--deployer-secret-env <VAR>` — read deployer S-strkey from an env var.
    /// - `--sign-with-ledger` — use a connected Ledger hardware wallet.
    ///
    /// Mainnet is structurally refused. Use `--dry-run` to derive the
    /// deterministic policy address without any network access.
    ///
    /// The policy SHA-256 is re-verified at runtime before any submission.
    /// The command is idempotent: if the registry already has a
    /// spending-limit-policy entry for the target network with the same WASM
    /// sha256, no RPC traffic is issued and `status: "already_deployed"` is
    /// returned. The address is consumed by
    /// `smart-account rules add-policy --kind spending-limit`.
    #[command(name = "deploy-spending-limit-policy")]
    DeploySpendingLimitPolicy(Box<deploy_spending_limit_policy::DeploySpendingLimitPolicyArgs>),

    /// Deploy one of the three OZ policy contracts (`--kind simple-threshold`,
    /// `--kind spending-limit`, or `--kind weighted-threshold`) and record the
    /// address in the verifier registry
    /// (`~/.config/stellar-agent/networks.toml`).
    ///
    /// Supports two mutually-exclusive deployer-source modes:
    ///
    /// - `--deployer-secret-env <VAR>` — read deployer S-strkey from an env var.
    /// - `--sign-with-ledger` — use a connected Ledger hardware wallet.
    ///
    /// Mainnet is structurally refused. Use `--dry-run` to derive the
    /// deterministic policy address without any network access.
    ///
    /// `--kind spending-limit` routes to the same substrate as the standalone
    /// `smart-account deploy-spending-limit-policy` verb, which remains
    /// available unchanged.
    ///
    /// Each kind's WASM SHA-256 is re-verified at runtime before any
    /// submission. Idempotent per network + kind: re-running with the same
    /// WASM sha256 returns `status: "already_deployed"` with no RPC traffic.
    #[command(name = "deploy-policy")]
    DeployPolicy(Box<deploy_policy::DeployPolicyArgs>),

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
    /// 2. Destination audit status MUST be `Audited`, `Provisional`, or `Unaudited`.
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
    ///
    /// Alias for `smart-account rules list`; both produce identical JSON envelopes.
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

/// Runs the `smart-account` subcommand group.
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
pub async fn run(args: &SmartAccountArgs) -> i32 {
    match &args.subcommand {
        SmartAccountSubcommand::Multicall(multicall_args) => multicall::run(multicall_args).await,
        SmartAccountSubcommand::Rules(rules_args) => rules::run(rules_args).await,
        SmartAccountSubcommand::Signers(signers_args) => signers::run(signers_args).await,
        SmartAccountSubcommand::DeployWebAuthnVerifier(deploy_args) => {
            deploy_webauthn_verifier::run(deploy_args).await
        }
        SmartAccountSubcommand::DeployEd25519Verifier(deploy_args) => {
            deploy_ed25519_verifier::run(deploy_args).await
        }
        SmartAccountSubcommand::DeploySpendingLimitPolicy(deploy_args) => {
            deploy_spending_limit_policy::run(deploy_args).await
        }
        SmartAccountSubcommand::DeployPolicy(deploy_args) => deploy_policy::run(deploy_args).await,
        SmartAccountSubcommand::MigrateVerifier(migrate_args) => {
            migrate_verifier::run(migrate_args).await
        }
        SmartAccountSubcommand::ListVerifiers(list_args) => list_verifiers::run(list_args).await,
        SmartAccountSubcommand::ListRules(list_args) => list_rules::run(list_args).await,
        SmartAccountSubcommand::RegisterMulticall(args) => register_multicall::run(args).await,
        SmartAccountSubcommand::UnregisterMulticall(args) => unregister_multicall::run(args).await,
        SmartAccountSubcommand::Timelock(args) => timelock::run(args).await,
    }
}
