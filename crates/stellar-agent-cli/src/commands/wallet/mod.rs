//! `stellar-agent wallet` subcommand group.
//!
//! Wallet-side smart-account orchestration. Currently provides:
//!
//! - [`rules`] — context-rule lifecycle subcommands
//!   (`wallet rules create / get / set-name / set-valid-until / delete /
//!   add-policy / remove-policy / list`).
//!   **`wallet rules list`** is the canonical name for enumerating active
//!   context rules. `wallet sa list-rules` is retained as an alias for
//!   backwards-compat (no deprecation warning).
//! - [`sa`] — smart-account infrastructure subcommands, e.g.
//!   `wallet sa deploy-webauthn-verifier`.
//!   `wallet sa list-rules` — alias for `wallet rules list` (secondary entry
//!   point retained for backwards-compat).
//! - [`signers`] — signer-set lifecycle subcommands:
//!   `wallet signers list / refresh / add / remove / set-threshold`.
//! - [`multicall`] — multicall router bundle submission subcommand:
//!   `wallet multicall` — submit a batched invocation bundle through the
//!   deployed multicall router contract.
//!
//! # Dispatch
//!
//! [`WalletArgs`] is a `clap` [`Args`] struct with a nested
//! [`WalletSubcommand`] enum. The top-level [`crate::main`] function routes
//! `Commands::Wallet(args)` to [`run`], which delegates to the appropriate
//! subcommand handler.

pub mod common;
pub mod multicall;
pub mod rules;
pub mod sa;
pub mod signers;

use clap::{Args, Subcommand};

/// Arguments for the `wallet` subcommand group.
#[derive(Debug, Args)]
#[non_exhaustive]
pub struct WalletArgs {
    /// The wallet subcommand to run.
    #[command(subcommand)]
    pub subcommand: WalletSubcommand,
}

/// Subcommands of `stellar-agent wallet`.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum WalletSubcommand {
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
    /// - `wallet rules create` — install a new context rule via OZ
    ///   `add_context_rule`. Mints a new `rule_id` on success.
    /// - `wallet rules get <id>` — read a single rule by `rule_id`. Read-only,
    ///   no signing.
    /// - `wallet rules set-name <id> <name>` — rename an existing rule via
    ///   OZ `update_context_rule_name`.
    /// - `wallet rules set-valid-until <id> <ledger | none>` — change the
    ///   rule's expiry via OZ `update_context_rule_valid_until`. `none`
    ///   clears the expiry → permanent rule.
    /// - `wallet rules delete <id>` — remove a rule via OZ
    ///   `remove_context_rule`.
    /// - `wallet rules add-policy` — add a policy contract to an existing rule
    ///   via OZ `add_policy`. Enforces the per-rule cap (≤5 policies).
    /// - `wallet rules remove-policy` — remove a policy from an existing rule
    ///   via OZ `remove_policy`.
    /// - **`wallet rules list`** — enumerate all active context rules (canonical
    ///   name). Delegates to `wallet sa list-rules`; both produce identical
    ///   JSON envelopes. `wallet sa list-rules` is retained for
    ///   backwards-compat (no deprecation warning).
    ///
    /// All write subcommands invoke `Signer::sign_auth_digest` exclusively
    /// (inverse-bypass discipline) and emit
    /// `EventKind::SaRawInvocation` audit-log rows in addition to the
    /// domain-row pair on the `create` / `delete` paths
    /// (`SaContextRuleCreated` / `SaContextRuleDeleted`).
    Rules(Box<rules::RulesArgs>),

    /// Smart-account infrastructure subcommands.
    ///
    /// Provides:
    /// - `wallet sa deploy-webauthn-verifier` — deploy the OZ WebAuthn-verifier WASM
    ///   contract and record the address in `~/.config/stellar-agent/networks.toml`.
    ///   Idempotent. Supports dry-run, three deployer modes, and mainnet defence.
    Sa(Box<sa::SaArgs>),

    /// Signer-set lifecycle for an existing OZ smart-account.
    ///
    /// Provides:
    /// - `wallet signers list` — reads on-chain signer set; emits
    ///   `SaSignerSetBaselined` on first observation (divergence anchor).
    /// - `wallet signers refresh` — unconditionally writes a fresh
    ///   `SaSignerSetBaselined` row (re-anchor after intentional out-of-band
    ///   mutation).
    /// - `wallet signers add` — adds one delegated ed25519 signer to a context
    ///   rule via OZ `add_signer`; emits `SaSignerAdded`. Refuses if adding
    ///   would exceed internal counters (upstream guard).
    /// - `wallet signers remove` — removes one signer by `signer_id` via OZ
    ///   `remove_signer`; emits `SaSignerRemoved`. Refuses if removing would
    ///   drop `signer_count` below `threshold` (brick-prevention).
    /// - `wallet signers set-threshold` — changes the threshold via the
    ///   threshold-policy contract's `set_threshold`; emits `SaThresholdChanged`.
    ///   Refuses if `new_threshold > signer_count`.
    ///
    /// All subcommands structurally refuse mainnet and invoke
    /// `Signer::sign_auth_digest` exclusively.
    Signers(Box<signers::SignersArgs>),
}

/// Runs the `wallet` subcommand group.
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
pub async fn run(args: &WalletArgs) -> i32 {
    match &args.subcommand {
        WalletSubcommand::Multicall(multicall_args) => multicall::run(multicall_args).await,
        WalletSubcommand::Rules(rules_args) => rules::run(rules_args).await,
        WalletSubcommand::Sa(sa_args) => sa::run(sa_args).await,
        WalletSubcommand::Signers(signers_args) => signers::run(signers_args).await,
    }
}
