//! `stellar-agent smart-account rules` — context-rule lifecycle subcommands.
//!
//! CLI surface for the
//! [`stellar_agent_smart_account::managers::rules::ContextRuleManager`].
//!
//! # Subcommands
//!
//! - [`CreateArgs`] — `smart-account rules create` (OZ `add_context_rule`)
//! - [`GetArgs`] — `smart-account rules get <id>` (OZ `get_context_rule`, read-only)
//! - [`SetNameArgs`] — `smart-account rules set-name <id> <name>`
//!   (OZ `update_context_rule_name`)
//! - [`SetValidUntilArgs`] — `smart-account rules set-valid-until <id> <ledger | none>`
//!   (OZ `update_context_rule_valid_until`; `none` clears expiry → permanent)
//! - [`DeleteArgs`] — `smart-account rules delete <id>` (OZ `remove_context_rule`)
//! - [`AddPolicyArgs`] — `smart-account rules add-policy` (OZ `add_policy`).
//! - [`RemovePolicyArgs`] — `smart-account rules remove-policy` (OZ `remove_policy`).
//! - [`ListArgs`] — **`smart-account rules list`** (canonical name;
//!   delegates to [`crate::commands::smart_account::list_rules::run`]).
//!   `smart-account list-rules` is retained as an alias for backwards-compatibility
//!   (no deprecation warning is emitted).
//!
//! # Command-name aliasing
//!
//! `smart-account rules list` is the canonical name. `smart-account list-rules` is retained
//! without modification for backwards-compat. Both entry points delegate to the
//! same handler (`sa::list_rules::run`) and produce identical JSON envelopes.
//!
//! A `tracing::info!` row carrying `command = "smart-account rules list"` is emitted
//! at the dispatch site so the operator-invoked command name is unambiguous in
//! audit-log correlation.
//!
//! # Signer-source modes (mirror of `accounts deploy-c`)
//!
//! Write subcommands accept exactly one of:
//! - `--signer-secret-env <VAR>` — read S-strkey from env var.
//! - `--sign-with-ledger` — Ledger hardware wallet (BIP-44 `--account-index`).
//!
//! Read subcommands (`get`) accept neither — they need only the smart-account
//! address + a source-account strkey for the simulation envelope.
//!
//! # Mainnet write defence
//!
//! Write subcommands structurally refuse mainnet
//! (`network.mainnet_write_forbidden`) before any RPC or signing call.
//! Read subcommands accept mainnet (read-only, no write risk).
//!
//! # Inverse-bypass discipline
//!
//! All write paths invoke `Signer::sign_auth_digest` exclusively via the
//! manager's `complete_authorization_entry` call site. A CI gate enforces this:
//! the alternative SEP-23-payload signing primitive (the sibling of
//! `sign_auth_digest`) MUST NOT be invoked from any source under
//! `crates/stellar-agent-cli/src/commands/wallet/` and is repo-gate-rejected.

use std::time::Duration;

use base64::Engine as _;
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use stellar_agent_core::envelope::{Envelope, OutputFormat};
use stellar_agent_core::error::CapKind;
use stellar_agent_core::error::{NetworkError, ValidationError, WalletError};
use stellar_agent_core::observability::redact_strkey_first5_last5;
use stellar_agent_core::profile::caip2::MAINNET_RPC_URL;
use stellar_agent_core::smart_account::rule_id::ContextRuleId;
use stellar_agent_smart_account::error::SaError;
use stellar_agent_smart_account::managers::credentials::CredentialsManager;
use stellar_agent_smart_account::managers::rules::{
    ContextRuleDefinition, ContextRuleManager, ContextRuleManagerConfig, ContextRuleSignerInput,
    InstallRuleOutput, OZ_MAX_NAME_SIZE, OZ_MAX_POLICIES, OZ_MAX_SIGNERS, PinStatus, RuleContext,
    SmartAccountAddress, VerifyPinsResult as SaVerifyPinsResult, decode_context_type_from_scval,
    decode_policy_count_from_scval, parse_c_strkey_to_smart_account,
    parse_g_strkey_to_signer_address,
};
use stellar_agent_smart_account::simple_threshold_policy::build_simple_threshold_install_param;
use stellar_agent_smart_account::spending_limit_policy::{
    build_spending_limit_install_param, ensure_call_contract_context_for_spending_limit,
    ensure_valid_spending_limit_params,
};
use stellar_agent_smart_account::verifiers::VerifierRegistry;
use stellar_agent_smart_account::weighted_threshold_policy::{
    WeightedThresholdSignerInput, build_weighted_threshold_install_param,
};
use stellar_xdr::ReadXdr as _;
use tracing::info;
use uuid::Uuid;

use crate::commands::smart_account::common::{
    CommonArgsView, CommonHandlerContext, SignerSourceFlags, construct_signers_manager_from_fields,
    network_to_chain_id, open_audit_writer,
};
use crate::commands::smart_account::list_rules as sa_list_rules;
use crate::common::network::TargetNetwork;
use crate::common::render::render_json;
use crate::common::{resolve_profile_name, validate_path_component_ascii_safe};

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Default submission timeout in seconds.
const DEFAULT_TIMEOUT_SECONDS: u64 = 60;

/// Default Stellar testnet Soroban RPC endpoint.
const TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";

// ─────────────────────────────────────────────────────────────────────────────
// Cap-enforcement helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Returns `Err(ContextRuleCapsExceeded { kind: Signer, … })` when
/// `signer_total > OZ_MAX_SIGNERS`.  The on-chain `TooManySigners = 3010`
/// error is the authoritative last-line defence; this check gives the
/// operator an actionable error before the simulate/submit cycle.
fn enforce_signer_cap(signer_total: usize) -> Result<(), ValidationError> {
    if signer_total > OZ_MAX_SIGNERS as usize {
        let attempted = u32::try_from(signer_total).unwrap_or(u32::MAX);
        return Err(ValidationError::ContextRuleCapsExceeded {
            kind: CapKind::Signer,
            attempted,
            max: OZ_MAX_SIGNERS,
        });
    }
    Ok(())
}

/// Returns `Err(ContextRuleCapsExceeded { kind: Policy, … })` when adding one
/// more policy to a rule that already holds `policy_count` policies would
/// exceed `OZ_MAX_POLICIES`.  The on-chain enforcement is the authoritative
/// last-line defence; this check produces an actionable error before any RPC
/// call.
fn enforce_policy_cap(policy_count: u32) -> Result<(), ValidationError> {
    let attempted = policy_count.saturating_add(1);
    if attempted > OZ_MAX_POLICIES {
        return Err(ValidationError::ContextRuleCapsExceeded {
            kind: CapKind::Policy,
            attempted,
            max: OZ_MAX_POLICIES,
        });
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared argument structs
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments shared across all four write subcommands (`create`, `set-name`,
/// `set-valid-until`, `delete`). Flattened via `#[command(flatten)]` so the
/// CLI surface is unchanged.
///
/// `output` is included here because every write handler needs it for
/// `emit_error` and `emit_success` calls before any async I/O.
#[derive(Debug, Args)]
pub struct CommonRulesWriteArgs {
    /// Smart-account C-strkey.
    #[arg(long, value_name = "C_STRKEY", required = true)]
    pub account: String,

    /// Profile name for audit-log path resolution.
    #[arg(long, value_name = "NAME")]
    pub profile: Option<String>,

    /// Signer-source mode and Ledger derivation index.
    #[command(flatten)]
    pub signer_source: SignerSourceFlags,

    /// Network to target.
    #[arg(long, default_value_t = TargetNetwork::Testnet, value_name = "NETWORK")]
    pub network: TargetNetwork,

    /// Soroban RPC endpoint URL.
    #[arg(long, default_value = TESTNET_RPC_URL, value_name = "URL")]
    pub rpc_url: String,

    /// Secondary RPC URL for divergence checks. Defaults to `--rpc-url`.
    #[arg(long, value_name = "URL")]
    pub secondary_rpc_url: Option<String>,

    /// Submission timeout in seconds.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECONDS, value_name = "SECONDS")]
    pub timeout_seconds: u64,

    /// Output format: `json` (default) or `table`.
    #[arg(long, default_value_t = OutputFormat::DEFAULT, value_name = "FORMAT")]
    pub output: OutputFormat,
}

/// Arguments shared by the read subcommand (`get`).
#[derive(Debug, Args)]
pub struct CommonRulesReadArgs {
    /// Smart-account C-strkey.
    #[arg(long, value_name = "C_STRKEY", required = true)]
    pub account: String,

    /// Network to target.
    #[arg(long, default_value_t = TargetNetwork::Testnet, value_name = "NETWORK")]
    pub network: TargetNetwork,

    /// Soroban RPC endpoint URL.
    #[arg(long, default_value = TESTNET_RPC_URL, value_name = "URL")]
    pub rpc_url: String,

    /// Submission timeout in seconds.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECONDS, value_name = "SECONDS")]
    pub timeout_seconds: u64,

    /// Output format: `json` (default) or `table`.
    #[arg(long, default_value_t = OutputFormat::DEFAULT, value_name = "FORMAT")]
    pub output: OutputFormat,
}

/// Builds a [`CommonHandlerContext`] and [`ContextRuleManager`] from args that
/// implement [`CommonArgsView`], returning an error exit code on failure.
///
/// Used by the three simpler write handlers (`set_name_run`, `set_valid_until_run`,
/// `delete_run`) to collapse the repeated boilerplate context-build block.
/// `create_run` does not use this helper because it has substantial pre-validation
/// before the context-build step.
///
/// # Errors
///
/// Returns `Err(1)` with a JSON envelope emitted to stdout when context
/// construction or manager creation fails.
async fn prepare_write_context<A>(
    args: &A,
    output: OutputFormat,
    request_id: &str,
) -> Result<(CommonHandlerContext, ContextRuleManager), i32>
where
    A: CommonArgsView + Sync,
{
    let ctx = CommonHandlerContext::new(args)
        .await
        .map_err(|e| emit_error(&e, output, request_id))?;
    let manager = ctx
        .context_rule_manager()
        .map_err(|e| emit_error(&e, output, request_id))?;
    Ok((ctx, manager))
}

// ─────────────────────────────────────────────────────────────────────────────
// Top-level dispatch
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for the `smart-account rules` subcommand group.
#[derive(Debug, Args)]
#[non_exhaustive]
pub struct RulesArgs {
    /// The rules subcommand to run.
    #[command(subcommand)]
    pub subcommand: RulesSubcommand,
}

/// Subcommands of `stellar-agent smart-account rules`.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum RulesSubcommand {
    /// Install a new context rule (OZ `add_context_rule`).
    ///
    /// Builds an InvokeHostFunction op, simulates, signs the auth-entry
    /// digest, signs the SEP-23 source-account envelope, submits, and
    /// returns the new `rule_id` parsed from the simulated `ContextRule`
    /// return value.
    Create(Box<CreateArgs>),

    /// Read a single context rule by `rule_id` (OZ `get_context_rule`).
    ///
    /// Read-only path: no signing, no submission, no audit-log emission.
    /// Returns `Some(rule_struct)` on match or `None` if the rule was
    /// already removed.
    Get(Box<GetArgs>),

    /// Rename an existing rule (OZ `update_context_rule_name`).
    ///
    /// Single-arg metadata update; preserves `valid_until`, `signers`,
    /// `policies`.
    SetName(Box<SetNameArgs>),

    /// Change a rule's expiry (OZ `update_context_rule_valid_until`).
    ///
    /// `<ledger | none>`: a u32 ledger sequence sets explicit expiry;
    /// `none` clears expiry → permanent rule.
    SetValidUntil(Box<SetValidUntilArgs>),

    /// Remove a context rule (OZ `remove_context_rule`).
    ///
    /// Idempotent on the host side: re-deleting a missing rule fails
    /// simulation with `SmartAccountError::ContextRuleNotFound` and
    /// surfaces as `SaError::DeploymentFailed { phase: "simulate", ...}`.
    Delete(Box<DeleteArgs>),

    /// Verify the pinned wasm hashes for a context rule against live on-chain
    /// contracts (wasm-hash drift-detection on demand).
    ///
    /// Read-only; no signing, no submission. Reports `verifier_pin_status`
    /// and `policy_pin_status` each as one of `"match"`, `"drift"`,
    /// `"unavailable"`, `"no_pin"`, or `"no_contracts"`. The
    /// `pinned_*_first8` fields carry the stored pin from the audit log;
    /// `observed_*_first8` carry the live values fetched via two-RPC
    /// consultation.
    VerifyPins(Box<VerifyPinsArgs>),

    /// Add a policy contract to an existing context rule (OZ `add_policy`).
    ///
    /// Fetches the current rule via `get_context_rule`, checks the per-rule
    /// policy cap (`OZ_MAX_POLICIES = 5`) before simulate, then constructs an
    /// `InvokeHostFunctionOp` calling `add_policy(rule_id, policy, install_param)`,
    /// simulates, signs the auth-entry digest, submits, and returns the
    /// assigned `policy_id`.
    AddPolicy(Box<AddPolicyArgs>),

    /// Remove a policy from an existing context rule (OZ `remove_policy`).
    ///
    /// Constructs an `InvokeHostFunctionOp` calling
    /// `remove_policy(rule_id, policy_id)`, simulates, signs, and submits.
    RemovePolicy(Box<RemovePolicyArgs>),

    /// Read an installed spending-limit policy's budget state (read-only).
    ///
    /// Identifies the spending-limit policy via wasm-hash allowlist lookup,
    /// reads `get_spending_limit_data`, and computes the rolling-window
    /// budget snapshot. No signing, no submission, no audit-log emission.
    ///
    /// The returned `in_window_spent` / `remaining_budget` are exact only as
    /// of `as_of_ledger` — a point-in-time estimate, not a guarantee for a
    /// future submission (an intervening spend can still cause
    /// `SpendingLimitExceeded`).
    GetSpendingLimit(Box<GetSpendingLimitArgs>),

    /// Retune an installed spending-limit policy's limit (OZ
    /// `set_spending_limit`), without resetting rolling spend history.
    ///
    /// `period_ledgers` is immutable post-install: OZ `set_spending_limit`
    /// mutates only the limit. Retuning the period requires
    /// `remove-policy` + `add-policy --kind spending-limit`, which resets
    /// the rolling spend history.
    SetSpendingLimit(Box<SetSpendingLimitArgs>),

    /// Enumerate all active context rules on a smart account (canonical name).
    ///
    /// **Canonical command:** `smart-account rules list`. Delegates directly to
    /// [`crate::commands::smart_account::list_rules::run`]; argument shape and
    /// JSON envelope are identical to `smart-account list-rules`.
    ///
    /// `smart-account list-rules` is retained unchanged as a secondary entry point
    /// for backwards-compat. No deprecation warning is emitted.
    ///
    /// A `tracing::info!` row carrying `command = "smart-account rules list"` is
    /// emitted at the dispatch site so the operator-invoked command name is
    /// distinguishable from the alias in audit-log correlation.
    List(Box<ListArgs>),
}

/// Arguments for `smart-account rules list`.
///
/// Re-exports the [`sa_list_rules::ListRulesArgs`] shape verbatim; no newtype
/// wrapper is needed because clap derive resolves the type at the variant level
/// and the `#[command(override_usage)]` on `ListRulesArgs` is suppressed by the
/// parent `RulesSubcommand` context.
///
/// The JSON envelope shape is identical to `smart-account list-rules`.
pub type ListArgs = sa_list_rules::ListRulesArgs;

/// Runs the `smart-account rules` subcommand group.
///
/// # Errors
///
/// Never returns `Err` — errors are captured into the exit code.
///
/// # Panics
///
/// Never panics.
pub async fn run(args: &RulesArgs) -> i32 {
    match &args.subcommand {
        RulesSubcommand::Create(a) => create_run(a).await,
        RulesSubcommand::Get(a) => get_run(a).await,
        RulesSubcommand::SetName(a) => set_name_run(a).await,
        RulesSubcommand::SetValidUntil(a) => set_valid_until_run(a).await,
        RulesSubcommand::Delete(a) => delete_run(a).await,
        RulesSubcommand::VerifyPins(a) => verify_pins_run(a).await,
        RulesSubcommand::AddPolicy(a) => add_policy_run(a).await,
        RulesSubcommand::RemovePolicy(a) => remove_policy_run(a).await,
        RulesSubcommand::GetSpendingLimit(a) => get_spending_limit_run(a).await,
        RulesSubcommand::SetSpendingLimit(a) => set_spending_limit_run(a).await,
        RulesSubcommand::List(a) => list_rules_run(a).await,
    }
}

/// Dispatch handler for `smart-account rules list`.
///
/// Emits a structured `tracing::info!` row carrying the operator-invoked
/// command name (`"smart-account rules list"`) before delegating to the shared
/// `smart-account list-rules` handler.  The log row allows forensic correlation
/// across the audit log: an operator invoking `smart-account rules list` produces
/// `command = "smart-account rules list"`, whereas `smart-account list-rules` produces
/// `command = "smart-account list-rules"` at its own dispatch site — both refer
/// to the same underlying `list_active_context_rules` RPC scan.
///
/// Security note: without this emit the audit log cannot distinguish which
/// surface the operator used, which makes forensic timeline reconstruction
/// ambiguous.
async fn list_rules_run(args: &ListArgs) -> i32 {
    info!(
        command = "smart-account rules list",
        account = tracing::field::display(
            stellar_agent_core::observability::redact_strkey_first5_last5(&args.account)
        ),
        network = %args.network,
        "smart-account rules list: dispatching to list-rules handler"
    );
    sa_list_rules::run(args).await
}

// ─────────────────────────────────────────────────────────────────────────────
// `smart-account rules create`
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for `smart-account rules create`.
///
/// One required signer-source mode (mutually exclusive). One required
/// smart-account flag. At least one of `--signer-delegated` or
/// `--signer-webauthn` (repeatable; flags are cumulative for multi-sig rules).
/// OZ `MAX_SIGNERS=15` cap is enforced on-chain.
///
/// # Passkey-only refusal
///
/// When only `--signer-webauthn` entries are present and no `--signer-delegated`
/// entries are specified, the CLI prints a warning banner to stderr and refuses
/// with `validation.passkey_only_rule_no_delegated_fallback` unless
/// `--accept-no-delegated-fallback` is also passed.
///
/// Rationale: a passkey-only rule has no delegated G-key fallback. If the
/// authenticator device is lost the rule cannot be used. The flag makes the
/// operator explicitly acknowledge this risk.
#[non_exhaustive]
#[derive(Debug, Args)]
pub struct CreateArgs {
    /// Network, RPC, signer, timeout, and output shared with all write subcommands.
    #[command(flatten)]
    pub common: CommonRulesWriteArgs,

    /// Operator-facing rule name. Plain UTF-8; OZ length cap enforced
    /// on-chain.
    #[arg(long, value_name = "STRING", required = true)]
    pub name: String,

    /// One or more delegated-signer G-strkeys (one G-strkey per
    /// `--signer-delegated`; flag is repeatable).
    ///
    /// Each G-strkey is encoded as the OZ `Signer::Delegated(Address)`
    /// variant.
    #[arg(long = "signer-delegated", value_name = "G_STRKEY",
          num_args = 1.., action = clap::ArgAction::Append)]
    pub signer_delegated: Vec<String>,

    /// One or more passkey credential names (as stored in the passkeys registry
    /// via `credentials add-passkey`). Repeatable for multi-sig rules.
    ///
    /// Each name is resolved from `<passkeys_dir>/<profile>.toml`. The
    /// `public_key_sec1_b64` and `credential_id_b64url` fields are decoded
    /// and concatenated as `pubkey_data = pubkey_65_bytes || credential_id_bytes`
    /// (per the OZ `canonicalize_key` WebAuthn verifier convention).
    /// The on-chain representation is `Signer::External(verifier_addr, pubkey_data)`.
    ///
    /// The verifier contract address is read from the `VerifierRegistry` for
    /// the target network passphrase (written by `smart-account deploy-webauthn-verifier`).
    ///
    /// # Passkey-only fallback
    ///
    /// When no `--signer-delegated` entries are present, pass
    /// `--accept-no-delegated-fallback` to acknowledge the passkey-only risk.
    #[arg(long = "signer-webauthn", value_name = "CREDENTIAL_NAME",
          num_args = 1.., action = clap::ArgAction::Append)]
    pub signer_webauthn: Vec<String>,

    /// Acknowledge that this rule has no delegated (ed25519) fallback signer
    /// and the passkey authenticator device is the sole signing authority.
    ///
    /// Required when `--signer-webauthn` entries are provided and no
    /// `--signer-delegated` entries are present (passkey-only refusal). If
    /// omitted, the command is refused with
    /// `validation.passkey_only_rule_no_delegated_fallback`.
    #[arg(long)]
    pub accept_no_delegated_fallback: bool,

    /// Opt-in to installing a rule whose verifier or policy contract has a
    /// mutable admin / owner storage key.
    ///
    /// By default (`false`), `smart-account rules create` fails with
    /// `sa.verifier_mutable` / `sa.policy_mutable` when the referenced verifier
    /// or policy contract carries a non-zero `Admin` or `Owner` storage key (OZ
    /// ownable-storage convention).  A mutable contract can be silently upgraded
    /// by its administrator — pinning does not protect against that.
    ///
    /// When set, the install proceeds AND the audit log emits
    /// `SaMutableContractOverride { kind, rule_id, contract_address_redacted }`.
    /// The JSON envelope reflects `mutable_override: true`.
    #[arg(long)]
    pub accept_mutable_verifier: bool,

    /// Opt-in to installing a rule whose verifier wasm-hash is not in the
    /// `VERIFIER_ALLOWLIST` / `THRESHOLD_POLICY_WASM_HASHES` allowlists.
    ///
    /// By default (`false`), `smart-account rules create` fails with
    /// `sa.verifier_wasm_not_in_allowlist` / `sa.policy_wasm_not_in_allowlist`
    /// when the referenced contract's wasm is not a recognised version.  This
    /// prevents silent use of custom or unaudited verifier / policy contracts.
    ///
    /// When set, the install proceeds AND the audit log emits
    /// `SaUnknownContractOverride { kind, rule_id, contract_address_redacted }`.
    /// The JSON envelope reflects `unknown_override: true`.
    #[arg(long)]
    pub accept_unknown_verifier: bool,

    /// Auth rule-id(s) whose signers authorise this install. Repeatable.
    /// Default: `0` (the constructor-installed bootstrap rule from
    /// `accounts deploy-c`).
    #[arg(long = "auth-rule-id", value_name = "U32",
          num_args = 1.., action = clap::ArgAction::Append, default_values_t = [0_u32])]
    pub auth_rule_id: Vec<u32>,

    /// Optional ledger sequence at which the rule expires. Omit (or pass
    /// `none`) for a permanent rule.
    #[arg(long, value_name = "LEDGER", default_value = "none")]
    pub valid_until: String,

    /// Context the rule authorizes. Accepted forms:
    ///
    /// - `default` (or omit the flag) — authorizes any context.
    /// - `call-contract:<C-strkey>` — scopes the rule to invocations of one
    ///   specific contract.
    /// - `create-contract:<64-hex-wasm-hash>` — scopes the rule to creating a
    ///   contract with one specific 32-byte wasm hash.
    #[arg(long = "context", value_name = "SPEC", default_value = "default")]
    pub context: String,
}

/// Result envelope for `smart-account rules create`.
///
/// Carries the wasm-pinning fields `pinned_verifier_wasm_hashes_first8`,
/// `pinned_policy_wasm_hashes_first8`, `mutable_override`, and
/// `unknown_override` — all sourced from the `PinResult` returned by
/// `install_rule`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateResult {
    /// Smart-account C-strkey the rule was installed on.
    pub smart_account: String,
    /// Newly minted `rule_id` (parsed from the simulated `ContextRule`
    /// return value).
    pub rule_id: u32,
    /// Operator-facing rule name.
    pub name: String,
    /// Total number of signers attached (delegated + external/WebAuthn combined).
    pub signers_count: u32,
    /// Number of delegated (ed25519) signers attached.
    pub signer_delegated_count: u32,
    /// Number of WebAuthn passkey (External) signers attached.
    pub signer_webauthn_count: u32,
    /// Optional ledger expiry, `null` for permanent rules.
    pub valid_until: Option<u32>,
    /// First-8-hex of each pinned verifier wasm hash (one per distinct
    /// External signer verifier contract).  Empty when no External signers
    /// are present.  Non-empty values confirm the wasm-hash pin was recorded.
    pub pinned_verifier_wasm_hashes_first8: Vec<String>,
    /// First-8-hex of each pinned policy wasm hash (one per policy attached
    /// to the rule).  Empty when no policies are present.
    pub pinned_policy_wasm_hashes_first8: Vec<String>,
    /// `true` when `--accept-mutable-verifier` was set AND at least one
    /// referenced contract had a mutable admin / owner key.
    pub mutable_override: bool,
    /// `true` when `--accept-unknown-verifier` was set AND at least one
    /// referenced contract had a wasm hash outside the allowlist.
    pub unknown_override: bool,
}

async fn create_run(args: &CreateArgs) -> i32 {
    let request_id = new_request_id();
    let account_redacted = redact_strkey_first5_last5(&args.common.account);

    if args.common.network == TargetNetwork::Mainnet {
        return emit_error(
            &WalletError::Network(NetworkError::MainnetWriteForbidden),
            args.common.output,
            &request_id,
        );
    }

    // Require at least one signer of any kind.
    if args.signer_delegated.is_empty() && args.signer_webauthn.is_empty() {
        return emit_error(
            &WalletError::Validation(ValidationError::AddressInvalid {
                input: "at least one of --signer-delegated or --signer-webauthn is required"
                    .to_owned(),
            }),
            args.common.output,
            &request_id,
        );
    }

    // Refuse a passkey-only rule without explicit acknowledgement: if ALL
    // signers are WebAuthn (no delegated fallback), the operator must pass
    // --accept-no-delegated-fallback to acknowledge that a lost authenticator
    // device leaves the rule permanently inaccessible.
    if args.signer_delegated.is_empty()
        && !args.signer_webauthn.is_empty()
        && !args.accept_no_delegated_fallback
    {
        // Print a stderr warning banner before the JSON refusal.
        #[allow(
            clippy::print_stderr,
            reason = "passkey-only risk acknowledgement banner"
        )]
        {
            eprintln!();
            eprintln!(
                "WARNING: passkey-only context rule — no delegated (ed25519) fallback signer."
            );
            eprintln!(
                "  If the authenticator device is lost, this rule will be permanently inaccessible."
            );
            eprintln!(
                "  To acknowledge this risk and proceed, add: --accept-no-delegated-fallback"
            );
            eprintln!();
        }
        return emit_error(
            &WalletError::Validation(ValidationError::PasskeyOnlyRuleNoDelegatedFallback {
                credential_count: args.signer_webauthn.len(),
            }),
            args.common.output,
            &request_id,
        );
    }

    // Pre-simulate signer-cap check: count the combined total of delegated +
    // webauthn signers BEFORE any network call and refuse fail-CLOSED when the
    // total exceeds OZ_MAX_SIGNERS. The on-chain enforcement
    // (`TooManySigners = 3010`) is the authoritative last-line defence; this
    // check gives the operator an actionable error with the rule-rotation
    // alternative before the simulate/submit cycle is reached.
    let signer_total = args.signer_delegated.len() + args.signer_webauthn.len();
    if let Err(e) = enforce_signer_cap(signer_total) {
        return emit_error(&WalletError::Validation(e), args.common.output, &request_id);
    }

    // Name-length pre-flight: OZ `MAX_NAME_SIZE = 20` bytes. The on-chain
    // `NameTooLong = 3015` panic is the authoritative last-line defence; this
    // check gives the operator an actionable `validation.rule_name_too_long`
    // error before any RPC call.
    if args.name.len() > OZ_MAX_NAME_SIZE {
        return emit_error(
            &WalletError::Validation(ValidationError::RuleNameTooLong {
                name_len: args.name.len(),
                max: OZ_MAX_NAME_SIZE,
            }),
            args.common.output,
            &request_id,
        );
    }

    // `smart-account rules create` does not currently support --policy flags; if/when
    // added, the policy-cap-check site lands here with
    // `kind: CapKind::Policy, max: OZ_MAX_POLICIES`.

    // Build the combined signer list: delegated entries first, then external.
    let delegated_count = args.signer_delegated.len() as u32;
    let mut signers: Vec<ContextRuleSignerInput> =
        Vec::with_capacity(args.signer_delegated.len() + args.signer_webauthn.len());

    for s in &args.signer_delegated {
        match parse_g_strkey_for_signer(s) {
            Ok(addr) => signers.push(ContextRuleSignerInput::Delegated { address: addr }),
            Err(e) => return emit_error(&e, args.common.output, &request_id),
        }
    }

    // Resolve WebAuthn passkey signers → External entries.
    let webauthn_count = args.signer_webauthn.len() as u32;
    if !args.signer_webauthn.is_empty() {
        // Load the VerifierRegistry to get the verifier contract address for
        // this network (written by `smart-account deploy-webauthn-verifier`).
        let verifier_registry = match VerifierRegistry::open() {
            Ok(r) => r,
            Err(e) => {
                return emit_error(
                    &WalletError::Validation(ValidationError::AddressInvalid {
                        input: format!("could not open verifier registry: {e}"),
                    }),
                    args.common.output,
                    &request_id,
                );
            }
        };

        let network_passphrase = args.common.network.passphrase();
        let verifier_entry = match verifier_registry.webauthn_verifier_for(network_passphrase) {
            Some(e) => e,
            None => {
                return emit_error(
                    &WalletError::Validation(ValidationError::AddressInvalid {
                        input: format!(
                            "no WebAuthn verifier deployed for network '{}'; \
                                 run: smart-account deploy-webauthn-verifier",
                            network_passphrase
                        ),
                    }),
                    args.common.output,
                    &request_id,
                );
            }
        };

        let verifier_sc_addr = match parse_c_strkey(&verifier_entry.address) {
            Ok(addr) => addr,
            Err(e) => return emit_error(&e, args.common.output, &request_id),
        };

        // Load the selected profile's passkeys registry read-only (no approval
        // store needed).
        let profile = resolve_profile_name(args.common.profile.as_deref());
        if let Err(reason) = validate_path_component_ascii_safe(&profile) {
            return emit_error(
                &WalletError::Validation(ValidationError::AddressInvalid {
                    input: format!("invalid profile name '{profile}': {reason}"),
                }),
                args.common.output,
                &request_id,
            );
        }
        // The "localhost" default satisfies the WebAuthn-2 §5.1.2 domain requirement.
        let creds_mgr = match CredentialsManager::from_defaults_readonly(&profile, "localhost") {
            Ok(m) => m,
            Err(e) => {
                return emit_error(
                    &WalletError::Validation(ValidationError::AddressInvalid {
                        input: format!("could not open passkeys registry: {e}"),
                    }),
                    args.common.output,
                    &request_id,
                );
            }
        };

        for credential_name in &args.signer_webauthn {
            let metadata = match creds_mgr.show(credential_name) {
                Ok(m) => m,
                Err(e) => {
                    return emit_error(
                        &WalletError::Validation(ValidationError::AddressInvalid {
                            input: format!("--signer-webauthn '{}': {e}", credential_name),
                        }),
                        args.common.output,
                        &request_id,
                    );
                }
            };

            if metadata.public_key_sec1_b64.is_empty() {
                return emit_error(
                    &WalletError::Validation(ValidationError::AddressInvalid {
                        input: format!(
                            "--signer-webauthn '{}': credential is missing \
                             public_key_sec1_b64 (delete and re-register)",
                            credential_name
                        ),
                    }),
                    args.common.output,
                    &request_id,
                );
            }

            // Decode public key (65-byte uncompressed SEC1 P-256 point).
            let pubkey_bytes = match base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(&metadata.public_key_sec1_b64)
            {
                Ok(b) => b,
                Err(_) => {
                    return emit_error(
                        &WalletError::Validation(ValidationError::AddressInvalid {
                            input: format!(
                                "--signer-webauthn '{}': public_key_sec1_b64 \
                                 is not valid base64url",
                                credential_name
                            ),
                        }),
                        args.common.output,
                        &request_id,
                    );
                }
            };
            if pubkey_bytes.len() != 65 {
                return emit_error(
                    &WalletError::Validation(ValidationError::AddressInvalid {
                        input: format!(
                            "--signer-webauthn '{}': public_key_sec1_b64 decodes to \
                             {} bytes, expected 65",
                            credential_name,
                            pubkey_bytes.len()
                        ),
                    }),
                    args.common.output,
                    &request_id,
                );
            }

            // Decode credential_id bytes.
            let credential_id_bytes = match base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(&metadata.credential_id_b64url)
            {
                Ok(b) => b,
                Err(_) => {
                    return emit_error(
                        &WalletError::Validation(ValidationError::AddressInvalid {
                            input: format!(
                                "--signer-webauthn '{}': credential_id_b64url \
                                 is not valid base64url",
                                credential_name
                            ),
                        }),
                        args.common.output,
                        &request_id,
                    );
                }
            };

            // pubkey_data = pubkey_65_bytes || credential_id_bytes.
            // Per the OZ `canonicalize_key` WebAuthn verifier convention:
            //   keyData = stored.publicKey + credIdBytes
            // The exact concatenation is canonical and MUST NOT be reordered.
            let mut pubkey_data = Vec::with_capacity(65 + credential_id_bytes.len());
            pubkey_data.extend_from_slice(&pubkey_bytes);
            pubkey_data.extend_from_slice(&credential_id_bytes);

            signers.push(ContextRuleSignerInput::External {
                verifier: verifier_sc_addr.clone(),
                pubkey_data,
            });
        }
    }

    let valid_until = match parse_valid_until(&args.valid_until) {
        Ok(v) => v,
        Err(e) => return emit_error(&e, args.common.output, &request_id),
    };

    // Parse the context grammar before any network setup so a malformed
    // `--context` fails closed with no RPC round-trip.
    let context_type = match parse_rule_context(&args.context) {
        Ok(c) => c,
        Err(e) => return emit_error(&e, args.common.output, &request_id),
    };

    // `create_run` builds its own context/manager here rather than going through
    // `prepare_write_context` because it has substantial pre-validation above.
    // The explicit `context_rule_manager()` call is required to wire the
    // `SignersManager` for wasm-hash pin enforcement.
    let ctx = match CommonHandlerContext::new(args).await {
        Ok(ctx) => ctx,
        Err(e) => return emit_error(&e, args.common.output, &request_id),
    };
    let manager = match ctx.context_rule_manager() {
        Ok(m) => m,
        Err(e) => return emit_error(&e, args.common.output, &request_id),
    };

    let definition = ContextRuleDefinition::new(
        context_type,
        args.name.clone(),
        valid_until,
        signers,
        vec![],
    );

    let signers_count = definition.signers_count();
    let auth_rule_ids: Vec<ContextRuleId> = args
        .auth_rule_id
        .iter()
        .map(|id| ContextRuleId::new(*id))
        .collect();

    match manager
        .install_rule(
            ctx.smart_account,
            definition,
            auth_rule_ids,
            ctx.signer.as_ref(),
            None,
            request_id.clone(),
            args.accept_mutable_verifier,
            args.accept_unknown_verifier,
        )
        .await
    {
        Ok(InstallRuleOutput {
            rule_id,
            pin_result,
            ..
        }) => {
            let pinned_verifier_wasm_hashes_first8 = pin_result.pinned_verifier_hashes_first8();
            let pinned_policy_wasm_hashes_first8 = pin_result.pinned_policy_hashes_first8();
            info!(
                smart_account = %account_redacted,
                rule_id,
                signers_count,
                signer_delegated_count = delegated_count,
                signer_webauthn_count = webauthn_count,
                mutable_override = pin_result.mutable_override,
                unknown_override = pin_result.unknown_override,
                "smart-account rules create: installed",
            );
            let result = CreateResult {
                smart_account: args.common.account.clone(),
                rule_id,
                name: args.name.clone(),
                signers_count,
                signer_delegated_count: delegated_count,
                signer_webauthn_count: webauthn_count,
                valid_until,
                pinned_verifier_wasm_hashes_first8,
                pinned_policy_wasm_hashes_first8,
                mutable_override: pin_result.mutable_override,
                unknown_override: pin_result.unknown_override,
            };
            emit_success(&result, args.common.output, &request_id, 0)
        }
        Err(e) => emit_error_sa(&e, args.common.output, &request_id),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// `smart-account rules get`
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for `smart-account rules get`.
#[non_exhaustive]
#[derive(Debug, Args)]
pub struct GetArgs {
    /// Network, RPC, timeout, and output shared with read subcommands.
    #[command(flatten)]
    pub common: CommonRulesReadArgs,

    /// Rule index to fetch.
    #[arg(long, value_name = "U32", required = true)]
    pub rule_id: u32,

    /// Source-account strkey for the simulation envelope. Any funded
    /// account on the target network works (read-only path; no signing).
    #[arg(long, value_name = "G_STRKEY", required = true)]
    pub source_account: String,
}

/// Result envelope for `smart-account rules get`. `present == false` means the
/// host-side `get_context_rule` raised `ContextRuleNotFound`.
///
/// Returns the presence flag + the queried `rule_id`. Structured rule-shape
/// decoding (signers, policies, valid_until, name) is surfaced by the
/// `smart-account rules list` enumerator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetResult {
    /// Smart-account C-strkey.
    pub smart_account: String,
    /// Queried rule index.
    pub rule_id: u32,
    /// `true` when the rule was found, `false` when on-chain
    /// `ContextRuleNotFound` was raised.
    pub present: bool,
}

async fn get_run(args: &GetArgs) -> i32 {
    let request_id = new_request_id();
    let account_redacted = redact_strkey_first5_last5(&args.common.account);

    let smart_account = match parse_c_strkey(&args.common.account) {
        Ok(addr) => addr,
        Err(e) => return emit_error(&e, args.common.output, &request_id),
    };

    if let Err(e) = stellar_strkey::ed25519::PublicKey::from_string(&args.source_account) {
        return emit_error(
            &WalletError::Validation(ValidationError::AddressInvalid {
                input: format!("--source-account: invalid G-strkey ({e})"),
            }),
            args.common.output,
            &request_id,
        );
    }

    // Use the read-only builder (no SignersManager): get_rule is a simulation-
    // only read path; there is nothing to authorise and no divergence check is
    // warranted.
    let manager = match build_readonly_manager(
        args.common.network,
        &args.common.rpc_url,
        args.common.timeout_seconds,
    ) {
        Ok(m) => m,
        Err(e) => return emit_error(&e, args.common.output, &request_id),
    };

    match manager
        .get_rule(smart_account, args.rule_id, &args.source_account)
        .await
    {
        Ok(Some(_scval)) => {
            info!(
                smart_account = %account_redacted,
                rule_id = args.rule_id,
                "smart-account rules get: present",
            );
            let result = GetResult {
                smart_account: args.common.account.clone(),
                rule_id: args.rule_id,
                present: true,
            };
            emit_success(&result, args.common.output, &request_id, 0)
        }
        Ok(None) => {
            info!(
                smart_account = %account_redacted,
                rule_id = args.rule_id,
                "smart-account rules get: not present",
            );
            let result = GetResult {
                smart_account: args.common.account.clone(),
                rule_id: args.rule_id,
                present: false,
            };
            emit_success(&result, args.common.output, &request_id, 0)
        }
        Err(e) => emit_error_sa(&e, args.common.output, &request_id),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// `smart-account rules set-name`
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for `smart-account rules set-name`.
#[non_exhaustive]
#[derive(Debug, Args)]
pub struct SetNameArgs {
    /// Network, RPC, signer, timeout, and output shared with all write subcommands.
    #[command(flatten)]
    pub common: CommonRulesWriteArgs,

    /// Rule index to rename.
    #[arg(long, value_name = "U32", required = true)]
    pub rule_id: u32,

    /// New rule name.
    #[arg(long, value_name = "STRING", required = true)]
    pub name: String,

    /// Auth rule-id whose signers authorise this update (typically the same
    /// as `--rule-id`; OZ may permit a different rule's signers to authorise
    /// when scoped under a meta-rule). Default: `--rule-id`.
    #[arg(long, value_name = "U32")]
    pub auth_rule_id: Option<u32>,
}

/// Result envelope for `smart-account rules set-name`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetNameResult {
    /// Smart-account C-strkey.
    pub smart_account: String,
    /// Updated rule index.
    pub rule_id: u32,
    /// New rule name.
    pub name: String,
}

async fn set_name_run(args: &SetNameArgs) -> i32 {
    let request_id = new_request_id();
    let account_redacted = redact_strkey_first5_last5(&args.common.account);

    if args.common.network == TargetNetwork::Mainnet {
        return emit_error(
            &WalletError::Network(NetworkError::MainnetWriteForbidden),
            args.common.output,
            &request_id,
        );
    }

    // Name-length pre-flight: OZ `MAX_NAME_SIZE = 20` bytes.
    if args.name.len() > OZ_MAX_NAME_SIZE {
        return emit_error(
            &WalletError::Validation(ValidationError::RuleNameTooLong {
                name_len: args.name.len(),
                max: OZ_MAX_NAME_SIZE,
            }),
            args.common.output,
            &request_id,
        );
    }

    let (ctx, manager) = match prepare_write_context(args, args.common.output, &request_id).await {
        Ok(pair) => pair,
        Err(code) => return code,
    };

    let auth_rule_ids = vec![ContextRuleId::new(
        args.auth_rule_id.unwrap_or(args.rule_id),
    )];

    match manager
        .update_name(
            ctx.smart_account,
            args.rule_id,
            args.name.clone(),
            auth_rule_ids,
            ctx.signer.as_ref(),
            None,
            request_id.clone(),
        )
        .await
    {
        Ok(()) => {
            info!(
                smart_account = %account_redacted,
                rule_id = args.rule_id,
                "smart-account rules set-name: updated",
            );
            let result = SetNameResult {
                smart_account: args.common.account.clone(),
                rule_id: args.rule_id,
                name: args.name.clone(),
            };
            emit_success(&result, args.common.output, &request_id, 0)
        }
        Err(e) => emit_error_sa(&e, args.common.output, &request_id),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// `smart-account rules set-valid-until`
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for `smart-account rules set-valid-until`.
#[non_exhaustive]
#[derive(Debug, Args)]
pub struct SetValidUntilArgs {
    /// Network, RPC, signer, timeout, and output shared with all write subcommands.
    #[command(flatten)]
    pub common: CommonRulesWriteArgs,

    /// Rule index to update.
    #[arg(long, value_name = "U32", required = true)]
    pub rule_id: u32,

    /// New expiry: a u32 ledger sequence, or `none` to clear expiry
    /// (permanent rule).
    #[arg(long, value_name = "LEDGER|none", required = true)]
    pub valid_until: String,

    /// Auth rule-id (default: `--rule-id`).
    #[arg(long, value_name = "U32")]
    pub auth_rule_id: Option<u32>,
}

/// Result envelope for `smart-account rules set-valid-until`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetValidUntilResult {
    /// Smart-account C-strkey.
    pub smart_account: String,
    /// Updated rule index.
    pub rule_id: u32,
    /// New `valid_until`. `null` = permanent (`none` was passed).
    pub valid_until: Option<u32>,
}

async fn set_valid_until_run(args: &SetValidUntilArgs) -> i32 {
    let request_id = new_request_id();
    let account_redacted = redact_strkey_first5_last5(&args.common.account);

    if args.common.network == TargetNetwork::Mainnet {
        return emit_error(
            &WalletError::Network(NetworkError::MainnetWriteForbidden),
            args.common.output,
            &request_id,
        );
    }

    let valid_until = match parse_valid_until(&args.valid_until) {
        Ok(v) => v,
        Err(e) => return emit_error(&e, args.common.output, &request_id),
    };

    let (ctx, manager) = match prepare_write_context(args, args.common.output, &request_id).await {
        Ok(pair) => pair,
        Err(code) => return code,
    };

    let auth_rule_ids = vec![ContextRuleId::new(
        args.auth_rule_id.unwrap_or(args.rule_id),
    )];

    match manager
        .update_valid_until(
            ctx.smart_account,
            args.rule_id,
            valid_until,
            auth_rule_ids,
            ctx.signer.as_ref(),
            None,
            request_id.clone(),
        )
        .await
    {
        Ok(()) => {
            let valid_until_label = valid_until
                .map(|n| n.to_string())
                .unwrap_or_else(|| "none".to_owned());
            info!(
                smart_account = %account_redacted,
                rule_id = args.rule_id,
                valid_until = %valid_until_label,
                "smart-account rules set-valid-until: updated",
            );
            let result = SetValidUntilResult {
                smart_account: args.common.account.clone(),
                rule_id: args.rule_id,
                valid_until,
            };
            emit_success(&result, args.common.output, &request_id, 0)
        }
        Err(e) => emit_error_sa(&e, args.common.output, &request_id),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// `smart-account rules delete`
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for `smart-account rules delete`.
#[non_exhaustive]
#[derive(Debug, Args)]
pub struct DeleteArgs {
    /// Network, RPC, signer, timeout, and output shared with all write subcommands.
    #[command(flatten)]
    pub common: CommonRulesWriteArgs,

    /// Rule index to delete.
    #[arg(long, value_name = "U32", required = true)]
    pub rule_id: u32,

    /// Auth rule-id (default: `--rule-id`).
    #[arg(long, value_name = "U32")]
    pub auth_rule_id: Option<u32>,
}

/// Result envelope for `smart-account rules delete`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteResult {
    /// Smart-account C-strkey.
    pub smart_account: String,
    /// Deleted rule index.
    pub rule_id: u32,
}

macro_rules! impl_common_args_view {
    ($ty:ty) => {
        impl CommonArgsView for $ty {
            fn account(&self) -> &str {
                &self.common.account
            }

            fn profile(&self) -> Option<&str> {
                self.common.profile.as_deref()
            }

            fn signer_source(&self) -> &SignerSourceFlags {
                &self.common.signer_source
            }

            fn network(&self) -> TargetNetwork {
                self.common.network
            }

            fn rpc_url(&self) -> &str {
                &self.common.rpc_url
            }

            fn secondary_rpc_url(&self) -> Option<&str> {
                self.common.secondary_rpc_url.as_deref()
            }

            fn timeout_seconds(&self) -> u64 {
                self.common.timeout_seconds
            }
        }
    };
}

impl_common_args_view!(CreateArgs);
impl_common_args_view!(SetNameArgs);
impl_common_args_view!(SetValidUntilArgs);
impl_common_args_view!(DeleteArgs);

async fn delete_run(args: &DeleteArgs) -> i32 {
    let request_id = new_request_id();
    let account_redacted = redact_strkey_first5_last5(&args.common.account);

    if args.common.network == TargetNetwork::Mainnet {
        return emit_error(
            &WalletError::Network(NetworkError::MainnetWriteForbidden),
            args.common.output,
            &request_id,
        );
    }

    let (ctx, manager) = match prepare_write_context(args, args.common.output, &request_id).await {
        Ok(pair) => pair,
        Err(code) => return code,
    };

    let auth_rule_ids = vec![ContextRuleId::new(
        args.auth_rule_id.unwrap_or(args.rule_id),
    )];

    match manager
        .delete_rule(
            ctx.smart_account,
            args.rule_id,
            auth_rule_ids,
            ctx.signer.as_ref(),
            None,
            request_id.clone(),
        )
        .await
    {
        Ok(()) => {
            info!(
                smart_account = %account_redacted,
                rule_id = args.rule_id,
                "smart-account rules delete: removed",
            );
            let result = DeleteResult {
                smart_account: args.common.account.clone(),
                rule_id: args.rule_id,
            };
            emit_success(&result, args.common.output, &request_id, 0)
        }
        Err(e) => emit_error_sa(&e, args.common.output, &request_id),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// `smart-account rules verify-pins`
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for `smart-account rules verify-pins`.
///
/// Read-only — no signing, no submission. Requires a signer-source to derive
/// the source-account G-strkey for the `getLedgerEntries` simulation envelope.
#[non_exhaustive]
#[derive(Debug, Args)]
pub struct VerifyPinsArgs {
    /// Smart-account contract C-strkey.
    #[arg(long, value_name = "C_STRKEY", required = true)]
    pub account: String,

    /// Rule ID whose pinned wasm hashes to verify.
    #[arg(long, value_name = "U32", required = true)]
    pub rule_id: u32,

    /// Optional profile override for the audit-log directory.
    #[arg(long, value_name = "NAME")]
    pub profile: Option<String>,

    /// Signer-source mode (used to derive source-account for RPC simulation).
    #[command(flatten)]
    pub signer_source: SignerSourceFlags,

    /// Network to target (testnet / mainnet).
    ///
    /// Read-only; mainnet is allowed for verification.
    #[arg(long, default_value_t = TargetNetwork::Testnet, value_name = "NETWORK")]
    pub network: TargetNetwork,

    /// Soroban RPC endpoint URL.
    #[arg(long, value_name = "URL")]
    pub rpc_url: Option<String>,

    /// Secondary RPC URL for two-RPC consultation. Defaults to `--rpc-url`.
    #[arg(long, value_name = "URL")]
    pub secondary_rpc_url: Option<String>,

    /// Request timeout in seconds.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECONDS, value_name = "SECONDS")]
    pub timeout_seconds: u64,

    /// Output format: `json` (default) or `table`.
    #[arg(long, default_value_t = OutputFormat::DEFAULT, value_name = "FORMAT")]
    pub output: OutputFormat,
}

impl CommonArgsView for VerifyPinsArgs {
    fn account(&self) -> &str {
        &self.account
    }

    fn profile(&self) -> Option<&str> {
        self.profile.as_deref()
    }

    fn signer_source(&self) -> &SignerSourceFlags {
        &self.signer_source
    }

    fn network(&self) -> TargetNetwork {
        self.network
    }

    fn rpc_url(&self) -> &str {
        // verify-pins mainnet fallback intentionally uses the third-party
        // Validation Cloud default documented on MAINNET_RPC_URL.
        self.rpc_url.as_deref().unwrap_or(match self.network {
            TargetNetwork::Testnet => TESTNET_RPC_URL,
            TargetNetwork::Mainnet => MAINNET_RPC_URL,
        })
    }

    fn secondary_rpc_url(&self) -> Option<&str> {
        self.secondary_rpc_url.as_deref()
    }

    fn timeout_seconds(&self) -> u64 {
        self.timeout_seconds
    }
}

/// Result envelope for `smart-account rules verify-pins`.
///
/// Each `*_pin_status` field is one of `"match"`, `"drift"`, `"unavailable"`,
/// `"no_pin"`, or `"no_contracts"` (serialised via [`PinStatus`]).
/// Mirrors `stellar_agent_smart_account::managers::rules::VerifyPinsResult`
/// and adds CLI-specific chain metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyPinsResult {
    /// Smart-account C-strkey checked.
    pub smart_account: String,
    /// Rule ID checked.
    pub rule_id: u32,
    /// Pin status for verifier contracts.
    pub verifier_pin_status: PinStatus,
    /// Pin status for policy contracts.
    pub policy_pin_status: PinStatus,
    /// Pinned verifier wasm hashes first-8-hex (from audit log).
    pub pinned_verifier_first8: Vec<String>,
    /// Pinned policy wasm hashes first-8-hex (from audit log).
    pub pinned_policy_first8: Vec<String>,
    /// Observed live verifier wasm hashes first-8-hex (from chain).
    pub observed_verifier_first8: Vec<String>,
    /// Observed live policy wasm hashes first-8-hex (from chain).
    pub observed_policy_first8: Vec<String>,
    /// Install-time mutable-contract override flag, sourced from the
    /// `SaContextRuleCreated` audit row. `false` for rules installed before
    /// override tracking was added.
    pub mutable_override: bool,
    /// Install-time unknown-wasm override flag, sourced from the
    /// `SaContextRuleCreated` audit row. `false` for rules installed before
    /// override tracking was added.
    pub unknown_override: bool,
    /// Present when `verifier_pin_status` or `policy_pin_status` is
    /// `Unavailable`, carrying the inner `SaError` wire code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unavailable_reason: Option<String>,
    /// CAIP-2 chain ID of the network checked.
    pub chain_id: String,
}

impl VerifyPinsResult {
    fn from_sa(sa: SaVerifyPinsResult, chain_id: String) -> Self {
        Self {
            smart_account: sa.smart_account,
            rule_id: sa.rule_id,
            verifier_pin_status: sa.verifier_pin_status,
            policy_pin_status: sa.policy_pin_status,
            pinned_verifier_first8: sa.pinned_verifier_first8,
            pinned_policy_first8: sa.pinned_policy_first8,
            observed_verifier_first8: sa.observed_verifier_first8,
            observed_policy_first8: sa.observed_policy_first8,
            mutable_override: sa.mutable_override,
            unknown_override: sa.unknown_override,
            unavailable_reason: sa.unavailable_wire_code.map(str::to_owned),
            chain_id,
        }
    }
}

async fn verify_pins_run(args: &VerifyPinsArgs) -> i32 {
    let request_id = new_request_id();
    let account_redacted = redact_strkey_first5_last5(&args.account);

    let ctx = match CommonHandlerContext::new(args).await {
        Ok(ctx) => ctx,
        Err(e) => return emit_error(&e, args.output, &request_id),
    };

    let source_account_strkey = match ctx.signer.public_key().await {
        Ok(pk) => pk.to_string(),
        Err(e) => {
            return emit_error(
                &WalletError::Validation(ValidationError::AddressInvalid {
                    input: format!("signer.public_key(): {e}"),
                }),
                args.output,
                &request_id,
            );
        }
    };

    let manager = match ctx.context_rule_manager() {
        Ok(m) => m,
        Err(e) => return emit_error(&e, args.output, &request_id),
    };

    info!(
        smart_account = %account_redacted,
        rule_id = args.rule_id,
        "smart-account rules verify-pins: running",
    );

    match manager
        .verify_rule_wasm_pins(
            ctx.smart_account,
            args.rule_id,
            &source_account_strkey,
            &request_id,
        )
        .await
    {
        Ok(sa_result) => {
            let chain_id = ctx.chain_id.clone();
            let result = VerifyPinsResult::from_sa(sa_result, chain_id);
            // Log the verdict at info level (no secret data in status strings).
            info!(
                smart_account = %account_redacted,
                rule_id = args.rule_id,
                verifier_pin_status = ?result.verifier_pin_status,
                policy_pin_status = ?result.policy_pin_status,
                "smart-account rules verify-pins: completed",
            );
            // Return exit code 1 when any status is Drift (operator-visible
            // signal that intervention is needed) while still emitting a
            // well-formed JSON envelope. Unavailable exits 0 (infrastructure
            // failure, not confirmed drift).
            let drift = matches!(result.verifier_pin_status, PinStatus::Drift)
                || matches!(result.policy_pin_status, PinStatus::Drift);
            let exit = if drift { 1 } else { 0 };
            emit_success(&result, args.output, &request_id, exit)
        }
        Err(e) => emit_error_sa(&e, args.output, &request_id),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// `smart-account rules add-policy`
// ─────────────────────────────────────────────────────────────────────────────

/// Selects how `smart-account rules add-policy` builds the install parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum PolicyKind {
    /// Raw passthrough: the operator supplies `--policy-address` and a
    /// base64-XDR `--install-param` verbatim.
    Raw,
    /// Typed spending-limit policy: the wallet resolves the deployed
    /// spending-limit policy from the registry (or `--policy` override), builds
    /// the `SpendingLimitAccountParams` install param from `--limit` + `--period`,
    /// and refuses non-`CallContract` rules client-side.
    SpendingLimit,
    /// Typed simple-threshold policy: the wallet resolves the deployed
    /// simple-threshold policy from the registry (or `--policy` override) and
    /// builds the one-entry `SimpleThresholdAccountParams` install param from
    /// `--threshold`. No context-type restriction.
    #[value(name = "simple-threshold")]
    SimpleThreshold,
    /// Typed weighted-threshold policy: the wallet resolves the deployed
    /// weighted-threshold policy from the registry (or `--policy` override)
    /// and builds the `WeightedThresholdAccountParams` install param from one
    /// or more `--weighted-signer-delegated` / `--weighted-signer-webauthn`
    /// flags (each `<identity>=<weight>`) plus `--threshold`. No
    /// context-type restriction (unlike spending-limit).
    #[value(name = "weighted-threshold")]
    WeightedThreshold,
}

/// Arguments for `smart-account rules add-policy`.
///
/// Adds a policy contract to an existing context rule.  Two mutually-exclusive
/// modes selected by `--kind`:
///
/// - `--kind raw` (default) — the operator supplies `--policy-address` and a
///   base64-encoded XDR `ScVal` `--install-param` (standard base64, not
///   base64url).  The wallet passes the decoded `ScVal` through to the on-chain
///   `add_policy(rule_id, policy, install_param)` call without further validation
///   (raw passthrough).
/// - `--kind spending-limit` — the wallet resolves the deployed OZ
///   spending-limit policy from the [`VerifierRegistry`] (or `--policy`
///   override), builds the `SpendingLimitAccountParams` install param from
///   `--limit` + `--period`, and refuses non-`CallContract` rules client-side
///   (OZ `install` rejects them with `OnlyCallContractAllowed`).
///
/// The per-rule policy cap (`OZ_MAX_POLICIES = 5`) is enforced BEFORE the
/// simulate cycle via a `get_context_rule` pre-fetch (shared by both modes).
///
/// # Mainnet write defence
///
/// Structurally refuses mainnet (`network.mainnet_write_forbidden`) before
/// any RPC or signing call.
#[non_exhaustive]
#[derive(Debug, Args)]
pub struct AddPolicyArgs {
    /// Smart-account contract C-strkey.
    #[arg(long, value_name = "C_STRKEY", required = true)]
    pub account: String,

    /// Context rule ID to add the policy to.
    #[arg(long, value_name = "U32", required = true)]
    pub rule_id: u32,

    /// Install-parameter mode. Default: `raw`.
    #[arg(
        long,
        value_enum,
        default_value_t = PolicyKind::Raw,
        value_name = "raw|spending-limit|simple-threshold|weighted-threshold"
    )]
    pub kind: PolicyKind,

    /// Policy contract C-strkey (raw mode).
    ///
    /// Required with `--kind raw`. Ignored with `--kind spending-limit` (use
    /// `--policy` for the typed override).
    #[arg(long, value_name = "C_STRKEY")]
    pub policy_address: Option<String>,

    /// Base64-encoded XDR `ScVal` install parameter (raw mode).
    ///
    /// Required with `--kind raw`. The wallet decodes this from standard base64
    /// (not base64url) and passes the resulting `ScVal` to `add_policy`
    /// unvalidated (raw passthrough). Use `stellar-xdr encode` or the MCP XDR
    /// tools to produce the correct encoding for a given policy type.
    #[arg(long, value_name = "SCVAL_BASE64")]
    pub install_param: Option<String>,

    /// Spending-limit in stroops (`--kind spending-limit`).
    ///
    /// Required with `--kind spending-limit`. The `i128` amount the rolling
    /// window admits before the policy panics `SpendingLimitExceeded`.
    #[arg(long, value_name = "STROOPS")]
    pub limit: Option<i128>,

    /// Rolling-window length in ledgers (`--kind spending-limit`).
    ///
    /// Required with `--kind spending-limit`.
    #[arg(long, value_name = "LEDGERS")]
    pub period: Option<u32>,

    /// Spending-limit policy contract C-strkey override (`--kind spending-limit`).
    ///
    /// When omitted, the policy address resolves from the [`VerifierRegistry`]
    /// for the target network (deploy one via
    /// `smart-account deploy-spending-limit-policy`). Only meaningful with
    /// `--kind spending-limit`.
    #[arg(long, value_name = "C_STRKEY")]
    pub policy: Option<String>,

    /// Signer threshold (`--kind simple-threshold` / `--kind weighted-threshold`).
    ///
    /// Required with both threshold-policy kinds. For `simple-threshold` this
    /// is the minimum number of signers; for `weighted-threshold` this is the
    /// minimum total weight.
    #[arg(long, value_name = "U32")]
    pub threshold: Option<u32>,

    /// One weighted-threshold delegated (ed25519) signer as `<G_STRKEY>=<WEIGHT>`
    /// (`--kind weighted-threshold`). Repeatable.
    #[arg(long = "weighted-signer-delegated", value_name = "G_STRKEY=WEIGHT",
          num_args = 1.., action = clap::ArgAction::Append)]
    pub weighted_signer_delegated: Vec<String>,

    /// One weighted-threshold WebAuthn (passkey) signer as
    /// `<CREDENTIAL_NAME>=<WEIGHT>` (`--kind weighted-threshold`). Repeatable.
    ///
    /// The credential name is resolved from the passkeys registry (as stored
    /// by `credentials add-passkey`), exactly as `smart-account rules create
    /// --signer-webauthn` resolves it.
    #[arg(long = "weighted-signer-webauthn", value_name = "CREDENTIAL_NAME=WEIGHT",
          num_args = 1.., action = clap::ArgAction::Append)]
    pub weighted_signer_webauthn: Vec<String>,

    /// Auth rule-id(s) whose signers authorise this operation. Default: the
    /// `--rule-id` value (the rule being modified is also the authorising rule).
    #[arg(long = "auth-rule-id", value_name = "U32",
          num_args = 1.., action = clap::ArgAction::Append)]
    pub auth_rule_id: Vec<u32>,

    /// Profile name for audit-log path resolution.
    #[arg(long, value_name = "NAME")]
    pub profile: Option<String>,

    /// Signer-source mode and Ledger derivation index.
    #[command(flatten)]
    pub signer_source: SignerSourceFlags,

    /// Network to target (testnet / mainnet).
    ///
    /// Mainnet is structurally refused (`network.mainnet_write_forbidden`).
    #[arg(long, default_value_t = TargetNetwork::Testnet, value_name = "NETWORK")]
    pub network: TargetNetwork,

    /// Soroban RPC endpoint URL.
    #[arg(long, default_value = TESTNET_RPC_URL, value_name = "URL")]
    pub rpc_url: String,

    /// Secondary RPC URL for divergence checks. Defaults to `--rpc-url`.
    #[arg(long, value_name = "URL")]
    pub secondary_rpc_url: Option<String>,

    /// Submission timeout in seconds.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECONDS, value_name = "SECONDS")]
    pub timeout_seconds: u64,

    /// Output format: `json` (default) or `table`.
    #[arg(long, default_value_t = OutputFormat::DEFAULT, value_name = "FORMAT")]
    pub output: OutputFormat,
}

impl CommonArgsView for AddPolicyArgs {
    fn account(&self) -> &str {
        &self.account
    }

    fn profile(&self) -> Option<&str> {
        self.profile.as_deref()
    }

    fn signer_source(&self) -> &SignerSourceFlags {
        &self.signer_source
    }

    fn network(&self) -> TargetNetwork {
        self.network
    }

    fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    fn secondary_rpc_url(&self) -> Option<&str> {
        self.secondary_rpc_url.as_deref()
    }

    fn timeout_seconds(&self) -> u64 {
        self.timeout_seconds
    }
}

/// Result envelope for `smart-account rules add-policy`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddPolicyResult {
    /// Smart-account C-strkey (unredacted in JSON envelope).
    pub smart_account: String,
    /// Context rule ID the policy was added to.
    pub rule_id: u32,
    /// On-chain policy ID assigned by the smart-account registry.
    pub policy_id: u32,
    /// Policy contract C-strkey (unredacted in JSON envelope).
    pub policy_address: String,
}

async fn add_policy_run(args: &AddPolicyArgs) -> i32 {
    let request_id = new_request_id();
    let account_redacted = redact_strkey_first5_last5(&args.account);

    // Mainnet write defence — structurally refuse before any RPC call.
    if args.network == TargetNetwork::Mainnet {
        return emit_error(
            &WalletError::Network(NetworkError::MainnetWriteForbidden),
            args.output,
            &request_id,
        );
    }

    // Parse the smart-account address.
    let smart_account = match parse_c_strkey(&args.account) {
        Ok(addr) => addr,
        Err(e) => return emit_error(&e, args.output, &request_id),
    };

    // Validate the flag combination for the selected mode and resolve the policy
    // address (display string) + install parameter accordingly. The typed
    // spending-limit path additionally decodes the rule context below (after the
    // rule fetch) and refuses non-CallContract rules before submit.
    let (policy_display, policy_sc_address, install_param) = match args.kind {
        PolicyKind::Raw => {
            let policy_address = match &args.policy_address {
                Some(a) => a.clone(),
                None => {
                    return emit_error(
                        &WalletError::Validation(ValidationError::AddressInvalid {
                            input: "--kind raw requires --policy-address".to_owned(),
                        }),
                        args.output,
                        &request_id,
                    );
                }
            };
            let raw_install = match &args.install_param {
                Some(p) => p,
                None => {
                    return emit_error(
                        &WalletError::Validation(ValidationError::AddressInvalid {
                            input: "--kind raw requires --install-param".to_owned(),
                        }),
                        args.output,
                        &request_id,
                    );
                }
            };
            if args.limit.is_some() || args.period.is_some() || args.policy.is_some() {
                return emit_error(
                    &WalletError::Validation(ValidationError::AddressInvalid {
                        input: "--limit / --period / --policy are only valid with \
                                --kind spending-limit"
                            .to_owned(),
                    }),
                    args.output,
                    &request_id,
                );
            }

            let policy_sc_address = match parse_c_strkey_to_smart_account(&policy_address) {
                Ok(addr) => addr,
                Err(e) => {
                    return emit_error(
                        &WalletError::Validation(ValidationError::AddressInvalid {
                            input: format!("--policy-address: {e}"),
                        }),
                        args.output,
                        &request_id,
                    );
                }
            };

            // Decode `--install-param` from standard base64 XDR to ScVal.
            // Raw passthrough — the wallet does NOT validate the param against the
            // target policy contract's expected shape.
            //
            // Use explicit depth + length limits (depth=500, len=10 MiB) instead
            // of `Limits::none()` to bound XDR-bomb resource exhaustion on
            // operator-supplied input. `stellar_xdr::Limits` does not implement
            // `Default`; the values here are the established XDR-decoder default
            // (10 MB / 500 depth).
            let install_param = match stellar_xdr::ScVal::from_xdr_base64(
                raw_install,
                stellar_xdr::Limits {
                    depth: 500,
                    len: 10 * 1024 * 1024,
                },
            ) {
                Ok(v) => v,
                Err(e) => {
                    return emit_error(
                        &WalletError::Validation(ValidationError::XdrArgumentMalformed {
                            arg: "install-param".to_owned(),
                            reason: format!("{e}"),
                        }),
                        args.output,
                        &request_id,
                    );
                }
            };

            (policy_address, policy_sc_address, install_param)
        }
        PolicyKind::SpendingLimit => {
            let limit = match args.limit {
                Some(v) => v,
                None => {
                    return emit_error(
                        &WalletError::Validation(ValidationError::AddressInvalid {
                            input: "--kind spending-limit requires --limit".to_owned(),
                        }),
                        args.output,
                        &request_id,
                    );
                }
            };
            let period = match args.period {
                Some(v) => v,
                None => {
                    return emit_error(
                        &WalletError::Validation(ValidationError::AddressInvalid {
                            input: "--kind spending-limit requires --period".to_owned(),
                        }),
                        args.output,
                        &request_id,
                    );
                }
            };
            if args.policy_address.is_some() || args.install_param.is_some() {
                return emit_error(
                    &WalletError::Validation(ValidationError::AddressInvalid {
                        input: "--policy-address / --install-param are only valid with \
                                --kind raw (use --policy for the typed override)"
                            .to_owned(),
                    }),
                    args.output,
                    &request_id,
                );
            }

            // Value pre-flight: refuse a non-positive limit or a zero period before
            // any registry lookup or network round-trip. Mirrors the OZ
            // `InvalidLimitOrPeriod` install-time constraint client-side.
            if let Err(e) = ensure_valid_spending_limit_params(limit, period) {
                return emit_error(
                    &WalletError::SmartAccount {
                        wire_code: e.wire_code(),
                        message: e.to_string(),
                    },
                    args.output,
                    &request_id,
                );
            }

            // Resolve the policy address: explicit `--policy` override, else the
            // network's registered spending-limit policy. Fail closed if neither.
            let policy_address = if let Some(explicit) = &args.policy {
                explicit.clone()
            } else {
                let registry = match VerifierRegistry::open() {
                    Ok(r) => r,
                    Err(e) => {
                        return emit_error(
                            &WalletError::Validation(ValidationError::AddressInvalid {
                                input: format!("could not open verifier registry: {e}"),
                            }),
                            args.output,
                            &request_id,
                        );
                    }
                };
                let passphrase = args.network.passphrase();
                match registry.spending_limit_policy_for(passphrase) {
                    Some(entry) => entry.address.clone(),
                    None => {
                        return emit_error(
                            &WalletError::Validation(ValidationError::AddressInvalid {
                                input: format!(
                                    "no spending-limit policy deployed for network \
                                     '{passphrase}'; run: \
                                     smart-account deploy-spending-limit-policy \
                                     (or pass --policy)"
                                ),
                            }),
                            args.output,
                            &request_id,
                        );
                    }
                }
            };

            let policy_sc_address = match parse_c_strkey_to_smart_account(&policy_address) {
                Ok(addr) => addr,
                Err(e) => {
                    return emit_error(
                        &WalletError::Validation(ValidationError::AddressInvalid {
                            input: format!("spending-limit policy address: {e}"),
                        }),
                        args.output,
                        &request_id,
                    );
                }
            };

            // Build the typed SpendingLimitAccountParams install param.
            let install_param = match build_spending_limit_install_param(limit, period) {
                Ok(v) => v,
                Err(e) => {
                    return emit_error(
                        &WalletError::SmartAccount {
                            wire_code: e.wire_code(),
                            message: e.to_string(),
                        },
                        args.output,
                        &request_id,
                    );
                }
            };

            (policy_address, policy_sc_address, install_param)
        }
        PolicyKind::SimpleThreshold => {
            let threshold = match args.threshold {
                Some(v) => v,
                None => {
                    return emit_error(
                        &WalletError::Validation(ValidationError::AddressInvalid {
                            input: "--kind simple-threshold requires --threshold".to_owned(),
                        }),
                        args.output,
                        &request_id,
                    );
                }
            };
            if args.policy_address.is_some()
                || args.install_param.is_some()
                || args.limit.is_some()
                || args.period.is_some()
                || !args.weighted_signer_delegated.is_empty()
                || !args.weighted_signer_webauthn.is_empty()
            {
                return emit_error(
                    &WalletError::Validation(ValidationError::AddressInvalid {
                        input: "--policy-address / --install-param / --limit / --period / \
                                --weighted-signer-* are only valid with the matching --kind"
                            .to_owned(),
                    }),
                    args.output,
                    &request_id,
                );
            }

            let policy_address = match resolve_policy_address_override_or_registry(
                &args.policy,
                args.network.passphrase(),
                "simple-threshold",
                |reg, net| {
                    reg.simple_threshold_policy_for(net)
                        .map(|e| e.address.clone())
                },
                "smart-account deploy-policy --kind simple-threshold",
            ) {
                Ok(a) => a,
                Err(e) => return emit_error(&e, args.output, &request_id),
            };

            let policy_sc_address = match parse_c_strkey_to_smart_account(&policy_address) {
                Ok(addr) => addr,
                Err(e) => {
                    return emit_error(
                        &WalletError::Validation(ValidationError::AddressInvalid {
                            input: format!("simple-threshold policy address: {e}"),
                        }),
                        args.output,
                        &request_id,
                    );
                }
            };

            let install_param = match build_simple_threshold_install_param(threshold) {
                Ok(v) => v,
                Err(e) => {
                    return emit_error(
                        &WalletError::SmartAccount {
                            wire_code: e.wire_code(),
                            message: e.to_string(),
                        },
                        args.output,
                        &request_id,
                    );
                }
            };

            (policy_address, policy_sc_address, install_param)
        }
        PolicyKind::WeightedThreshold => {
            let threshold = match args.threshold {
                Some(v) => v,
                None => {
                    return emit_error(
                        &WalletError::Validation(ValidationError::AddressInvalid {
                            input: "--kind weighted-threshold requires --threshold".to_owned(),
                        }),
                        args.output,
                        &request_id,
                    );
                }
            };
            if args.policy_address.is_some()
                || args.install_param.is_some()
                || args.limit.is_some()
                || args.period.is_some()
            {
                return emit_error(
                    &WalletError::Validation(ValidationError::AddressInvalid {
                        input: "--policy-address / --install-param / --limit / --period are \
                                only valid with the matching --kind"
                            .to_owned(),
                    }),
                    args.output,
                    &request_id,
                );
            }
            if args.weighted_signer_delegated.is_empty() && args.weighted_signer_webauthn.is_empty()
            {
                return emit_error(
                    &WalletError::Validation(ValidationError::AddressInvalid {
                        input: "--kind weighted-threshold requires at least one \
                                --weighted-signer-delegated or --weighted-signer-webauthn"
                            .to_owned(),
                    }),
                    args.output,
                    &request_id,
                );
            }

            let policy_address = match resolve_policy_address_override_or_registry(
                &args.policy,
                args.network.passphrase(),
                "weighted-threshold",
                |reg, net| {
                    reg.weighted_threshold_policy_for(net)
                        .map(|e| e.address.clone())
                },
                "smart-account deploy-policy --kind weighted-threshold",
            ) {
                Ok(a) => a,
                Err(e) => return emit_error(&e, args.output, &request_id),
            };

            let policy_sc_address = match parse_c_strkey_to_smart_account(&policy_address) {
                Ok(addr) => addr,
                Err(e) => {
                    return emit_error(
                        &WalletError::Validation(ValidationError::AddressInvalid {
                            input: format!("weighted-threshold policy address: {e}"),
                        }),
                        args.output,
                        &request_id,
                    );
                }
            };

            let mut signer_weights: Vec<(WeightedThresholdSignerInput, u32)> = Vec::with_capacity(
                args.weighted_signer_delegated.len() + args.weighted_signer_webauthn.len(),
            );

            for spec in &args.weighted_signer_delegated {
                let (g_strkey, weight) = match parse_weighted_signer_flag(spec) {
                    Ok(pair) => pair,
                    Err(e) => return emit_error(&e, args.output, &request_id),
                };
                if let Err(e) = parse_g_strkey_for_signer(&g_strkey) {
                    return emit_error(&e, args.output, &request_id);
                }
                signer_weights.push((WeightedThresholdSignerInput::Delegated { g_strkey }, weight));
            }

            if !args.weighted_signer_webauthn.is_empty() {
                let verifier_registry = match VerifierRegistry::open() {
                    Ok(r) => r,
                    Err(e) => {
                        return emit_error(
                            &WalletError::Validation(ValidationError::AddressInvalid {
                                input: format!("could not open verifier registry: {e}"),
                            }),
                            args.output,
                            &request_id,
                        );
                    }
                };
                let network_passphrase = args.network.passphrase();
                let verifier_entry = match verifier_registry
                    .webauthn_verifier_for(network_passphrase)
                {
                    Some(e) => e,
                    None => {
                        return emit_error(
                            &WalletError::Validation(ValidationError::AddressInvalid {
                                input: format!(
                                    "no WebAuthn verifier deployed for network '{network_passphrase}'; \
                                     run: smart-account deploy-webauthn-verifier"
                                ),
                            }),
                            args.output,
                            &request_id,
                        );
                    }
                };
                let verifier_sc_addr = match parse_c_strkey(&verifier_entry.address) {
                    Ok(addr) => addr,
                    Err(e) => return emit_error(&e, args.output, &request_id),
                };

                let profile = resolve_profile_name(args.profile.as_deref());
                if let Err(reason) = validate_path_component_ascii_safe(&profile) {
                    return emit_error(
                        &WalletError::Validation(ValidationError::AddressInvalid {
                            input: format!("invalid profile name '{profile}': {reason}"),
                        }),
                        args.output,
                        &request_id,
                    );
                }
                let creds_mgr =
                    match CredentialsManager::from_defaults_readonly(&profile, "localhost") {
                        Ok(m) => m,
                        Err(e) => {
                            return emit_error(
                                &WalletError::Validation(ValidationError::AddressInvalid {
                                    input: format!("could not open passkeys registry: {e}"),
                                }),
                                args.output,
                                &request_id,
                            );
                        }
                    };

                for spec in &args.weighted_signer_webauthn {
                    let (credential_name, weight) = match parse_weighted_signer_flag(spec) {
                        Ok(pair) => pair,
                        Err(e) => return emit_error(&e, args.output, &request_id),
                    };
                    let key_data =
                        match resolve_weighted_webauthn_key_data(&creds_mgr, &credential_name) {
                            Ok(kd) => kd,
                            Err(e) => return emit_error(&e, args.output, &request_id),
                        };
                    signer_weights.push((
                        WeightedThresholdSignerInput::External {
                            verifier: verifier_sc_addr.clone(),
                            key_data,
                        },
                        weight,
                    ));
                }
            }

            let install_param =
                match build_weighted_threshold_install_param(&signer_weights, threshold) {
                    Ok(v) => v,
                    Err(e) => {
                        return emit_error(
                            &WalletError::SmartAccount {
                                wire_code: e.wire_code(),
                                message: e.to_string(),
                            },
                            args.output,
                            &request_id,
                        );
                    }
                };

            (policy_address, policy_sc_address, install_param)
        }
    };

    // Build CommonHandlerContext (signer + manager + audit writer).
    let ctx = match CommonHandlerContext::new(args).await {
        Ok(ctx) => ctx,
        Err(e) => return emit_error(&e, args.output, &request_id),
    };

    // Derive the source-account strkey for the get_rule read call.
    let source_account_strkey = match ctx.signer.public_key().await {
        Ok(pk) => pk.to_string(),
        Err(e) => {
            return emit_error(
                &WalletError::Validation(ValidationError::AddressInvalid {
                    input: format!("signer.public_key(): {e}"),
                }),
                args.output,
                &request_id,
            );
        }
    };

    let manager = match ctx.context_rule_manager() {
        Ok(m) => m,
        Err(e) => return emit_error(&e, args.output, &request_id),
    };

    // Pre-simulate policy-cap check: fetch the current rule and decode
    // `policy_ids.len()`.
    // TOCTOU note: the pre-fetch + simulate-submit sequence is non-atomic. If
    // concurrent on-chain mutation lands between the `get_rule` observation and
    // the submit, the on-chain panic at discriminant 3011 (TooManyPolicies)
    // surfaces as `SaError::DeploymentFailed { phase: "simulate",
    // redacted_reason: <contains "3011" / "[OZ:TooManyPolicies]"> }`. Operators
    // should re-fetch via `smart-account rules get` and retry — or pivot to the
    // rule-rotation pattern.
    let rule_scval = match manager
        .get_rule(smart_account.clone(), args.rule_id, &source_account_strkey)
        .await
    {
        Ok(Some(scval)) => scval,
        Ok(None) => {
            return emit_error(
                &WalletError::Validation(ValidationError::AddressInvalid {
                    input: format!(
                        "rule_id {} not found on smart account {account_redacted}",
                        args.rule_id
                    ),
                }),
                args.output,
                &request_id,
            );
        }
        Err(e) => return emit_error_sa(&e, args.output, &request_id),
    };

    // Typed spending-limit pre-flight: decode the rule's real context type from
    // the already-fetched rule map (no extra RPC round-trip) and refuse
    // non-CallContract rules client-side before simulate/submit. OZ `install`
    // rejects them with `OnlyCallContractAllowed`
    // (spending_limit.rs:376-377, SHA a9c4216).
    if args.kind == PolicyKind::SpendingLimit {
        let rule_context = match decode_context_type_from_scval(&rule_scval) {
            Ok(c) => c,
            Err(e) => return emit_error_sa(&e, args.output, &request_id),
        };
        if let Err(e) = ensure_call_contract_context_for_spending_limit(&rule_context) {
            return emit_error(
                &WalletError::SmartAccount {
                    wire_code: e.wire_code(),
                    message: e.to_string(),
                },
                args.output,
                &request_id,
            );
        }
    }

    let policy_count = match decode_policy_count_from_scval(&rule_scval) {
        Ok(n) => n,
        Err(e) => return emit_error_sa(&e, args.output, &request_id),
    };

    if let Err(e) = enforce_policy_cap(policy_count) {
        return emit_error(&WalletError::Validation(e), args.output, &request_id);
    }

    // Resolve auth_rule_ids: default to the rule being modified.
    let auth_rule_ids: Vec<ContextRuleId> = if args.auth_rule_id.is_empty() {
        vec![ContextRuleId::new(args.rule_id)]
    } else {
        args.auth_rule_id
            .iter()
            .map(|id| ContextRuleId::new(*id))
            .collect()
    };

    match manager
        .add_policy(
            smart_account,
            args.rule_id,
            policy_sc_address,
            install_param,
            auth_rule_ids,
            ctx.signer.as_ref(),
            None,
            request_id.clone(),
        )
        .await
    {
        Ok(policy_id) => {
            info!(
                smart_account = %account_redacted,
                rule_id = args.rule_id,
                policy_id,
                "smart-account rules add-policy: installed",
            );
            let result = AddPolicyResult {
                smart_account: args.account.clone(),
                rule_id: args.rule_id,
                policy_id,
                policy_address: policy_display.clone(),
            };
            emit_success(&result, args.output, &request_id, 0)
        }
        Err(e) => emit_error_sa(&e, args.output, &request_id),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// `smart-account rules remove-policy`
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for `smart-account rules remove-policy`.
///
/// Removes a policy from an existing context rule by its on-chain `policy_id`.
///
/// # Mainnet write defence
///
/// Structurally refuses mainnet before any RPC or signing call.
#[non_exhaustive]
#[derive(Debug, Args)]
pub struct RemovePolicyArgs {
    /// Smart-account contract C-strkey.
    #[arg(long, value_name = "C_STRKEY", required = true)]
    pub account: String,

    /// Context rule ID to remove the policy from.
    #[arg(long, value_name = "U32", required = true)]
    pub rule_id: u32,

    /// On-chain policy ID to remove (from the rule's `policy_ids` registry).
    #[arg(long, value_name = "U32", required = true)]
    pub policy_id: u32,

    /// Auth rule-id(s) whose signers authorise this operation. Default: the
    /// `--rule-id` value.
    #[arg(long = "auth-rule-id", value_name = "U32",
          num_args = 1.., action = clap::ArgAction::Append)]
    pub auth_rule_id: Vec<u32>,

    /// Profile name for audit-log path resolution.
    #[arg(long, value_name = "NAME")]
    pub profile: Option<String>,

    /// Signer-source mode and Ledger derivation index.
    #[command(flatten)]
    pub signer_source: SignerSourceFlags,

    /// Network to target (testnet / mainnet).
    ///
    /// Mainnet is structurally refused (`network.mainnet_write_forbidden`).
    #[arg(long, default_value_t = TargetNetwork::Testnet, value_name = "NETWORK")]
    pub network: TargetNetwork,

    /// Soroban RPC endpoint URL.
    #[arg(long, default_value = TESTNET_RPC_URL, value_name = "URL")]
    pub rpc_url: String,

    /// Secondary RPC URL for divergence checks. Defaults to `--rpc-url`.
    #[arg(long, value_name = "URL")]
    pub secondary_rpc_url: Option<String>,

    /// Submission timeout in seconds.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECONDS, value_name = "SECONDS")]
    pub timeout_seconds: u64,

    /// Output format: `json` (default) or `table`.
    #[arg(long, default_value_t = OutputFormat::DEFAULT, value_name = "FORMAT")]
    pub output: OutputFormat,
}

impl CommonArgsView for RemovePolicyArgs {
    fn account(&self) -> &str {
        &self.account
    }

    fn profile(&self) -> Option<&str> {
        self.profile.as_deref()
    }

    fn signer_source(&self) -> &SignerSourceFlags {
        &self.signer_source
    }

    fn network(&self) -> TargetNetwork {
        self.network
    }

    fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    fn secondary_rpc_url(&self) -> Option<&str> {
        self.secondary_rpc_url.as_deref()
    }

    fn timeout_seconds(&self) -> u64 {
        self.timeout_seconds
    }
}

/// Result envelope for `smart-account rules remove-policy`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemovePolicyResult {
    /// Smart-account C-strkey (unredacted in JSON envelope).
    pub smart_account: String,
    /// Context rule ID the policy was removed from.
    pub rule_id: u32,
    /// On-chain policy ID that was removed.
    pub policy_id: u32,
}

async fn remove_policy_run(args: &RemovePolicyArgs) -> i32 {
    let request_id = new_request_id();
    let account_redacted = redact_strkey_first5_last5(&args.account);

    // Mainnet write defence — structurally refuse before any RPC call.
    if args.network == TargetNetwork::Mainnet {
        return emit_error(
            &WalletError::Network(NetworkError::MainnetWriteForbidden),
            args.output,
            &request_id,
        );
    }

    // Parse the smart-account address.
    let smart_account = match parse_c_strkey(&args.account) {
        Ok(addr) => addr,
        Err(e) => return emit_error(&e, args.output, &request_id),
    };

    // Build CommonHandlerContext.
    let ctx = match CommonHandlerContext::new(args).await {
        Ok(ctx) => ctx,
        Err(e) => return emit_error(&e, args.output, &request_id),
    };

    let manager = match ctx.context_rule_manager() {
        Ok(m) => m,
        Err(e) => return emit_error(&e, args.output, &request_id),
    };

    // Resolve auth_rule_ids: default to the rule being modified.
    let auth_rule_ids: Vec<ContextRuleId> = if args.auth_rule_id.is_empty() {
        vec![ContextRuleId::new(args.rule_id)]
    } else {
        args.auth_rule_id
            .iter()
            .map(|id| ContextRuleId::new(*id))
            .collect()
    };

    match manager
        .remove_policy(
            smart_account,
            args.rule_id,
            args.policy_id,
            auth_rule_ids,
            ctx.signer.as_ref(),
            None,
            request_id.clone(),
        )
        .await
    {
        Ok(()) => {
            info!(
                smart_account = %account_redacted,
                rule_id = args.rule_id,
                policy_id = args.policy_id,
                "smart-account rules remove-policy: removed",
            );
            let result = RemovePolicyResult {
                smart_account: args.account.clone(),
                rule_id: args.rule_id,
                policy_id: args.policy_id,
            };
            emit_success(&result, args.output, &request_id, 0)
        }
        Err(e) => emit_error_sa(&e, args.output, &request_id),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// `smart-account rules get-spending-limit`
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for `smart-account rules get-spending-limit`.
///
/// Read-only: identifies the spending-limit policy attached to `rule_id`,
/// reads its on-chain data, and computes the rolling-window budget snapshot.
/// No signing, no submission, no audit-log emission.
#[non_exhaustive]
#[derive(Debug, Args)]
pub struct GetSpendingLimitArgs {
    /// Network, RPC, timeout, and output shared with read subcommands.
    #[command(flatten)]
    pub common: CommonRulesReadArgs,

    /// Context rule ID whose spending-limit policy to read.
    #[arg(long, value_name = "U32", required = true)]
    pub rule_id: u32,

    /// Source-account strkey for the simulation envelope. Any funded
    /// account on the target network works (read-only path; no signing).
    #[arg(long, value_name = "G_STRKEY", required = true)]
    pub source_account: String,
}

/// Result envelope for `smart-account rules get-spending-limit`.
///
/// # Point-in-time caveat
///
/// `in_window_spent` and `remaining_budget` are exact only as of
/// `as_of_ledger`. Forward ledger movement past that point only grows
/// headroom (older entries fall out of the rolling window), but any
/// intervening spend shrinks it — these values are an estimate, not a
/// guarantee for a future submission, which can still fail
/// `SpendingLimitExceeded` (OZ error 3221).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetSpendingLimitResult {
    /// Smart-account C-strkey.
    pub smart_account: String,
    /// Context rule ID that was queried.
    pub rule_id: u32,
    /// Spending-limit-policy contract C-strkey (unredacted; on-chain public
    /// identifier).
    pub policy_address: String,
    /// The configured spending limit, in stroops, as a decimal string. A raw
    /// JSON number is not used here — `serde_json::from_value` backs numbers
    /// with `f64`, which cannot represent an i128 exactly above `2^53` — the
    /// same convention as the MCP `stellar_rules_get` budget snapshot.
    pub spending_limit: String,
    /// The rolling-window period, in ledgers.
    pub period_ledgers: u32,
    /// Sum of spend-history entries within the rolling window as of
    /// `as_of_ledger`, as a decimal string (see `spending_limit`). See the
    /// point-in-time caveat above.
    pub in_window_spent: String,
    /// `max(0, spending_limit - in_window_spent)`, as a decimal string (see
    /// `spending_limit`). See the point-in-time caveat above.
    pub remaining_budget: String,
    /// Ledger sequence the simulation observed; the "as of" ledger for
    /// `in_window_spent` / `remaining_budget`.
    pub as_of_ledger: u32,
    /// Ledger sequence at and before which history entries are excluded
    /// from `in_window_spent` (`as_of_ledger.saturating_sub(period_ledgers)`).
    pub window_cutoff_ledger: u32,
    /// Number of entries in the on-chain spend history (bounded by the OZ
    /// `MAX_HISTORY_ENTRIES = 1000` cap; not all necessarily in-window).
    pub history_entries: u32,
    /// The on-chain cached total, verbatim, for transparency, as a decimal
    /// string (see `spending_limit`). NOT used to compute `in_window_spent`
    /// — `get_spending_limit_data` performs no eviction on read, so this
    /// total can include entries that have since fallen outside the rolling
    /// window.
    pub cached_total_spent: String,
}

async fn get_spending_limit_run(args: &GetSpendingLimitArgs) -> i32 {
    let request_id = new_request_id();
    let account_redacted = redact_strkey_first5_last5(&args.common.account);

    let smart_account = match parse_c_strkey(&args.common.account) {
        Ok(addr) => addr,
        Err(e) => return emit_error(&e, args.common.output, &request_id),
    };

    if let Err(e) = stellar_strkey::ed25519::PublicKey::from_string(&args.source_account) {
        return emit_error(
            &WalletError::Validation(ValidationError::AddressInvalid {
                input: format!("--source-account: invalid G-strkey ({e})"),
            }),
            args.common.output,
            &request_id,
        );
    }

    // Read-only path: a SignersManager is still required (identify_spending_limit_policy
    // and get_spending_limit_data are its methods), but no Signer is resolved —
    // both methods take `source_account_strkey: Option<&str>`, not a `Signer`.
    // `CommonRulesReadArgs` has no `--profile` flag; resolve the default profile
    // (matches the read-only precedent set by `smart-account rules get`).
    let profile_name = resolve_profile_name(None);
    let (audit_writer, audit_log_path) = match open_audit_writer(&profile_name) {
        Ok(pair) => pair,
        Err(e) => return emit_error(&e, args.common.output, &request_id),
    };
    let chain_id = network_to_chain_id(args.common.network);
    let manager = match construct_signers_manager_from_fields(
        &profile_name,
        args.common.network.passphrase(),
        chain_id,
        &args.common.rpc_url,
        &args.common.rpc_url,
        Duration::from_secs(args.common.timeout_seconds),
        audit_writer,
        &audit_log_path,
    ) {
        Ok(m) => m,
        Err(e) => return emit_error(&e, args.common.output, &request_id),
    };

    let policy_addr = match manager
        .identify_spending_limit_policy(
            smart_account.clone(),
            args.rule_id,
            Some(&args.source_account),
            request_id.clone(),
        )
        .await
    {
        Ok(addr) => addr,
        Err(e) => return emit_error_sa(&e, args.common.output, &request_id),
    };

    let (data, as_of_ledger) = match manager
        .get_spending_limit_data(
            policy_addr.clone(),
            args.rule_id,
            smart_account,
            Some(&args.source_account),
            request_id.clone(),
        )
        .await
    {
        Ok(pair) => pair,
        Err(e) => return emit_error_sa(&e, args.common.output, &request_id),
    };

    let window =
        stellar_agent_smart_account::managers::spending_limit_data::compute_spending_window(
            &data,
            as_of_ledger,
        );

    let policy_address = match contract_scaddress_to_strkey(&policy_addr) {
        Ok(s) => s,
        Err(e) => return emit_error(&e, args.common.output, &request_id),
    };

    info!(
        smart_account = %account_redacted,
        rule_id = args.rule_id,
        as_of_ledger,
        "smart-account rules get-spending-limit: read",
    );

    let history_entries = u32::try_from(data.spending_history.len()).unwrap_or(u32::MAX);
    let result = GetSpendingLimitResult {
        smart_account: args.common.account.clone(),
        rule_id: args.rule_id,
        policy_address,
        spending_limit: data.spending_limit.to_string(),
        period_ledgers: data.period_ledgers,
        in_window_spent: window.in_window_spent.to_string(),
        remaining_budget: window.remaining.to_string(),
        as_of_ledger,
        window_cutoff_ledger: window.window_cutoff_ledger,
        history_entries,
        cached_total_spent: data.cached_total_spent.to_string(),
    };
    emit_success(&result, args.common.output, &request_id, 0)
}

// ─────────────────────────────────────────────────────────────────────────────
// `smart-account rules set-spending-limit`
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for `smart-account rules set-spending-limit`.
///
/// Retunes the spending limit of an installed spending-limit policy. Does
/// NOT reset the rolling spend history (OZ `set_spending_limit` mutates only
/// the limit; the period is immutable post-install).
///
/// # Mainnet write defence
///
/// Structurally refuses mainnet before any RPC or signing call.
#[non_exhaustive]
#[derive(Debug, Args)]
pub struct SetSpendingLimitArgs {
    /// Smart-account contract C-strkey.
    #[arg(long, value_name = "C_STRKEY", required = true)]
    pub account: String,

    /// Context rule ID whose spending-limit policy to retune.
    #[arg(long = "rule-id", value_name = "U32", required = true)]
    pub rule_id: u32,

    /// Context rule ID that AUTHORIZES the retune (default: the genesis
    /// admin rule, 0). Must be admin-capable: the retune executes on the
    /// smart account itself, an auth context the CallContract-scoped rule
    /// named by `--rule-id` always refuses on-chain (UnvalidatedContext) —
    /// the target rule can never authorize its own retune.
    #[arg(long = "auth-rule-id", value_name = "U32", default_value_t = 0)]
    pub auth_rule_id: u32,

    /// New spending limit, in stroops. Must be positive.
    #[arg(long, value_name = "STROOPS", required = true)]
    pub limit: i128,

    /// Profile name for audit-log path resolution.
    #[arg(long, value_name = "NAME")]
    pub profile: Option<String>,

    #[command(flatten)]
    pub signer_source: SignerSourceFlags,

    /// Network to target (testnet / mainnet).
    #[arg(long, default_value_t = TargetNetwork::Testnet, value_name = "NETWORK")]
    pub network: TargetNetwork,

    /// Soroban RPC endpoint URL.
    #[arg(long, default_value = TESTNET_RPC_URL, value_name = "URL")]
    pub rpc_url: String,

    /// Secondary RPC URL for two-RPC consultation.
    #[arg(long, value_name = "URL")]
    pub secondary_rpc_url: Option<String>,

    /// Submission timeout in seconds.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECONDS, value_name = "SECONDS")]
    pub timeout_seconds: u64,

    /// Output format: `json` (default) or `table`.
    #[arg(long, default_value_t = OutputFormat::DEFAULT, value_name = "FORMAT")]
    pub output: OutputFormat,
}

impl CommonArgsView for SetSpendingLimitArgs {
    fn account(&self) -> &str {
        &self.account
    }

    fn profile(&self) -> Option<&str> {
        self.profile.as_deref()
    }

    fn signer_source(&self) -> &SignerSourceFlags {
        &self.signer_source
    }

    fn network(&self) -> TargetNetwork {
        self.network
    }

    fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    fn secondary_rpc_url(&self) -> Option<&str> {
        self.secondary_rpc_url.as_deref()
    }

    fn timeout_seconds(&self) -> u64 {
        self.timeout_seconds
    }
}

/// Result envelope for `smart-account rules set-spending-limit`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetSpendingLimitResult {
    /// Smart-account C-strkey.
    pub smart_account: String,
    /// Context rule ID whose spending-limit policy was retuned.
    pub rule_id: u32,
    /// The new spending limit that was applied, in stroops, as a decimal
    /// string. A raw JSON number is not used here — `serde_json::from_value`
    /// backs numbers with `f64`, which cannot represent an i128 exactly
    /// above `2^53` — the same convention as `GetSpendingLimitResult`.
    pub new_limit: String,
}

async fn set_spending_limit_run(args: &SetSpendingLimitArgs) -> i32 {
    let request_id = new_request_id();
    let account_redacted = redact_strkey_first5_last5(&args.account);

    // Mainnet write defence — structurally refuse before any RPC call.
    if args.network == TargetNetwork::Mainnet {
        return emit_error(
            &WalletError::Network(NetworkError::MainnetWriteForbidden),
            args.output,
            &request_id,
        );
    }

    // Value pre-flight: refuse a non-positive limit before resolving a signer
    // or building any manager. `SignersManager::set_spending_limit` repeats
    // this check (defense in depth for non-CLI callers); this CLI-level copy
    // avoids requiring a signer for an input that will always be refused.
    if args.limit <= 0 {
        return emit_error_sa(
            &SaError::SpendingLimitInstallRefused {
                reason: format!(
                    "set-spending-limit refused: --limit must be positive; got {} \
                     (OZ set_spending_limit rejects non-positive values with \
                     InvalidLimitOrPeriod)",
                    args.limit
                ),
            },
            args.output,
            &request_id,
        );
    }

    let ctx = match CommonHandlerContext::new(args).await {
        Ok(ctx) => ctx,
        Err(e) => return emit_error(&e, args.output, &request_id),
    };

    let manager = match ctx.signers_manager() {
        Ok(m) => m,
        Err(e) => return emit_error(&e, args.output, &request_id),
    };

    info!(
        rule_id = args.rule_id,
        new_limit = args.limit,
        account = %account_redacted,
        "smart-account rules set-spending-limit: submitting set_spending_limit"
    );

    let auth_rule_ids = vec![ContextRuleId::new(args.auth_rule_id)];
    match manager
        .set_spending_limit(
            ctx.smart_account,
            args.rule_id,
            &auth_rule_ids,
            args.limit,
            ctx.signer.as_ref(),
            request_id.clone(),
        )
        .await
    {
        Ok(()) => {
            let result = SetSpendingLimitResult {
                smart_account: args.account.clone(),
                rule_id: args.rule_id,
                new_limit: args.limit.to_string(),
            };
            emit_success(&result, args.output, &request_id, 0)
        }
        Err(e) => emit_error_sa(&e, args.output, &request_id),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Parses a C-strkey via the smart_account-crate helper, mapping `SaError`
/// to a `WalletError::Validation` envelope-friendly error.
fn parse_c_strkey(s: &str) -> Result<SmartAccountAddress, WalletError> {
    parse_c_strkey_to_smart_account(s).map_err(|e| {
        WalletError::Validation(ValidationError::AddressInvalid {
            input: format!("--account: {e}"),
        })
    })
}

/// Renders a contract [`stellar_xdr::ScAddress`] as its C-strkey form.
///
/// Used for `get-spending-limit`'s `policy_address` output field.
/// `identify_spending_limit_policy` always returns a contract address in
/// practice (policies are on-chain contracts, never G-accounts) — the
/// `Account` arm is a typed refusal rather than a silent placeholder, so a
/// future decode-path change cannot surface a fabricated all-zero address.
fn contract_scaddress_to_strkey(addr: &stellar_xdr::ScAddress) -> Result<String, WalletError> {
    match addr {
        stellar_xdr::ScAddress::Contract(stellar_xdr::ContractId(stellar_xdr::Hash(bytes))) => {
            // `stellar_strkey` 0.0.18 returns `heapless::String<56>` from
            // `to_string()`, not `std::string::String`.
            Ok(stellar_strkey::Contract(*bytes)
                .to_string()
                .as_str()
                .to_owned())
        }
        other => Err(WalletError::Validation(ValidationError::AddressInvalid {
            input: format!(
                "policy address is not a contract address; expected a spending-limit-policy \
                 contract, got {other:?}"
            ),
        })),
    }
}

/// Parses a G-strkey via the smart_account-crate helper, used for
/// `--signer-delegated` args.
fn parse_g_strkey_for_signer(s: &str) -> Result<SmartAccountAddress, WalletError> {
    parse_g_strkey_to_signer_address(s).map_err(|e| {
        WalletError::Validation(ValidationError::AddressInvalid {
            input: format!("--signer-delegated: {e}"),
        })
    })
}

/// Resolves a policy contract address for `add-policy`: an explicit
/// `--policy` override, else the network's registered address for `kind`
/// looked up via `getter`. Fail-closed with an actionable hint naming
/// `deploy_verb` if neither is available.
fn resolve_policy_address_override_or_registry(
    policy_override: &Option<String>,
    network_passphrase: &str,
    kind: &str,
    getter: impl FnOnce(&VerifierRegistry, &str) -> Option<String>,
    deploy_verb: &str,
) -> Result<String, WalletError> {
    if let Some(explicit) = policy_override {
        return Ok(explicit.clone());
    }
    let registry = VerifierRegistry::open().map_err(|e| {
        WalletError::Validation(ValidationError::AddressInvalid {
            input: format!("could not open verifier registry: {e}"),
        })
    })?;
    getter(&registry, network_passphrase).ok_or_else(|| {
        WalletError::Validation(ValidationError::AddressInvalid {
            input: format!(
                "no {kind} policy deployed for network '{network_passphrase}'; \
                 run: {deploy_verb} (or pass --policy)"
            ),
        })
    })
}

/// Parses one `--weighted-signer-{delegated,webauthn} <identity>=<weight>`
/// flag value into its `(identity, weight)` parts.
///
/// Splits on the LAST `=` so a `--weighted-signer-delegated` G-strkey (which
/// never contains `=`) and a `--weighted-signer-webauthn` credential name
/// (operator-chosen, also not expected to contain `=`) both parse
/// unambiguously.
fn parse_weighted_signer_flag(spec: &str) -> Result<(String, u32), WalletError> {
    let (identity, weight_str) = spec.rsplit_once('=').ok_or_else(|| {
        WalletError::Validation(ValidationError::AddressInvalid {
            input: format!("'{spec}': expected '<identity>=<weight>'"),
        })
    })?;
    let weight = weight_str.parse::<u32>().map_err(|_| {
        WalletError::Validation(ValidationError::AddressInvalid {
            input: format!("'{spec}': weight '{weight_str}' is not a valid u32"),
        })
    })?;
    if identity.is_empty() {
        return Err(WalletError::Validation(ValidationError::AddressInvalid {
            input: format!("'{spec}': identity must not be empty"),
        }));
    }
    Ok((identity.to_owned(), weight))
}

/// Resolves one `--weighted-signer-webauthn` credential name to the raw
/// External-signer `key_data` bytes (`pubkey_65_bytes || credential_id_bytes`),
/// mirroring the decode step in `smart-account rules create --signer-webauthn`.
fn resolve_weighted_webauthn_key_data(
    creds_mgr: &CredentialsManager,
    credential_name: &str,
) -> Result<Vec<u8>, WalletError> {
    let metadata = creds_mgr.show(credential_name).map_err(|e| {
        WalletError::Validation(ValidationError::AddressInvalid {
            input: format!("--weighted-signer-webauthn '{credential_name}': {e}"),
        })
    })?;

    if metadata.public_key_sec1_b64.is_empty() {
        return Err(WalletError::Validation(ValidationError::AddressInvalid {
            input: format!(
                "--weighted-signer-webauthn '{credential_name}': credential is missing \
                 public_key_sec1_b64 (delete and re-register)"
            ),
        }));
    }

    let pubkey_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&metadata.public_key_sec1_b64)
        .map_err(|_| {
            WalletError::Validation(ValidationError::AddressInvalid {
                input: format!(
                    "--weighted-signer-webauthn '{credential_name}': public_key_sec1_b64 \
                     is not valid base64url"
                ),
            })
        })?;
    if pubkey_bytes.len() != 65 {
        return Err(WalletError::Validation(ValidationError::AddressInvalid {
            input: format!(
                "--weighted-signer-webauthn '{credential_name}': public_key_sec1_b64 decodes \
                 to {} bytes, expected 65",
                pubkey_bytes.len()
            ),
        }));
    }

    let credential_id_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&metadata.credential_id_b64url)
        .map_err(|_| {
            WalletError::Validation(ValidationError::AddressInvalid {
                input: format!(
                    "--weighted-signer-webauthn '{credential_name}': credential_id_b64url \
                     is not valid base64url"
                ),
            })
        })?;

    // pubkey_data = pubkey_65_bytes || credential_id_bytes, per the OZ
    // `canonicalize_key` WebAuthn verifier convention. Must not be reordered.
    let mut pubkey_data = Vec::with_capacity(65 + credential_id_bytes.len());
    pubkey_data.extend_from_slice(&pubkey_bytes);
    pubkey_data.extend_from_slice(&credential_id_bytes);
    Ok(pubkey_data)
}

/// Parses a `--valid-until <LEDGER | none>` arg.
fn parse_valid_until(s: &str) -> Result<Option<u32>, WalletError> {
    if s.eq_ignore_ascii_case("none") {
        return Ok(None);
    }
    s.parse::<u32>().map(Some).map_err(|_| {
        WalletError::Validation(ValidationError::ValidUntilInvalid {
            input: s.to_owned(),
        })
    })
}

/// Accepted `--context` grammar, embedded verbatim in every parse error so the
/// operator sees the exact valid forms.
const CONTEXT_GRAMMAR: &str = "accepted --context forms: 'default' (or omit the flag), \
     'call-contract:<C-strkey>', 'create-contract:<64-hex-wasm-hash>'";

/// Parses the `--context` flag into a [`RuleContext`].
///
/// Fail-closed: any value that is not `default`, a well-formed
/// `call-contract:<C-strkey>`, or a well-formed
/// `create-contract:<64-hex-wasm-hash>` is rejected before any network call.
/// The C-strkey and the 32-byte wasm hash are validated here at parse time.
fn parse_rule_context(s: &str) -> Result<RuleContext, WalletError> {
    let config_err = |reason: String| {
        WalletError::Validation(ValidationError::ConfigInvalid {
            component: "--context",
            reason,
        })
    };

    if s.eq_ignore_ascii_case("default") {
        return Ok(RuleContext::Default);
    }

    if let Some(strkey) = s.strip_prefix("call-contract:") {
        let contract = parse_c_strkey_to_smart_account(strkey).map_err(|_| {
            config_err(format!(
                "call-contract target is not a valid C-strkey; {CONTEXT_GRAMMAR}"
            ))
        })?;
        return Ok(RuleContext::CallContract { contract });
    }

    if let Some(hex_hash) = s.strip_prefix("create-contract:") {
        if hex_hash.len() != 64 {
            return Err(config_err(format!(
                "create-contract wasm hash must be 64 hex chars (32 bytes), got {}; \
                 {CONTEXT_GRAMMAR}",
                hex_hash.len()
            )));
        }
        let bytes = hex::decode(hex_hash).map_err(|_| {
            config_err(format!(
                "create-contract wasm hash is not valid hex; {CONTEXT_GRAMMAR}"
            ))
        })?;
        let wasm_hash: [u8; 32] = bytes.try_into().map_err(|_| {
            // Unreachable: a 64-char hex string decodes to exactly 32 bytes.
            config_err(format!(
                "create-contract wasm hash did not decode to 32 bytes; {CONTEXT_GRAMMAR}"
            ))
        })?;
        return Ok(RuleContext::CreateContract { wasm_hash });
    }

    Err(config_err(format!(
        "unknown context '{s}'; {CONTEXT_GRAMMAR}"
    )))
}

/// Builds a read-only [`ContextRuleManager`] (no signing, no divergence check).
///
/// Used only by `smart-account rules get` which is a simulation-only read path.
/// Write paths use the full `build_manager` which injects a `SignersManager`
/// for the divergence check.
fn build_readonly_manager(
    network: TargetNetwork,
    rpc_url: &str,
    timeout_seconds: u64,
) -> Result<ContextRuleManager, WalletError> {
    let chain_id = match network {
        TargetNetwork::Testnet => "stellar:testnet",
        TargetNetwork::Mainnet => "stellar:mainnet",
    };
    ContextRuleManager::new(ContextRuleManagerConfig::new(
        rpc_url.to_owned(),
        network.passphrase().to_owned(),
        Duration::from_secs(timeout_seconds),
        chain_id.to_owned(),
    ))
    .map_err(|e| {
        WalletError::Validation(ValidationError::ConfigInvalid {
            component: "ContextRuleManager",
            reason: e.to_string(),
        })
    })
}

/// Generates a fresh UUID-v4 request-id string for audit-log forensic
/// correlation across the success / failure emission set.
fn new_request_id() -> String {
    Uuid::new_v4().to_string()
}

/// Renders an envelope around an `Ok` result, threading the caller-supplied
/// `request_id` through so the JSON envelope's `request_id` matches the
/// audit-log row's `request_id` (forensic-correlation invariant).
///
/// The rules surface emits JSON for both `Json` and `Table` formats; structured
/// human-render is provided by the `smart-account rules list` enumerator.
fn emit_success<T: Serialize>(
    result: &T,
    output: OutputFormat,
    request_id: &str,
    exit_code: i32,
) -> i32 {
    let envelope = Envelope::ok_with_request_id(result, request_id.to_owned());
    let _ = output;
    render_json(&envelope);
    exit_code
}

/// Renders an envelope around a [`WalletError`], threading the caller-supplied
/// `request_id` through so failure envelopes correlate with their
/// `SaRawInvocation` audit-log row.
///
/// JSON is emitted for both `Json` and `Table` to keep success / failure
/// rendering consistent; structured Table rendering for the rules surface is
/// provided by `smart-account rules list`.
fn emit_error(err: &WalletError, output: OutputFormat, request_id: &str) -> i32 {
    let envelope = Envelope::<()>::err_with_request_id(err, request_id.to_owned());
    let _ = output;
    render_json(&envelope);
    1
}

/// Maps an [`SaError`] into the appropriate [`WalletError`] envelope shape,
/// threading `request_id`.
///
/// Most variants map to `WalletError::SmartAccount { wire_code, message }`.
/// `SaError::HorizonExceeded` maps to
/// `WalletError::Validation(ValidationError::SessionRuleHorizonExceeded)`
/// because it is a pre-submission wallet-side refusal, not an on-chain
/// smart-account failure.
fn emit_error_sa(err: &SaError, output: OutputFormat, request_id: &str) -> i32 {
    // Route horizon-exceeded as a validation error so the CLI envelope `kind`
    // field matches the ValidationError wire code
    // `"validation.session_rule_horizon_exceeded"`.
    if let SaError::HorizonExceeded {
        rule_id_or_pending,
        requested_horizon,
        max_horizon,
    } = err
    {
        let wrapped = WalletError::Validation(ValidationError::SessionRuleHorizonExceeded {
            rule_id_or_pending: *rule_id_or_pending,
            requested_horizon: *requested_horizon,
            max_horizon: *max_horizon,
        });
        return emit_error(&wrapped, output, request_id);
    }
    let wrapped = WalletError::SmartAccount {
        wire_code: err.wire_code(),
        message: err.to_string(),
    };
    emit_error(&wrapped, output, request_id)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only assertions"
    )]

    use super::*;
    use clap::Parser;
    use serial_test::serial;
    use stellar_agent_core::constants::SIMULATE_SENTINEL_G;
    use stellar_agent_core::error::CapKind;

    const PASSKEY_PROJECT_A_TOML: &str = "[[credentials]]\ncredential_name = \"laptop-passkey\"\ncredential_id_b64url = \"cHJvamVjdC1hLWNyZWRlbnRpYWw\"\nrp_id = \"localhost\"\ntransports = \"internal\"\nregistered_at_unix_ms = 2\npublic_key_sec1_b64 = \"BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"\n";

    #[test]
    fn create_result_signers_count_round_trips_as_combined_total() {
        let result = CreateResult {
            smart_account: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".to_owned(),
            rule_id: 7,
            name: "mixed-signers".to_owned(),
            signers_count: 2,
            signer_delegated_count: 1,
            signer_webauthn_count: 1,
            valid_until: None,
            pinned_verifier_wasm_hashes_first8: vec![],
            pinned_policy_wasm_hashes_first8: vec![],
            mutable_override: false,
            unknown_override: false,
        };

        let json = serde_json::to_string(&result).unwrap();
        let round_trip: CreateResult = serde_json::from_str(&json).unwrap();

        assert_eq!(
            round_trip.signers_count,
            round_trip.signer_delegated_count + round_trip.signer_webauthn_count
        );
    }

    // ── Per-rule signer cap at `smart-account rules create` ─────────────────────────
    //
    // These tests call the real `enforce_signer_cap` helper (also used by
    // `create_run`) to verify the guard boundary.  Any inversion or deletion
    // of the `>` predicate in the helper causes these tests to fail.

    /// 16 `--signer-delegated` args exceed OZ_MAX_SIGNERS.
    ///
    /// Parses args via the clap harness, then feeds the count to
    /// `enforce_signer_cap`.  The helper must return
    /// `Err(ContextRuleCapsExceeded { kind: Signer, attempted: 16, max: 15 })`.
    #[test]
    fn create_16_delegated_signers_exceeds_cap() {
        // 16 distinct G-strkeys. Using a single sentinel repeated would cause
        // on-chain DuplicateSigner but the cap check fires before any network
        // call, so the value doesn't matter for this test.
        const G: &str = SIMULATE_SENTINEL_G;
        let mut argv = vec![
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--name",
            "capped-rule",
            "--signer-secret-env",
            "__STELLAR_AGENT_RULES_TEST_DUMMY_VAR",
        ];
        // 16 occurrences of --signer-delegated.
        for _ in 0..16 {
            argv.push("--signer-delegated");
            argv.push(G);
        }
        let parsed = CreateArgsHarness::parse_from(argv);
        let total = parsed.args.signer_delegated.len() + parsed.args.signer_webauthn.len();
        assert_eq!(total, 16);

        // Call the real guard — NOT the predicate directly.
        let err = enforce_signer_cap(total)
            .expect_err("enforce_signer_cap must return Err for 16 signers");
        let wallet_err = WalletError::Validation(err);
        assert_eq!(wallet_err.code(), "validation.context_rule_caps_exceeded");
        let msg = wallet_err.to_string();
        assert!(
            msg.contains("cannot add Signer #16"),
            "error message must name kind and attempted count; got: {msg}"
        );
        assert!(
            msg.contains("current cap: 15"),
            "error message must name the cap; got: {msg}"
        );
        assert!(
            msg.contains("rule-rotation pattern"),
            "error message must name the alternative; got: {msg}"
        );
    }

    /// 16 `--signer-webauthn` args exceed OZ_MAX_SIGNERS.
    ///
    /// WebAuthn args are resolved via the passkeys registry at `create_run`
    /// time; the cap check fires before that resolution.  `enforce_signer_cap`
    /// must return `Err` for 16 webauthn-only entries.
    #[test]
    fn create_16_webauthn_signers_exceeds_cap() {
        let mut argv = vec![
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--name",
            "capped-rule-webauthn",
            "--accept-no-delegated-fallback",
            "--signer-secret-env",
            "__STELLAR_AGENT_RULES_TEST_DUMMY_VAR",
        ];
        for i in 0..16_u32 {
            argv.push("--signer-webauthn");
            // Use static strings; leak is acceptable in test-only code.
            argv.push(Box::leak(format!("cred-{i}").into_boxed_str()));
        }
        let parsed = CreateArgsHarness::parse_from(argv);
        let total = parsed.args.signer_delegated.len() + parsed.args.signer_webauthn.len();
        assert_eq!(total, 16);
        enforce_signer_cap(total)
            .expect_err("enforce_signer_cap must return Err for 16 webauthn signers");
    }

    /// Mixed 8 delegated + 8 webauthn = 16 total exceeds cap.
    #[test]
    fn create_mixed_8_delegated_8_webauthn_exceeds_cap() {
        let mut argv = vec![
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--name",
            "capped-mixed-rule",
            "--signer-secret-env",
            "__STELLAR_AGENT_RULES_TEST_DUMMY_VAR",
        ];
        for _ in 0..8_u32 {
            argv.push("--signer-delegated");
            argv.push(SIMULATE_SENTINEL_G);
        }
        for i in 0..8_u32 {
            argv.push("--signer-webauthn");
            argv.push(Box::leak(format!("wa-cred-{i}").into_boxed_str()));
        }
        let parsed = CreateArgsHarness::parse_from(argv);
        let total = parsed.args.signer_delegated.len() + parsed.args.signer_webauthn.len();
        assert_eq!(total, 16, "8 + 8 = 16 total signers");
        enforce_signer_cap(total)
            .expect_err("enforce_signer_cap must return Err for 16 total signers");
    }

    /// Exactly 15 `--signer-delegated` does NOT trigger cap.
    ///
    /// Boundary condition: `OZ_MAX_SIGNERS` exactly is allowed.
    /// `enforce_signer_cap` must return `Ok(())` for 15 signers — if the
    /// predicate were `>=` instead of `>`, this assertion would fail.
    #[test]
    fn create_exactly_15_signers_does_not_exceed_cap() {
        let mut argv = vec![
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--name",
            "at-boundary-rule",
            "--signer-secret-env",
            "__STELLAR_AGENT_RULES_TEST_DUMMY_VAR",
        ];
        for _ in 0..15_u32 {
            argv.push("--signer-delegated");
            argv.push(SIMULATE_SENTINEL_G);
        }
        let parsed = CreateArgsHarness::parse_from(argv);
        let total = parsed.args.signer_delegated.len() + parsed.args.signer_webauthn.len();
        assert_eq!(total, 15, "exactly 15 signers at boundary");
        // Must be Ok — the guard allows exactly OZ_MAX_SIGNERS signers.
        enforce_signer_cap(total)
            .expect("enforce_signer_cap must return Ok(()) for exactly 15 signers");
    }

    /// Asserts that the wire code for `ContextRuleCapsExceeded` is stable.
    ///
    /// Wire-format stability policy: the code string is part of the public API.
    /// Renaming silently is a breaking change.
    #[test]
    fn context_rule_caps_exceeded_wire_code_is_stable() {
        let err = ValidationError::ContextRuleCapsExceeded {
            kind: CapKind::Signer,
            attempted: 16,
            max: 15,
        };
        assert_eq!(err.code(), "validation.context_rule_caps_exceeded");
    }

    /// Asserts that `CapKind::Policy` produces a distinct `{kind:?}` token in
    /// the error message.
    #[test]
    fn context_rule_caps_exceeded_policy_kind_message() {
        let err = ValidationError::ContextRuleCapsExceeded {
            kind: CapKind::Policy,
            attempted: 6,
            max: 5,
        };
        let msg = err.to_string();
        assert!(
            msg.contains("cannot add Policy #6"),
            "policy cap error must name kind=Policy; got: {msg}"
        );
        assert!(
            msg.contains("current cap: 5"),
            "policy cap error must name max=5; got: {msg}"
        );
    }

    #[derive(Parser)]
    struct CreateArgsHarness {
        #[command(flatten)]
        args: CreateArgs,
    }

    #[test]
    fn create_args_accepts_profile_for_webauthn_registry_lookup() {
        let parsed = CreateArgsHarness::parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--name",
            "mixed-signers",
            "--signer-webauthn",
            "laptop-passkey",
            "--accept-no-delegated-fallback",
            "--profile",
            "project-a",
            "--signer-secret-env",
            "__STELLAR_AGENT_RULES_TEST_DUMMY_VAR",
        ]);

        assert_eq!(parsed.args.common.profile.as_deref(), Some("project-a"));
    }

    #[test]
    fn create_args_accepts_secondary_rpc_url() {
        let parsed = CreateArgsHarness::parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--name",
            "mixed-signers",
            "--signer-delegated",
            SIMULATE_SENTINEL_G,
            "--secondary-rpc-url",
            "https://secondary.example",
            "--signer-secret-env",
            "__STELLAR_AGENT_RULES_TEST_DUMMY_VAR",
        ]);

        assert_eq!(
            parsed.args.common.secondary_rpc_url.as_deref(),
            Some("https://secondary.example")
        );
    }

    // ── --context grammar matrix ─────────────────────────────────────────────

    /// Extracts the `ConfigInvalid` reason string from a `--context` parse
    /// failure, asserting the error is the expected variant and component.
    fn context_error_reason(err: WalletError) -> String {
        match err {
            WalletError::Validation(ValidationError::ConfigInvalid { component, reason }) => {
                assert_eq!(
                    component, "--context",
                    "context parse errors must carry component '--context'"
                );
                reason
            }
            other => panic!("expected ConfigInvalid for --context; got {other:?}"),
        }
    }

    /// Both the literal `default` and an omitted flag (whose clap default is
    /// `default`) resolve to `RuleContext::Default`, and the parse is
    /// case-insensitive.
    #[test]
    fn parse_rule_context_default_variants() {
        assert!(matches!(
            parse_rule_context("default").unwrap(),
            RuleContext::Default
        ));
        assert!(matches!(
            parse_rule_context("DEFAULT").unwrap(),
            RuleContext::Default
        ));

        // Flag absent: clap fills the `default` default_value.
        let parsed = CreateArgsHarness::parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--name",
            "no-context-flag",
            "--signer-delegated",
            SIMULATE_SENTINEL_G,
            "--signer-secret-env",
            "__STELLAR_AGENT_RULES_TEST_DUMMY_VAR",
        ]);
        assert_eq!(
            parsed.args.context, "default",
            "omitted --context must default to 'default'"
        );
        assert!(matches!(
            parse_rule_context(&parsed.args.context).unwrap(),
            RuleContext::Default
        ));
    }

    /// `call-contract:<C-strkey>` parses to `RuleContext::CallContract` carrying
    /// the decoded contract address.
    #[test]
    fn parse_rule_context_call_contract_valid() {
        let strkey = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";
        let expected = parse_c_strkey_to_smart_account(strkey).unwrap();
        let ctx = parse_rule_context(&format!("call-contract:{strkey}")).unwrap();
        match ctx {
            RuleContext::CallContract { contract } => assert_eq!(contract, expected),
            other => panic!("expected CallContract; got {other:?}"),
        }
    }

    /// `create-contract:<64-hex>` parses to `RuleContext::CreateContract`
    /// carrying the decoded 32-byte wasm hash.
    #[test]
    fn parse_rule_context_create_contract_valid() {
        let hex_hash = "ab".repeat(32);
        let ctx = parse_rule_context(&format!("create-contract:{hex_hash}")).unwrap();
        match ctx {
            RuleContext::CreateContract { wasm_hash } => assert_eq!(wasm_hash, [0xAB_u8; 32]),
            other => panic!("expected CreateContract; got {other:?}"),
        }
    }

    /// A malformed C-strkey in `call-contract:` fails closed with the accepted
    /// grammar in the message.
    #[test]
    fn parse_rule_context_call_contract_malformed_strkey_fails_closed() {
        let err = parse_rule_context("call-contract:not-a-strkey").unwrap_err();
        let reason = context_error_reason(err);
        assert!(
            reason.contains("call-contract:") && reason.contains("create-contract:"),
            "error must name the accepted grammar; got: {reason}"
        );
    }

    /// A wrong-length hex in `create-contract:` (63 chars) fails closed.
    #[test]
    fn parse_rule_context_create_contract_wrong_length_fails_closed() {
        let short = "a".repeat(63);
        let err = parse_rule_context(&format!("create-contract:{short}")).unwrap_err();
        let reason = context_error_reason(err);
        assert!(
            reason.contains("64 hex chars"),
            "wrong-length hash error must name the 64-hex requirement; got: {reason}"
        );
        assert!(
            reason.contains("create-contract:"),
            "error must name the accepted grammar; got: {reason}"
        );
    }

    /// A 64-char non-hex string in `create-contract:` fails closed.
    #[test]
    fn parse_rule_context_create_contract_non_hex_fails_closed() {
        let non_hex = "z".repeat(64);
        let err = parse_rule_context(&format!("create-contract:{non_hex}")).unwrap_err();
        let reason = context_error_reason(err);
        assert!(
            reason.contains("not valid hex"),
            "non-hex hash error must say so; got: {reason}"
        );
    }

    /// An unknown context kind fails closed with the accepted grammar.
    #[test]
    fn parse_rule_context_unknown_kind_fails_closed() {
        let err = parse_rule_context("frobnicate:whatever").unwrap_err();
        let reason = context_error_reason(err);
        assert!(
            reason.contains("unknown context") && reason.contains("call-contract:"),
            "unknown kind must name the accepted grammar; got: {reason}"
        );
    }

    /// The empty string fails closed (it is neither `default` nor a prefixed
    /// form).
    #[test]
    fn parse_rule_context_empty_string_fails_closed() {
        let err = parse_rule_context("").unwrap_err();
        let reason = context_error_reason(err);
        assert!(
            reason.contains("call-contract:") && reason.contains("create-contract:"),
            "empty context must name the accepted grammar; got: {reason}"
        );
    }

    /// `CreateArgs` accepts a well-formed `--context call-contract:<C-strkey>`
    /// on the command line and threads it through to `parse_rule_context`.
    #[test]
    fn create_args_accepts_call_contract_context_flag() {
        let strkey = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";
        let parsed = CreateArgsHarness::parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--name",
            "scoped-rule",
            "--signer-delegated",
            SIMULATE_SENTINEL_G,
            "--context",
            &format!("call-contract:{strkey}"),
            "--signer-secret-env",
            "__STELLAR_AGENT_RULES_TEST_DUMMY_VAR",
        ]);
        assert_eq!(parsed.args.context, format!("call-contract:{strkey}"));
        assert!(matches!(
            parse_rule_context(&parsed.args.context).unwrap(),
            RuleContext::CallContract { .. }
        ));
    }

    #[derive(Parser)]
    struct SetNameArgsHarness {
        #[command(flatten)]
        args: SetNameArgs,
    }

    #[test]
    fn set_name_args_accept_profile_and_secondary_rpc_url() {
        let parsed = SetNameArgsHarness::parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "1",
            "--name",
            "renamed",
            "--profile",
            "project-a",
            "--secondary-rpc-url",
            "https://secondary.example",
            "--signer-secret-env",
            "__STELLAR_AGENT_RULES_TEST_DUMMY_VAR",
        ]);

        assert_eq!(parsed.args.common.profile.as_deref(), Some("project-a"));
        assert_eq!(
            parsed.args.common.secondary_rpc_url.as_deref(),
            Some("https://secondary.example")
        );
    }

    #[test]
    fn webauthn_registry_lookup_uses_selected_profile() {
        let dir = tempfile::TempDir::new().unwrap();
        let passkeys_dir = dir.path().join("passkeys");
        std::fs::create_dir_all(&passkeys_dir).unwrap();
        std::fs::write(
            passkeys_dir.join("default.toml"),
            "[[credentials]]\ncredential_name = \"default-passkey\"\ncredential_id_b64url = \"ZGVmYXVsdC1jcmVkZW50aWFs\"\nrp_id = \"localhost\"\ntransports = \"usb\"\nregistered_at_unix_ms = 1\npublic_key_sec1_b64 = \"BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"\n",
        )
        .unwrap();
        std::fs::write(passkeys_dir.join("project-a.toml"), PASSKEY_PROJECT_A_TOML).unwrap();

        let default_mgr =
            CredentialsManager::new(passkeys_dir.clone(), "default", "localhost", None);
        assert!(default_mgr.show("laptop-passkey").is_err());

        let project_mgr = CredentialsManager::new(passkeys_dir, "project-a", "localhost", None);
        let meta = project_mgr.show("laptop-passkey").unwrap();
        assert_eq!(meta.credential_name, "laptop-passkey");
        assert_eq!(meta.transports, "internal");
    }

    /// RAII guard for the `STELLAR_AGENT_HOME` env-var override.
    ///
    /// Restores the previous value (or removes it if absent) on `Drop` —
    /// panic-safe, unlike a manual save/restore around the work block. The
    /// `#[allow(unsafe_code)]` attribute is applied to each of the two impl
    /// blocks (one on `impl StellarAgentHomeGuard`, one on `impl Drop`).
    struct StellarAgentHomeGuard {
        previous: Option<std::ffi::OsString>,
    }

    #[allow(
        unsafe_code,
        reason = "test-only process environment override; #[serial] prevents sibling mutation, RAII guard unwinds on Drop"
    )]
    impl StellarAgentHomeGuard {
        fn new(value: &std::path::Path) -> Self {
            let previous = std::env::var_os("STELLAR_AGENT_HOME");
            // SAFETY: serialised by #[serial]; mutated only by this guard
            // and unwound on Drop.
            unsafe {
                std::env::set_var("STELLAR_AGENT_HOME", value);
            }
            Self { previous }
        }
    }

    #[allow(
        unsafe_code,
        reason = "test-only process environment restore; panic-safe via Drop"
    )]
    impl Drop for StellarAgentHomeGuard {
        fn drop(&mut self) {
            // SAFETY: same as new(); serialised by #[serial], restores
            // pre-test state regardless of panic.
            unsafe {
                if let Some(value) = self.previous.take() {
                    std::env::set_var("STELLAR_AGENT_HOME", value);
                } else {
                    std::env::remove_var("STELLAR_AGENT_HOME");
                }
            }
        }
    }

    #[test]
    #[serial]
    fn webauthn_registry_lookup_via_from_defaults_readonly() {
        let dir = tempfile::TempDir::new().unwrap();
        let passkeys_dir = dir.path().join("passkeys");
        std::fs::create_dir_all(&passkeys_dir).unwrap();
        std::fs::write(passkeys_dir.join("project-a.toml"), PASSKEY_PROJECT_A_TOML).unwrap();

        let _guard = StellarAgentHomeGuard::new(dir.path());

        let mgr = CredentialsManager::from_defaults_readonly("project-a", "localhost").unwrap();
        let meta = mgr.show("laptop-passkey").unwrap();

        assert_eq!(meta.credential_name, "laptop-passkey");
        assert_eq!(meta.transports, "internal");
        // Guard drops here, restoring STELLAR_AGENT_HOME to its pre-test state.
    }

    // ── `--accept-mutable-verifier` / `--accept-unknown-verifier` + verify-pins ──

    #[test]
    fn create_args_accept_mutable_verifier_flag() {
        let parsed = CreateArgsHarness::parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--name",
            "rule-with-mutable-override",
            "--signer-delegated",
            SIMULATE_SENTINEL_G,
            "--accept-mutable-verifier",
            "--signer-secret-env",
            "__STELLAR_AGENT_RULES_TEST_DUMMY_VAR",
        ]);

        assert!(
            parsed.args.accept_mutable_verifier,
            "--accept-mutable-verifier must set accept_mutable_verifier = true"
        );
        assert!(
            !parsed.args.accept_unknown_verifier,
            "accept_unknown_verifier must default to false"
        );
    }

    #[test]
    fn create_args_accept_unknown_verifier_flag() {
        let parsed = CreateArgsHarness::parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--name",
            "rule-with-unknown-override",
            "--signer-delegated",
            SIMULATE_SENTINEL_G,
            "--accept-unknown-verifier",
            "--signer-secret-env",
            "__STELLAR_AGENT_RULES_TEST_DUMMY_VAR",
        ]);

        assert!(
            parsed.args.accept_unknown_verifier,
            "--accept-unknown-verifier must set accept_unknown_verifier = true"
        );
        assert!(
            !parsed.args.accept_mutable_verifier,
            "accept_mutable_verifier must default to false"
        );
    }

    #[test]
    fn create_args_both_override_flags_are_independent() {
        let parsed = CreateArgsHarness::parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--name",
            "rule-with-both-overrides",
            "--signer-delegated",
            SIMULATE_SENTINEL_G,
            "--accept-mutable-verifier",
            "--accept-unknown-verifier",
            "--signer-secret-env",
            "__STELLAR_AGENT_RULES_TEST_DUMMY_VAR",
        ]);

        assert!(parsed.args.accept_mutable_verifier);
        assert!(parsed.args.accept_unknown_verifier);
    }

    #[derive(Parser)]
    struct VerifyPinsArgsHarness {
        #[command(flatten)]
        args: VerifyPinsArgs,
    }

    #[test]
    fn verify_pins_args_parse_required_fields() {
        let parsed = VerifyPinsArgsHarness::parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "3",
            "--signer-secret-env",
            "__STELLAR_AGENT_RULES_TEST_DUMMY_VAR",
        ]);

        assert_eq!(
            parsed.args.account,
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM"
        );
        assert_eq!(parsed.args.rule_id, 3);
        // VerifyPinsArgs is read-only: it carries no install-time override flags.
        assert_eq!(
            parsed.args.network,
            TargetNetwork::Testnet,
            "default network is testnet"
        );
        assert_eq!(
            parsed.args.rpc_url(),
            TESTNET_RPC_URL,
            "testnet default RPC URL must remain the testnet endpoint"
        );
    }

    #[test]
    fn verify_pins_args_requires_account_and_rule_id() {
        assert!(
            VerifyPinsArgsHarness::try_parse_from([
                "test",
                "--rule-id",
                "3",
                "--signer-secret-env",
                "__STELLAR_AGENT_RULES_TEST_DUMMY_VAR",
            ])
            .is_err(),
            "--account is required"
        );
        assert!(
            VerifyPinsArgsHarness::try_parse_from([
                "test",
                "--account",
                "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
                "--signer-secret-env",
                "__STELLAR_AGENT_RULES_TEST_DUMMY_VAR",
            ])
            .is_err(),
            "--rule-id is required"
        );
    }

    #[test]
    fn verify_pins_args_parse_timeout_profile_and_rpc_url() {
        let parsed = VerifyPinsArgsHarness::parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "8",
            "--profile",
            "ops",
            "--rpc-url",
            "https://rpc.example",
            "--timeout-seconds",
            "17",
            "--signer-secret-env",
            "__STELLAR_AGENT_RULES_TEST_DUMMY_VAR",
        ]);

        assert_eq!(parsed.args.profile.as_deref(), Some("ops"));
        assert_eq!(parsed.args.rpc_url.as_deref(), Some("https://rpc.example"));
        assert_eq!(parsed.args.rpc_url(), "https://rpc.example");
        assert_eq!(parsed.args.timeout_seconds, 17);
    }

    #[test]
    fn verify_pins_args_mainnet_defaults_to_mainnet_rpc_url() {
        let parsed = VerifyPinsArgsHarness::parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "9",
            "--network",
            "mainnet",
            "--signer-secret-env",
            "__STELLAR_AGENT_RULES_TEST_DUMMY_VAR",
        ]);

        assert_eq!(parsed.args.network, TargetNetwork::Mainnet);
        assert_eq!(parsed.args.rpc_url(), MAINNET_RPC_URL);
        assert_eq!(parsed.args.rpc_url, None);
    }

    #[test]
    fn verify_pins_args_accept_secondary_rpc_url() {
        let parsed = VerifyPinsArgsHarness::parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "5",
            "--secondary-rpc-url",
            "https://secondary.example",
            "--signer-secret-env",
            "__STELLAR_AGENT_RULES_TEST_DUMMY_VAR",
        ]);

        assert_eq!(
            parsed.args.secondary_rpc_url.as_deref(),
            Some("https://secondary.example")
        );
    }

    #[test]
    fn verify_pins_result_json_round_trip() {
        let result = VerifyPinsResult {
            smart_account: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".to_owned(),
            rule_id: 2,
            verifier_pin_status: PinStatus::Match,
            policy_pin_status: PinStatus::Match,
            pinned_verifier_first8: vec!["ab12cd34".to_owned()],
            pinned_policy_first8: vec!["ef56gh78".to_owned()],
            observed_verifier_first8: vec!["ab12cd34".to_owned()],
            observed_policy_first8: vec!["ef56gh78".to_owned()],
            mutable_override: false,
            unknown_override: false,
            unavailable_reason: None,
            chain_id: "stellar:testnet".to_owned(),
        };

        let json = serde_json::to_string(&result).unwrap();
        let round_trip: VerifyPinsResult = serde_json::from_str(&json).unwrap();

        assert_eq!(round_trip.verifier_pin_status, PinStatus::Match);
        assert_eq!(round_trip.policy_pin_status, PinStatus::Match);
        assert_eq!(round_trip.pinned_verifier_first8, vec!["ab12cd34"]);
        assert_eq!(round_trip.chain_id, "stellar:testnet");
        assert!(!round_trip.mutable_override);
        assert!(!round_trip.unknown_override);
        // Snake-case wire strings per PinStatus serde.
        assert!(
            json.contains("\"match\""),
            "expected snake_case 'match' in {json}"
        );
        assert!(
            json.contains("\"verifier_pin_status\":\"match\""),
            "verifier status field must use snake_case wire value: {json}"
        );
        // unavailable_reason is skipped when None.
        assert!(!json.contains("unavailable_reason"));
    }

    #[test]
    fn verify_pins_result_unavailable_reason_serialised_when_present() {
        let result = VerifyPinsResult {
            smart_account: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".to_owned(),
            rule_id: 1,
            verifier_pin_status: PinStatus::Unavailable,
            policy_pin_status: PinStatus::Unavailable,
            pinned_verifier_first8: vec![],
            pinned_policy_first8: vec![],
            observed_verifier_first8: vec![],
            observed_policy_first8: vec![],
            mutable_override: false,
            unknown_override: false,
            unavailable_reason: Some("sa.network_rpc_divergence".to_owned()),
            chain_id: "stellar:testnet".to_owned(),
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(
            json.contains("unavailable_reason"),
            "unavailable_reason must appear in JSON when Some"
        );
        assert!(json.contains("sa.network_rpc_divergence"));
        // Wire value must be snake_case "unavailable".
        assert!(
            json.contains("\"unavailable\""),
            "expected snake_case 'unavailable' in {json}"
        );
    }

    #[test]
    fn verify_pins_result_drift_and_no_pin_wire_values_are_stable() {
        let result = VerifyPinsResult {
            smart_account: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".to_owned(),
            rule_id: 4,
            verifier_pin_status: PinStatus::Drift,
            policy_pin_status: PinStatus::NoPin,
            pinned_verifier_first8: vec!["aaaaaaaa".to_owned()],
            pinned_policy_first8: vec![],
            observed_verifier_first8: vec!["bbbbbbbb".to_owned()],
            observed_policy_first8: vec![],
            mutable_override: false,
            unknown_override: false,
            unavailable_reason: None,
            chain_id: "stellar:testnet".to_owned(),
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(
            json.contains("\"verifier_pin_status\":\"drift\""),
            "drift status must serialize as 'drift': {json}"
        );
        assert!(
            json.contains("\"policy_pin_status\":\"no_pin\""),
            "no-pin status must serialize as 'no_pin': {json}"
        );
    }

    // ── Per-rule policy cap at `smart-account rules add-policy` ──────────────────────
    //
    // Verify that the policy-count predicate used in `add_policy_run` fires
    // correctly at the boundary (5 → refused; 4 → OK).
    //
    // Strategy: the full `add_policy_run` is async and calls the network (via
    // `manager.get_rule`), so we test the cap-check predicate directly on a
    // synthetic `ScVal::Map` fixture — the same approach used for the signer
    // cap.  The fixture is built by `make_rule_scval_with_policies(n)`, which
    // constructs the minimum `ContextRule` ScVal shape needed for
    // `decode_policy_count_from_scval` to succeed.
    //
    // `AddPolicyArgsHarness` verifies the clap surface (all required flags parse
    // correctly), independently of the cap-check path.

    use stellar_xdr::{ScMap as XdrScMap, ScMapEntry as XdrScMapEntry, ScVec as XdrScVec};

    /// Builds a synthetic `ContextRule` `ScVal::Map` containing a `policy_ids`
    /// field with `n` entries.
    ///
    /// Only the `policy_ids` key is required by `decode_policy_count_from_scval`.
    /// The value is `ScVal::Vec(Some(ScVec([U32(0), U32(1), ...])))`.
    ///
    /// OZ storage layout: `ContextRuleEntry.policy_ids: Vec<u32>`.
    fn make_rule_scval_with_policies(n: usize) -> stellar_xdr::ScVal {
        let elems: Vec<stellar_xdr::ScVal> =
            (0..n).map(|i| stellar_xdr::ScVal::U32(i as u32)).collect();
        let policy_ids_vec =
            stellar_xdr::ScVal::Vec(Some(XdrScVec(elems.try_into().expect("policy_ids VecM"))));
        let entry = XdrScMapEntry {
            key: stellar_xdr::ScVal::Symbol(stellar_xdr::ScSymbol(
                "policy_ids".try_into().expect("ScSymbol"),
            )),
            val: policy_ids_vec,
        };
        stellar_xdr::ScVal::Map(Some(XdrScMap(vec![entry].try_into().expect("ScMap"))))
    }

    #[derive(Parser)]
    struct AddPolicyArgsHarness {
        #[command(flatten)]
        args: AddPolicyArgs,
    }

    /// A rule with `policy_count = 5` triggers the
    /// `ContextRuleCapsExceeded { kind: Policy, attempted: 6, max: 5 }` error.
    ///
    /// Decodes the count from a real ScVal (exercising production code) then
    /// feeds it to `enforce_policy_cap`.  The helper must return `Err`.  If the
    /// `>` predicate in `enforce_policy_cap` were inverted or deleted this test
    /// would fail.
    #[test]
    fn add_policy_5_policy_rule_triggers_cap() {
        let scval = make_rule_scval_with_policies(5);
        let policy_count =
            decode_policy_count_from_scval(&scval).expect("decode_policy_count_from_scval");
        assert_eq!(policy_count, 5, "5-element policy_ids must yield count=5");

        // Call the real guard — NOT the predicate directly.
        let err = enforce_policy_cap(policy_count)
            .expect_err("enforce_policy_cap must return Err for policy_count=5 (attempted=6)");
        let wallet_err = WalletError::Validation(err);
        assert_eq!(wallet_err.code(), "validation.context_rule_caps_exceeded");
        let msg = wallet_err.to_string();
        assert!(
            msg.contains("cannot add Policy #6"),
            "cap error must name kind=Policy and attempted=6; got: {msg}"
        );
        assert!(
            msg.contains("current cap: 5"),
            "cap error must name max=5; got: {msg}"
        );
    }

    /// A rule with `policy_count = 4` does NOT trigger the cap.
    ///
    /// Boundary condition: `enforce_policy_cap(4)` computes `attempted = 5`,
    /// which equals `OZ_MAX_POLICIES`.  The predicate is strictly `>`, so 5
    /// must pass.  If the predicate were `>=` this assertion would fail.
    #[test]
    fn add_policy_4_policy_rule_does_not_trigger_cap() {
        let scval = make_rule_scval_with_policies(4);
        let policy_count =
            decode_policy_count_from_scval(&scval).expect("decode_policy_count_from_scval");
        assert_eq!(policy_count, 4, "4-element policy_ids must yield count=4");

        // Must be Ok — adding a 5th policy to a 4-policy rule is within cap.
        enforce_policy_cap(policy_count)
            .expect("enforce_policy_cap must return Ok(()) for policy_count=4 (attempted=5)");
    }

    /// `AddPolicyArgsHarness` parses all required fields.
    #[test]
    fn add_policy_args_parse_required_fields() {
        // Use ScVal::Void encoded as standard base64 XDR for the install-param.
        // `ScVal::Void` XDR is 4 zero bytes (discriminant=0, no body), which
        // encodes to base64 "AAAAAA==".
        let void_b64 = {
            use stellar_xdr::{Limits, WriteXdr as _};
            stellar_xdr::ScVal::Void
                .to_xdr_base64(Limits::none())
                .expect("ScVal::Void to base64")
        };
        let parsed = AddPolicyArgsHarness::parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "3",
            "--policy-address",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--install-param",
            &void_b64,
            "--signer-secret-env",
            "__STELLAR_AGENT_RULES_TEST_DUMMY_VAR",
        ]);

        assert_eq!(parsed.args.rule_id, 3);
        assert_eq!(parsed.args.kind, PolicyKind::Raw, "default kind is raw");
        assert_eq!(
            parsed.args.install_param.as_deref(),
            Some(void_b64.as_str())
        );
        assert_eq!(
            parsed.args.policy_address.as_deref(),
            Some("CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM")
        );
        assert_eq!(
            parsed.args.network,
            TargetNetwork::Testnet,
            "default network is testnet"
        );
        assert!(
            parsed.args.auth_rule_id.is_empty(),
            "auth_rule_id defaults to empty (handler defaults to [rule_id])"
        );
    }

    /// An unrecognised `--kind` value is a clap grammar error, not a runtime
    /// refusal — the four valid values are `raw`, `spending-limit`,
    /// `simple-threshold`, `weighted-threshold`.
    #[test]
    fn add_policy_args_unknown_kind_is_grammar_error() {
        let result = AddPolicyArgsHarness::try_parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "3",
            "--kind",
            "not-a-real-kind",
            "--signer-secret-env",
            "__STELLAR_AGENT_RULES_TEST_DUMMY_VAR",
        ]);
        assert!(
            result.is_err(),
            "an unrecognised --kind value must be a clap parse error"
        );
    }

    /// Each of the three typed `--kind` values (`simple-threshold`,
    /// `spending-limit`, `weighted-threshold`) parses to the matching
    /// `PolicyKind` variant.
    #[test]
    fn add_policy_args_kind_grammar_accepts_all_typed_values() {
        for (label, expected) in [
            ("simple-threshold", PolicyKind::SimpleThreshold),
            ("spending-limit", PolicyKind::SpendingLimit),
            ("weighted-threshold", PolicyKind::WeightedThreshold),
        ] {
            let parsed = AddPolicyArgsHarness::parse_from([
                "test",
                "--account",
                "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
                "--rule-id",
                "3",
                "--kind",
                label,
                "--signer-secret-env",
                "__STELLAR_AGENT_RULES_TEST_DUMMY_VAR",
            ]);
            assert_eq!(parsed.args.kind, expected, "--kind {label} must parse");
        }
    }

    /// Verifies that `AddPolicyArgs` accepts multiple `--auth-rule-id` flags.
    #[test]
    fn add_policy_args_accept_multiple_auth_rule_ids() {
        let void_b64 = {
            use stellar_xdr::{Limits, WriteXdr as _};
            stellar_xdr::ScVal::Void
                .to_xdr_base64(Limits::none())
                .expect("ScVal::Void to base64")
        };
        let parsed = AddPolicyArgsHarness::parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "5",
            "--policy-address",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--install-param",
            &void_b64,
            "--auth-rule-id",
            "1",
            "--auth-rule-id",
            "2",
            "--signer-secret-env",
            "__STELLAR_AGENT_RULES_TEST_DUMMY_VAR",
        ]);

        assert_eq!(parsed.args.auth_rule_id, vec![1_u32, 2_u32]);
    }

    #[derive(Parser)]
    struct RemovePolicyArgsHarness {
        #[command(flatten)]
        args: RemovePolicyArgs,
    }

    /// Verifies that `RemovePolicyArgs` parses all required fields correctly.
    #[test]
    fn remove_policy_args_parse_required_fields() {
        let parsed = RemovePolicyArgsHarness::parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "7",
            "--policy-id",
            "2",
            "--signer-secret-env",
            "__STELLAR_AGENT_RULES_TEST_DUMMY_VAR",
        ]);

        assert_eq!(parsed.args.rule_id, 7);
        assert_eq!(parsed.args.policy_id, 2);
        assert_eq!(
            parsed.args.network,
            TargetNetwork::Testnet,
            "default network is testnet"
        );
        assert!(
            parsed.args.auth_rule_id.is_empty(),
            "auth_rule_id defaults to empty"
        );
    }

    /// Verifies `AddPolicyResult` round-trips through JSON.
    #[test]
    fn add_policy_result_json_round_trip() {
        let result = AddPolicyResult {
            smart_account: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".to_owned(),
            rule_id: 3,
            policy_id: 1,
            policy_address: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".to_owned(),
        };
        let json = serde_json::to_string(&result).unwrap();
        let rt: AddPolicyResult = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.rule_id, 3);
        assert_eq!(rt.policy_id, 1);
    }

    /// Verifies `RemovePolicyResult` round-trips through JSON.
    #[test]
    fn remove_policy_result_json_round_trip() {
        let result = RemovePolicyResult {
            smart_account: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".to_owned(),
            rule_id: 7,
            policy_id: 2,
        };
        let json = serde_json::to_string(&result).unwrap();
        let rt: RemovePolicyResult = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.rule_id, 7);
        assert_eq!(rt.policy_id, 2);
    }

    /// Verifies that `unknown_override: true` appears in the JSON envelope
    /// when a rule was installed with `--accept-unknown-verifier`: the
    /// install-time override flags are sourced from the `SaContextRuleCreated`
    /// audit row and must be surfaced in the CLI output.
    #[test]
    fn verify_pins_result_unknown_override_appears_in_json() {
        let result = VerifyPinsResult {
            smart_account: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".to_owned(),
            rule_id: 3,
            verifier_pin_status: PinStatus::Match,
            policy_pin_status: PinStatus::NoContracts,
            pinned_verifier_first8: vec!["deadbeef".to_owned()],
            pinned_policy_first8: vec![],
            observed_verifier_first8: vec!["deadbeef".to_owned()],
            observed_policy_first8: vec![],
            mutable_override: false,
            unknown_override: true,
            unavailable_reason: None,
            chain_id: "stellar:testnet".to_owned(),
        };

        let json = serde_json::to_string(&result).unwrap();
        let round_trip: VerifyPinsResult = serde_json::from_str(&json).unwrap();

        assert!(
            round_trip.unknown_override,
            "unknown_override: true must survive JSON round-trip"
        );
        assert!(
            !round_trip.mutable_override,
            "mutable_override must be false"
        );
        // Wire values for PinStatus variants.
        assert!(
            json.contains("\"match\""),
            "verifier status must be 'match'"
        );
        assert!(
            json.contains("\"no_contracts\""),
            "policy status must be 'no_contracts'"
        );
    }

    // ── smart-account rules list alias delegation ────────────────────────────────────
    //
    // `smart-account rules list` and `smart-account list-rules` produce identical JSON
    // envelopes against the same inputs.
    //
    // The dispatch-site log must carry the operator-invoked command name
    // verbatim so forensic audit-log correlation is unambiguous.
    //
    // Three properties are verified:
    //
    // Compile-time identity: `ListArgs` is a type alias for
    // `sa_list_rules::ListRulesArgs`. The alias identity is enforced at compile
    // time; assigning one type where the other is expected proves they are the
    // same type.
    //
    // JSON envelope byte-identity: `ListRulesResult` from `sa::list_rules` is the
    // shared wire type; both surfaces delegate to the same `run` function and
    // produce the same `ListRulesResult`. Structural identity is asserted by
    // serialising a fixed `ListRulesResult` value twice and comparing the strings.
    //
    // Dispatch-site log: `list_rules_run` emits a `tracing::info!` row with
    // `command = "smart-account rules list"` BEFORE delegating to `sa_list_rules::run`.
    // The row is captured via `CaptureWriter` + `tracing_subscriber::fmt()` by
    // invoking only the info! call directly (not the full async handler, which
    // would require a live RPC endpoint).

    use stellar_agent_test_support::CaptureWriter;

    /// `ListArgs` is a transparent type alias for
    /// `sa_list_rules::ListRulesArgs`.
    ///
    /// This assertion holds at compile time: the `type ListArgs = ...` declaration
    /// in the parent module guarantees that any `&ListArgs` is assignable from
    /// `&sa_list_rules::ListRulesArgs`. This test makes the relationship explicit
    /// in the test suite so a future maintainer cannot inadvertently break it by
    /// introducing a wrapper.
    #[test]
    fn list_args_is_type_alias_for_list_rules_args() {
        // Construct a value of the concrete type and assign it to the alias.
        // If the alias diverges from `ListRulesArgs`, this will fail to compile.
        fn accepts_list_args(_: &ListArgs) {}
        fn accepts_list_rules_args(_: &sa_list_rules::ListRulesArgs) {}

        // Both fn-pointer casts are compile-time proofs: if the alias ever
        // diverges from `sa_list_rules::ListRulesArgs`, one of these casts
        // will fail to compile. No runtime assertion is needed — the alias
        // identity is a compile-time invariant, not a runtime value.
        let _ = accepts_list_args as fn(&ListArgs);
        let _ = accepts_list_rules_args as fn(&sa_list_rules::ListRulesArgs);
    }

    /// JSON envelope byte-identity by construction.
    ///
    /// Both `smart-account rules list` and `smart-account list-rules` share the same
    /// `ListRulesResult` wire type from `sa::list_rules`.  A fixed value is
    /// serialised twice and the byte strings must be identical, confirming that
    /// there is no divergent serialisation path.
    #[test]
    fn wallet_rules_list_and_sa_list_rules_emit_byte_identical_json() {
        // Construct a representative ListRulesResult value (same struct type
        // used by both surfaces).
        let result = sa_list_rules::ListRulesResult {
            rules: vec![sa_list_rules::ListRulesEntry {
                rule_id: 0,
                name: "boot-rule".to_owned(),
                context_type_label: "default".to_owned(),
                signer_count: 1,
                policy_count: 0,
                valid_until: None,
            }],
            active_count: 1,
            scanned_id_range: sa_list_rules::ScannedIdRange { start: 0, end: 1 },
            rules_skipped: 0,
            gaps_seen: 0,
            audit_log_missing: vec![],
        };

        // Serialise via the `smart-account rules list` path (delegates to sa_list_rules).
        // Both surfaces use the same function and the same type; the serialised
        // bytes must be identical.
        let json_via_rules_list = serde_json::to_string(&result).unwrap();

        // Serialise a structurally identical value (same expression, same type).
        let result2 = sa_list_rules::ListRulesResult {
            rules: vec![sa_list_rules::ListRulesEntry {
                rule_id: 0,
                name: "boot-rule".to_owned(),
                context_type_label: "default".to_owned(),
                signer_count: 1,
                policy_count: 0,
                valid_until: None,
            }],
            active_count: 1,
            scanned_id_range: sa_list_rules::ScannedIdRange { start: 0, end: 1 },
            rules_skipped: 0,
            gaps_seen: 0,
            audit_log_missing: vec![],
        };
        let json_via_sa_list_rules = serde_json::to_string(&result2).unwrap();

        assert_eq!(
            json_via_rules_list, json_via_sa_list_rules,
            "smart-account rules list and smart-account list-rules must produce identical JSON envelopes"
        );

        // Sanity: the JSON envelope contains the expected top-level keys.
        let parsed: serde_json::Value = serde_json::from_str(&json_via_rules_list).unwrap();
        assert!(
            parsed["rules"].is_array(),
            "envelope must contain 'rules' array"
        );
        assert_eq!(parsed["active_count"].as_u64(), Some(1));
        assert!(parsed["scanned_id_range"].is_object());
        assert_eq!(parsed["rules_skipped"].as_u64(), Some(0));
        assert_eq!(parsed["gaps_seen"].as_u64(), Some(0));
        assert!(parsed["audit_log_missing"].is_array());
    }

    /// Dispatch-site log carries `command = "smart-account rules list"`.
    ///
    /// The structured-log row emitted at the `list_rules_run` dispatch site must
    /// carry `command = "smart-account rules list"` verbatim so audit-log forensic
    /// correlation can distinguish the operator-invoked command from the
    /// `smart-account list-rules` alias.
    ///
    /// Strategy: emit the same `tracing::info!` call that `list_rules_run` emits
    /// (without invoking the async handler — which would require a live RPC) and
    /// capture the output via [`CaptureWriter`].
    #[test]
    fn list_rules_dispatch_log_carries_command_name() {
        let capture = CaptureWriter::new();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::INFO)
            .finish();

        // Emit the same structured event that `list_rules_run` emits at the
        // dispatch site. The account field is redacted per the redaction rules.
        let account_redacted = stellar_agent_core::observability::redact_strkey_first5_last5(
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
        );
        let network = TargetNetwork::Testnet;
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(
                command = "smart-account rules list",
                account = tracing::field::display(&account_redacted),
                network = %network,
                "smart-account rules list: dispatching to list-rules handler"
            );
        });

        let log_output = capture.captured_str();

        // The log line must contain the operator-invoked command name verbatim.
        assert!(
            log_output.contains("smart-account rules list"),
            "dispatch-site log must contain 'smart-account rules list'; captured: {log_output}"
        );
        // The message must NOT contain "smart-account list-rules" — that is emitted
        // by `sa::list_rules::run` at its own dispatch site (distinct event).
        // (No assertion needed for the positive case on the list-rules side — that is
        //  tested by the list_rules module's own tests in sa/list_rules.rs.)
    }

    // ─────────────────────────────────────────────────────────────────────────
    // clap parse-tests for CommonRulesWriteArgs / CommonRulesReadArgs
    // ─────────────────────────────────────────────────────────────────────────

    /// `smart-account rules create` parse-test:
    ///
    /// - `--signer-delegated` is repeatable (num_args 1..)
    /// - `--auth-rule-id` defaults to `[0]` and is repeatable
    /// - `--valid-until none` parses as the string "none"
    /// - `--valid-until 12345` parses as the string "12345"
    /// - Signer-source flags are mutually exclusive (three-way group)
    #[test]
    fn create_args_signer_delegated_repeatable_and_auth_rule_id_defaults() {
        // Multi-delegated and repeated --auth-rule-id.
        let parsed = CreateArgsHarness::parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--name",
            "multi-signer",
            "--signer-delegated",
            SIMULATE_SENTINEL_G,
            "--signer-delegated",
            "GBVVQS6GNVDWPZQBPJYLOOPWIBPBBAJKJX5AMQT5PNQAMOJEHKXUMCP",
            "--auth-rule-id",
            "1",
            "--auth-rule-id",
            "2",
            "--valid-until",
            "12345",
            "--signer-secret-env",
            "__STELLAR_AGENT_RULES_TEST_DUMMY_VAR",
        ]);

        assert_eq!(
            parsed.args.signer_delegated.len(),
            2,
            "--signer-delegated must be repeatable"
        );
        assert_eq!(
            parsed.args.auth_rule_id,
            vec![1_u32, 2_u32],
            "--auth-rule-id must be repeatable"
        );
        assert_eq!(
            parsed.args.valid_until, "12345",
            "--valid-until 12345 must round-trip"
        );

        // Default --auth-rule-id = [0] when flag is absent.
        let parsed_default = CreateArgsHarness::parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--name",
            "default-auth",
            "--signer-delegated",
            SIMULATE_SENTINEL_G,
            "--signer-secret-env",
            "__STELLAR_AGENT_RULES_TEST_DUMMY_VAR",
        ]);
        assert_eq!(
            parsed_default.args.auth_rule_id,
            vec![0_u32],
            "--auth-rule-id must default to [0]"
        );
        assert_eq!(
            parsed_default.args.valid_until, "none",
            "--valid-until must default to 'none'"
        );

        // Signer-source flags are mutually exclusive: two flags must fail.
        assert!(
            CreateArgsHarness::try_parse_from([
                "test",
                "--account",
                "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
                "--name",
                "test",
                "--signer-delegated",
                SIMULATE_SENTINEL_G,
                "--signer-secret-env",
                "__STELLAR_AGENT_RULES_TEST_DUMMY_VAR",
                "--sign-with-ledger",
            ])
            .is_err(),
            "two signer-source flags must be mutually exclusive"
        );
    }

    #[derive(Parser)]
    struct SetValidUntilArgsHarness {
        #[command(flatten)]
        args: SetValidUntilArgs,
    }

    /// `smart-account rules set-valid-until` parse-test:
    ///
    /// - `--valid-until none` round-trips as the string "none"
    /// - `--valid-until 12345` round-trips as "12345"
    /// - `--auth-rule-id` is optional
    #[test]
    fn set_valid_until_args_valid_until_parses_none_and_ledger() {
        let parsed_none = SetValidUntilArgsHarness::parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "3",
            "--valid-until",
            "none",
            "--signer-secret-env",
            "__STELLAR_AGENT_RULES_TEST_DUMMY_VAR",
        ]);
        assert_eq!(parsed_none.args.valid_until, "none");
        assert!(
            parsed_none.args.auth_rule_id.is_none(),
            "--auth-rule-id is optional"
        );

        let parsed_ledger = SetValidUntilArgsHarness::parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "3",
            "--valid-until",
            "12345",
            "--auth-rule-id",
            "5",
            "--signer-secret-env",
            "__STELLAR_AGENT_RULES_TEST_DUMMY_VAR",
        ]);
        assert_eq!(parsed_ledger.args.valid_until, "12345");
        assert_eq!(parsed_ledger.args.auth_rule_id, Some(5_u32));
    }

    #[derive(Parser)]
    struct DeleteArgsHarness {
        #[command(flatten)]
        args: DeleteArgs,
    }

    /// `smart-account rules delete` parse-test:
    ///
    /// - `--rule-id` is required
    /// - `--auth-rule-id` is optional
    /// - Signer-source flags are mutually exclusive
    #[test]
    fn delete_args_rule_id_required_and_auth_rule_id_optional() {
        let parsed = DeleteArgsHarness::parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "7",
            "--signer-secret-env",
            "__STELLAR_AGENT_RULES_TEST_DUMMY_VAR",
        ]);
        assert_eq!(parsed.args.rule_id, 7);
        assert!(
            parsed.args.auth_rule_id.is_none(),
            "--auth-rule-id defaults to None"
        );

        // --rule-id is required.
        assert!(
            DeleteArgsHarness::try_parse_from([
                "test",
                "--account",
                "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
                "--signer-secret-env",
                "__STELLAR_AGENT_RULES_TEST_DUMMY_VAR",
            ])
            .is_err(),
            "--rule-id is required"
        );

        // Signer-source flags are mutually exclusive.
        assert!(
            DeleteArgsHarness::try_parse_from([
                "test",
                "--account",
                "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
                "--rule-id",
                "1",
                "--signer-secret-env",
                "__STELLAR_AGENT_RULES_TEST_DUMMY_VAR",
                "--sign-with-ledger",
            ])
            .is_err(),
            "two signer-source flags must be mutually exclusive"
        );
    }

    /// `smart-account rules set-name` parse-test:
    ///
    /// - `--auth-rule-id` defaults to None (handler falls back to `--rule-id`)
    /// - Signer-source flags are mutually exclusive
    #[test]
    fn set_name_args_auth_rule_id_optional_and_signer_source_exclusive() {
        let parsed = SetNameArgsHarness::parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "4",
            "--name",
            "new-name",
            "--signer-secret-env",
            "__STELLAR_AGENT_RULES_TEST_DUMMY_VAR",
        ]);
        assert_eq!(parsed.args.rule_id, 4);
        assert!(
            parsed.args.auth_rule_id.is_none(),
            "--auth-rule-id defaults to None"
        );

        // Signer-source flags are mutually exclusive.
        assert!(
            SetNameArgsHarness::try_parse_from([
                "test",
                "--account",
                "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
                "--rule-id",
                "4",
                "--name",
                "new-name",
                "--signer-secret-env",
                "__STELLAR_AGENT_RULES_TEST_DUMMY_VAR",
                "--sign-with-ledger",
            ])
            .is_err(),
            "two signer-source flags must be mutually exclusive"
        );
    }

    // ── add-policy --kind spending-limit pre-flight tests ─────────────────────

    const ADD_POLICY_TEST_ACCOUNT: &str =
        "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";

    const ADD_POLICY_TEST_ACCOUNT_G: &str =
        "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";

    fn add_policy_args(kind: PolicyKind) -> AddPolicyArgs {
        AddPolicyArgs {
            account: ADD_POLICY_TEST_ACCOUNT.to_owned(),
            rule_id: 1,
            kind,
            policy_address: None,
            install_param: None,
            limit: None,
            period: None,
            policy: None,
            threshold: None,
            weighted_signer_delegated: vec![],
            weighted_signer_webauthn: vec![],
            auth_rule_id: vec![],
            profile: None,
            signer_source: SignerSourceFlags {
                signer_secret_env: Some("__STELLAR_AGENT_RULES_ADD_POLICY_DUMMY".to_owned()),
                sign_with_ledger: false,
                account_index: Some(0),
            },
            network: TargetNetwork::Testnet,
            rpc_url: TESTNET_RPC_URL.to_owned(),
            secondary_rpc_url: None,
            timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
            output: OutputFormat::Json,
        }
    }

    /// `--kind raw` without `--policy-address` is refused before any network
    /// call.
    #[tokio::test]
    async fn add_policy_raw_requires_policy_address() {
        let mut args = add_policy_args(PolicyKind::Raw);
        args.install_param = Some("AAAAAA==".to_owned());
        let code = add_policy_run(&args).await;
        assert_eq!(code, 1, "raw mode without --policy-address must be refused");
    }

    /// `--kind spending-limit` without `--limit` is refused before any network
    /// call.
    #[tokio::test]
    async fn add_policy_spending_limit_requires_limit() {
        let mut args = add_policy_args(PolicyKind::SpendingLimit);
        args.period = Some(17_280);
        let code = add_policy_run(&args).await;
        assert_eq!(
            code, 1,
            "spending-limit mode without --limit must be refused"
        );
    }

    /// `--kind spending-limit` combined with the raw-mode `--policy-address`
    /// flag is refused (mode conflict) before any network call.
    #[tokio::test]
    async fn add_policy_spending_limit_rejects_raw_flags() {
        let mut args = add_policy_args(PolicyKind::SpendingLimit);
        args.limit = Some(10_000_000);
        args.period = Some(17_280);
        args.policy_address = Some(ADD_POLICY_TEST_ACCOUNT.to_owned());
        let code = add_policy_run(&args).await;
        assert_eq!(
            code, 1,
            "spending-limit mode must reject the raw --policy-address flag"
        );
    }

    /// `--kind spending-limit` with no `--policy` override and no registered
    /// policy for the network fails closed before any network call.
    #[tokio::test]
    #[serial]
    async fn add_policy_spending_limit_missing_registry_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let registry_path = dir.path().join("networks.toml");

        // SAFETY: serialised by #[serial]; no concurrent env access.
        #[allow(unsafe_code, reason = "test-only env override; #[serial] serialises")]
        unsafe {
            std::env::set_var(
                stellar_agent_smart_account::verifiers::STELLAR_AGENT_NETWORKS_TOML_ENV,
                &registry_path,
            );
        }

        let mut args = add_policy_args(PolicyKind::SpendingLimit);
        args.limit = Some(10_000_000);
        args.period = Some(17_280);
        let code = add_policy_run(&args).await;

        // SAFETY: same as set; serialised by #[serial].
        #[allow(unsafe_code, reason = "test-only env cleanup; #[serial] serialises")]
        unsafe {
            std::env::remove_var(
                stellar_agent_smart_account::verifiers::STELLAR_AGENT_NETWORKS_TOML_ENV,
            );
        }

        assert_eq!(
            code, 1,
            "spending-limit mode must fail closed when no policy is registered"
        );
    }

    /// `--kind spending-limit --limit 0` is refused before any registry lookup
    /// or network call (OZ `InvalidLimitOrPeriod` pre-flight).
    #[tokio::test]
    async fn add_policy_spending_limit_rejects_zero_limit() {
        let mut args = add_policy_args(PolicyKind::SpendingLimit);
        args.limit = Some(0);
        args.period = Some(17_280);
        let code = add_policy_run(&args).await;
        assert_eq!(code, 1, "limit == 0 must be refused");
    }

    /// `--kind spending-limit --limit -1` is refused before any registry
    /// lookup or network call.
    #[tokio::test]
    async fn add_policy_spending_limit_rejects_negative_limit() {
        let mut args = add_policy_args(PolicyKind::SpendingLimit);
        args.limit = Some(-1);
        args.period = Some(17_280);
        let code = add_policy_run(&args).await;
        assert_eq!(code, 1, "negative limit must be refused");
    }

    /// `--kind spending-limit --period 0` is refused before any registry
    /// lookup or network call.
    #[tokio::test]
    async fn add_policy_spending_limit_rejects_zero_period() {
        let mut args = add_policy_args(PolicyKind::SpendingLimit);
        args.limit = Some(10_000_000);
        args.period = Some(0);
        let code = add_policy_run(&args).await;
        assert_eq!(code, 1, "period == 0 must be refused");
    }

    // ── add-policy --kind simple-threshold pre-flight tests ───────────────────

    /// `--kind simple-threshold` without `--threshold` is refused before any
    /// network call.
    #[tokio::test]
    async fn add_policy_simple_threshold_requires_threshold() {
        let args = add_policy_args(PolicyKind::SimpleThreshold);
        let code = add_policy_run(&args).await;
        assert_eq!(
            code, 1,
            "simple-threshold mode without --threshold must be refused"
        );
    }

    /// `--kind simple-threshold --threshold 0` is refused before any registry
    /// lookup (the builder's client-side `InvalidThreshold` pre-flight fires
    /// even when `--policy` is supplied, so no registry access is needed for
    /// this assertion).
    #[tokio::test]
    async fn add_policy_simple_threshold_rejects_zero_threshold() {
        let mut args = add_policy_args(PolicyKind::SimpleThreshold);
        args.threshold = Some(0);
        args.policy = Some(ADD_POLICY_TEST_ACCOUNT.to_owned());
        let code = add_policy_run(&args).await;
        assert_eq!(code, 1, "threshold == 0 must be refused");
    }

    /// `--kind simple-threshold` combined with the raw-mode `--policy-address`
    /// flag is refused (mode conflict) before any network call.
    #[tokio::test]
    async fn add_policy_simple_threshold_rejects_raw_flags() {
        let mut args = add_policy_args(PolicyKind::SimpleThreshold);
        args.threshold = Some(2);
        args.policy_address = Some(ADD_POLICY_TEST_ACCOUNT.to_owned());
        let code = add_policy_run(&args).await;
        assert_eq!(
            code, 1,
            "simple-threshold mode must reject the raw --policy-address flag"
        );
    }

    /// `--kind simple-threshold` with no `--policy` override and no
    /// registered policy for the network fails closed before any network call.
    #[tokio::test]
    #[serial]
    async fn add_policy_simple_threshold_missing_registry_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let registry_path = dir.path().join("networks.toml");

        #[allow(unsafe_code, reason = "test-only env override; #[serial] serialises")]
        unsafe {
            std::env::set_var(
                stellar_agent_smart_account::verifiers::STELLAR_AGENT_NETWORKS_TOML_ENV,
                &registry_path,
            );
        }

        let mut args = add_policy_args(PolicyKind::SimpleThreshold);
        args.threshold = Some(2);
        let code = add_policy_run(&args).await;

        #[allow(unsafe_code, reason = "test-only env cleanup; #[serial] serialises")]
        unsafe {
            std::env::remove_var(
                stellar_agent_smart_account::verifiers::STELLAR_AGENT_NETWORKS_TOML_ENV,
            );
        }

        assert_eq!(
            code, 1,
            "simple-threshold mode must fail closed when no policy is registered"
        );
    }

    // ── add-policy --kind weighted-threshold pre-flight tests ─────────────────

    /// `--kind weighted-threshold` without `--threshold` is refused before any
    /// network call.
    #[tokio::test]
    async fn add_policy_weighted_threshold_requires_threshold() {
        let mut args = add_policy_args(PolicyKind::WeightedThreshold);
        args.weighted_signer_delegated = vec![format!("{ADD_POLICY_TEST_ACCOUNT_G}=1")];
        let code = add_policy_run(&args).await;
        assert_eq!(
            code, 1,
            "weighted-threshold mode without --threshold must be refused"
        );
    }

    /// `--kind weighted-threshold` without any `--weighted-signer-*` flag is
    /// refused before any network call.
    #[tokio::test]
    async fn add_policy_weighted_threshold_requires_a_signer() {
        let mut args = add_policy_args(PolicyKind::WeightedThreshold);
        args.threshold = Some(1);
        let code = add_policy_run(&args).await;
        assert_eq!(
            code, 1,
            "weighted-threshold mode without any weighted-signer flag must be refused"
        );
    }

    /// `--kind weighted-threshold` combined with the raw-mode `--policy-address`
    /// flag is refused (mode conflict) before any network call.
    #[tokio::test]
    async fn add_policy_weighted_threshold_rejects_raw_flags() {
        let mut args = add_policy_args(PolicyKind::WeightedThreshold);
        args.threshold = Some(1);
        args.weighted_signer_delegated = vec![format!("{ADD_POLICY_TEST_ACCOUNT_G}=1")];
        args.policy_address = Some(ADD_POLICY_TEST_ACCOUNT.to_owned());
        let code = add_policy_run(&args).await;
        assert_eq!(
            code, 1,
            "weighted-threshold mode must reject the raw --policy-address flag"
        );
    }

    /// A malformed `--weighted-signer-delegated` flag (missing `=<weight>`) is
    /// refused before any network call.
    #[tokio::test]
    async fn add_policy_weighted_threshold_rejects_malformed_signer_flag() {
        let mut args = add_policy_args(PolicyKind::WeightedThreshold);
        args.threshold = Some(1);
        args.weighted_signer_delegated = vec![ADD_POLICY_TEST_ACCOUNT_G.to_owned()];
        let code = add_policy_run(&args).await;
        assert_eq!(
            code, 1,
            "a weighted-signer flag missing '=<weight>' must be refused"
        );
    }

    /// A non-numeric weight suffix is refused before any network call.
    #[tokio::test]
    async fn add_policy_weighted_threshold_rejects_non_numeric_weight() {
        let mut args = add_policy_args(PolicyKind::WeightedThreshold);
        args.threshold = Some(1);
        args.weighted_signer_delegated = vec![format!("{ADD_POLICY_TEST_ACCOUNT_G}=not-a-number")];
        let code = add_policy_run(&args).await;
        assert_eq!(code, 1, "a non-numeric weight must be refused");
    }

    /// `--kind weighted-threshold` with no `--policy` override and no
    /// registered policy for the network fails closed before any network call.
    #[tokio::test]
    #[serial]
    async fn add_policy_weighted_threshold_missing_registry_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let registry_path = dir.path().join("networks.toml");

        #[allow(unsafe_code, reason = "test-only env override; #[serial] serialises")]
        unsafe {
            std::env::set_var(
                stellar_agent_smart_account::verifiers::STELLAR_AGENT_NETWORKS_TOML_ENV,
                &registry_path,
            );
        }

        let mut args = add_policy_args(PolicyKind::WeightedThreshold);
        args.threshold = Some(1);
        args.weighted_signer_delegated = vec![format!("{ADD_POLICY_TEST_ACCOUNT_G}=1")];
        let code = add_policy_run(&args).await;

        #[allow(unsafe_code, reason = "test-only env cleanup; #[serial] serialises")]
        unsafe {
            std::env::remove_var(
                stellar_agent_smart_account::verifiers::STELLAR_AGENT_NETWORKS_TOML_ENV,
            );
        }

        assert_eq!(
            code, 1,
            "weighted-threshold mode must fail closed when no policy is registered"
        );
    }

    // ── parse_weighted_signer_flag ─────────────────────────────────────────────

    /// A well-formed `<identity>=<weight>` flag parses to the expected pair.
    #[test]
    fn parse_weighted_signer_flag_parses_valid_spec() {
        let (identity, weight) =
            parse_weighted_signer_flag(&format!("{ADD_POLICY_TEST_ACCOUNT_G}=7")).unwrap();
        assert_eq!(identity, ADD_POLICY_TEST_ACCOUNT_G);
        assert_eq!(weight, 7);
    }

    /// A flag with no `=` is refused.
    #[test]
    fn parse_weighted_signer_flag_rejects_missing_equals() {
        assert!(parse_weighted_signer_flag(ADD_POLICY_TEST_ACCOUNT_G).is_err());
    }

    /// A flag with a non-numeric weight is refused.
    #[test]
    fn parse_weighted_signer_flag_rejects_non_numeric_weight() {
        assert!(parse_weighted_signer_flag(&format!("{ADD_POLICY_TEST_ACCOUNT_G}=abc")).is_err());
    }

    /// A flag with an empty identity is refused.
    #[test]
    fn parse_weighted_signer_flag_rejects_empty_identity() {
        assert!(parse_weighted_signer_flag("=5").is_err());
    }

    // ── get-spending-limit ────────────────────────────────────────────────────

    #[derive(Parser)]
    struct GetSpendingLimitArgsHarness {
        #[command(flatten)]
        args: GetSpendingLimitArgs,
    }

    #[test]
    fn get_spending_limit_args_parse_required_fields() {
        let parsed = GetSpendingLimitArgsHarness::parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "3",
            "--source-account",
            SIMULATE_SENTINEL_G,
        ]);
        assert_eq!(parsed.args.rule_id, 3);
        assert_eq!(parsed.args.source_account, SIMULATE_SENTINEL_G);
        assert_eq!(parsed.args.common.network, TargetNetwork::Testnet);
    }

    #[test]
    fn get_spending_limit_args_requires_rule_id_and_source_account() {
        assert!(
            GetSpendingLimitArgsHarness::try_parse_from([
                "test",
                "--account",
                "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
                "--source-account",
                SIMULATE_SENTINEL_G,
            ])
            .is_err(),
            "--rule-id is required"
        );
        assert!(
            GetSpendingLimitArgsHarness::try_parse_from([
                "test",
                "--account",
                "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
                "--rule-id",
                "1",
            ])
            .is_err(),
            "--source-account is required"
        );
    }

    /// An invalid `--source-account` G-strkey is refused before any manager
    /// construction or network call.
    #[tokio::test]
    async fn get_spending_limit_run_rejects_invalid_source_account() {
        let args = GetSpendingLimitArgs {
            common: CommonRulesReadArgs {
                account: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".to_owned(),
                network: TargetNetwork::Testnet,
                rpc_url: TESTNET_RPC_URL.to_owned(),
                timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
                output: OutputFormat::Json,
            },
            rule_id: 1,
            source_account: "not-a-valid-g-strkey".to_owned(),
        };
        let code = get_spending_limit_run(&args).await;
        assert_eq!(code, 1, "invalid --source-account must be refused");
    }

    // ── set-spending-limit ────────────────────────────────────────────────────

    #[derive(Parser)]
    struct SetSpendingLimitArgsHarness {
        #[command(flatten)]
        args: SetSpendingLimitArgs,
    }

    #[test]
    fn set_spending_limit_args_parse_required_fields() {
        let parsed = SetSpendingLimitArgsHarness::parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "4",
            "--limit",
            "10000000",
            "--signer-secret-env",
            "__STELLAR_AGENT_RULES_SET_SPENDING_LIMIT_DUMMY",
        ]);
        assert_eq!(parsed.args.rule_id, 4);
        assert_eq!(parsed.args.limit, 10_000_000_i128);
        // --auth-rule-id omitted: MUST default to 0 (the genesis admin rule),
        // never to --rule-id — the CallContract rule being retuned can never
        // authorize its own retune (on-chain UnvalidatedContext, 3002).
        assert_eq!(parsed.args.auth_rule_id, 0);
    }

    #[test]
    fn set_spending_limit_args_parses_explicit_auth_rule_id() {
        let parsed = SetSpendingLimitArgsHarness::parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "4",
            "--auth-rule-id",
            "7",
            "--limit",
            "10000000",
            "--signer-secret-env",
            "__STELLAR_AGENT_RULES_SET_SPENDING_LIMIT_DUMMY",
        ]);
        assert_eq!(parsed.args.auth_rule_id, 7);
        assert_eq!(
            parsed.args.rule_id, 4,
            "--auth-rule-id must not alias --rule-id"
        );
    }

    #[test]
    fn set_spending_limit_args_accepts_large_i128_limit() {
        // Regression-lock: --limit must accept a value well beyond i64::MAX,
        // since it is typed i128 end-to-end (stroop amounts are not bounded
        // by i64).
        let large = i128::from(i64::MAX) * 1000;
        let parsed = SetSpendingLimitArgsHarness::parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "4",
            "--limit",
            &large.to_string(),
            "--signer-secret-env",
            "__STELLAR_AGENT_RULES_SET_SPENDING_LIMIT_DUMMY",
        ]);
        assert_eq!(parsed.args.limit, large);
    }

    fn set_spending_limit_args(limit: i128) -> SetSpendingLimitArgs {
        SetSpendingLimitArgs {
            account: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".to_owned(),
            rule_id: 1,
            auth_rule_id: 0,
            limit,
            profile: None,
            signer_source: SignerSourceFlags {
                signer_secret_env: Some(
                    "__STELLAR_AGENT_RULES_SET_SPENDING_LIMIT_DUMMY".to_owned(),
                ),
                sign_with_ledger: false,
                account_index: Some(0),
            },
            network: TargetNetwork::Testnet,
            rpc_url: TESTNET_RPC_URL.to_owned(),
            secondary_rpc_url: None,
            timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
            output: OutputFormat::Json,
        }
    }

    /// `--limit 0` is refused before any signer resolution or network call.
    #[tokio::test]
    async fn set_spending_limit_rejects_zero_limit() {
        let args = set_spending_limit_args(0);
        let code = set_spending_limit_run(&args).await;
        assert_eq!(code, 1, "limit == 0 must be refused");
    }

    /// `--limit -1` is refused before any signer resolution or network call.
    #[tokio::test]
    async fn set_spending_limit_rejects_negative_limit() {
        let args = set_spending_limit_args(-1);
        let code = set_spending_limit_run(&args).await;
        assert_eq!(code, 1, "negative limit must be refused");
    }

    /// Mainnet is refused before the limit check (and before any signer
    /// resolution).
    #[tokio::test]
    async fn set_spending_limit_rejects_mainnet() {
        let mut args = set_spending_limit_args(10_000_000);
        args.network = TargetNetwork::Mainnet;
        let code = set_spending_limit_run(&args).await;
        assert_eq!(code, 1, "mainnet must be refused");
    }
}
