//! `stellar-agent smart-account migrate-verifier` subcommand.
//!
//! Constructs a [`MigrationPlan`] for migrating all `External` signers on a
//! smart account from a source verifier (`--from <HASH_HEX>`) to a destination
//! verifier contract (`--to <C_STRKEY>`), then either:
//!
//! - **Dry-run** (`--dry-run`): renders the plan as a JSON envelope without
//!   submitting any transactions.
//! - **Submit** (default): signs + submits each `remove_signer` / `add_signer`
//!   pair sequentially, each pair under its rule's lock as two checked signer
//!   mutations, and renders a `MigrateVerifierResult` with per-step tx hashes.
//!   A failure after a pair's removal was sent renders the pending add and
//!   prints, before the JSON envelope, the command that completes the pair.
//!
//! # Flags
//!
//! | Flag | Required | Description |
//! |------|----------|-------------|
//! | `--account <C_STRKEY>` | yes | Smart-account contract address. |
//! | `--from <HASH_HEX>` | yes | 64-char hex SHA-256 of the source verifier WASM. |
//! | `--to <C_STRKEY>` | yes | Destination verifier contract address. |
//! | `--dry-run` | no | Plan-only: no transactions submitted. |
//! | `--signer-secret-env <VAR>` | yes (submit) | Env-var holding the S-strkey seed. |
//! | `--sign-with-ledger` | yes (submit) | Ledger hardware-wallet signing. |
//! | `--network` | no | `testnet` (default) or `mainnet`. |
//! | `--rpc-url` | no | Soroban RPC endpoint. |
//! | `--secondary-rpc-url` | no | Secondary RPC for two-RPC consultation. |
//! | `--timeout-seconds` | no | Submission timeout (default 60). |
//!
//! # Mainnet refusal
//!
//! Dry-run mode allows mainnet (read-only).  On-chain submit structurally
//! refuses mainnet before any signing, key access, or RPC call, with the same
//! wire code as every other write surface:
//! `WalletError::Network(NetworkError::MainnetWriteForbidden)`
//! (`network.mainnet_write_forbidden`).
//!
//! # Pre-flight gates (fail-CLOSED)
//!
//! All three pre-flight gates are enforced inside [`MigrationPlanner::build`]:
//!
//! 1. Destination verifier hash MUST be in [`stellar_agent_smart_account::VERIFIER_ALLOWLIST`].
//! 2. Destination audit status MUST be `Audited`, `Provisional`, or `Unaudited`.
//! 3. Destination contract MUST be immutable (no admin/owner key).
//!
//! # Wire codes rendered
//!
//! - `sa.audit_log`: `SaError::AuditLog`
//! - `sa.contract_instance_unsupported`: `SaError::ContractInstanceUnsupported`
//! - `sa.threshold_read_failed`: `SaError::ThresholdReadFailed`
//! - `sa.deployment_failed`: `SaError::DeploymentFailed`
//! - `network.mainnet_write_forbidden` — structural mainnet-submit refusal
//! - `sa.verifier_migration_failed` — [`SaError::VerifierMigrationFailed`]
//! - `sa.verifier_wasm_revoked` — [`SaError::VerifierWasmRevoked`]
//! - `sa.verifier_wasm_retired` — [`SaError::VerifierWasmRetired`]
//! - `network.rpc_divergence` — [`SaError::NetworkRpcDivergence`]
//! - `sa.signer_set_missing_baseline`: [`SaError::SignerSetMissingBaseline`]
//! - `sa.signer_set_baseline_legacy`: [`SaError::SignerSetBaselineLegacy`]
//! - `sa.signer_set_diverged`: [`SaError::SignerSetDiverged`]
//! - `sa.baseline_write_failed`: [`SaError::BaselineWriteFailed`]
//! - `submission.tx_timeout`, `submission.tx_already_submitted`,
//!   `submission.hash_mismatch`: [`SaError::SubmissionUnresolved`], by kind
//! - `sa.policy_hash_drift`: [`SaError::PolicyHashDrift`], passed through by a step
//! - `sa.pinned_policy_absent`: [`SaError::PinnedPolicyAbsent`], passed through by a step
//! - `sa.pin_check_unavailable`: [`SaError::PinCheckUnavailable`], passed through by a step
//! - `sa.auth_entry_construction_failed`: [`SaError::AuthEntryConstructionFailed`],
//!   passed through by a step, including lock and signer-set deadline stages
//! - `sa.threshold_unreachable`: [`SaError::ThresholdUnreachable`]
//! - `sa.threshold_policy_identification_failed`:
//!   [`SaError::ThresholdPolicyIdentificationFailed`]

use clap::Args;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::{NetworkError, ValidationError, WalletError};
use stellar_agent_core::observability::redact_strkey_first5_last5;
use stellar_agent_core::profile::caip2::Caip2;
use stellar_agent_network::NetworkContext;
use stellar_agent_smart_account::error::SaError;
use stellar_agent_smart_account::managers::migration::{
    MigrationPlan, MigrationPlanner, MigrationSubmitResult, PendingAddStep, SignerMigrationStep,
};
use stellar_agent_smart_account::managers::rules::parse_c_strkey_to_smart_account;
use stellar_agent_smart_account::managers::signers::{
    DecodedOnChainSigner, SignersManager, decode_signer_scval_full,
};
use stellar_agent_smart_account::verifier_allowlist::VerifierAuditStatus;
use stellar_xdr::HostFunction;
use tracing::{info, warn};
use uuid::Uuid;

use crate::commands::smart_account::common::{
    CommonArgsView, CommonHandlerContext, SignerSourceFlags, construct_signers_manager_from_fields,
    load_command_profile, map_access_error, open_audit_writer_read_only, wrap_sa_error,
};
use crate::common::network::{
    EndpointFlags, EndpointUrlFlag, TargetNetwork, network_context_for_command,
};
use crate::common::render::render_json;
use crate::common::resolve_profile_name;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Default submission timeout in seconds.
const DEFAULT_TIMEOUT_SECONDS: u64 = 60;

// ─────────────────────────────────────────────────────────────────────────────
// CLI Args
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for `smart-account migrate-verifier`.
///
/// Default mode is on-chain submit (requires a signer-source flag).
/// Pass `--dry-run` for plan-only output with no transactions submitted.
#[non_exhaustive]
#[derive(Debug, Args)]
#[command(
    override_usage = "stellar-agent smart-account migrate-verifier \
        --account <C_STRKEY> --from <HASH_HEX> --to <C_STRKEY> \
        [--dry-run] \
        [ { --signer-secret-env <VAR> | --sign-with-ledger } ]",
    after_help = "SUBMIT PATH: Without --dry-run, provide exactly one of --signer-secret-env \
        or --sign-with-ledger. \
        Mainnet submit is structurally refused (network.mainnet_write_forbidden); \
        mainnet --dry-run is allowed (read-only). \
        Without --dry-run, transactions are submitted in pairs (remove_signer + add_signer \
        per affected External signer per context rule). \
\n\
INTER-TRANSACTION HAZARD: A migration with multiple affected External signers \
or multiple affected context rules produces more than 2 Soroban transactions. Between \
paired remove_signer / add_signer transactions the rule's signer set lacks the \
migrated signer. The `warnings` field in the JSON envelope is non-empty when \
total_transaction_count > 2. A failure between a pair's two transactions leaves a \
pending add: the result names the signers add command that completes it, and a re-run \
of migrate-verifier migrates the remaining signers."
)]
pub struct MigrateVerifierArgs {
    /// Smart-account contract C-strkey to migrate.
    #[arg(long, value_name = "C_STRKEY", required = true)]
    pub account: String,

    /// 64-char hex SHA-256 of the source verifier WASM to migrate away from.
    ///
    /// Only `External` signers whose verifier contract's on-chain WASM hash
    /// matches this value are included in the plan.
    #[arg(long, value_name = "HASH_HEX", required = true)]
    pub from: String,

    /// Destination verifier contract C-strkey to migrate to.
    ///
    /// The planner queries the WASM hash from chain and validates it against
    /// [`stellar_agent_smart_account::VERIFIER_ALLOWLIST`].
    #[arg(long = "to", value_name = "C_STRKEY", required = true)]
    pub to_verifier: String,

    /// Optional profile name for audit-log path resolution.
    #[arg(long, value_name = "NAME")]
    pub profile: Option<String>,

    /// Signer-source flags (mutually exclusive).
    ///
    /// Required for on-chain submit. Dry-run mode is read-only and does not
    /// require a signer-source flag.
    #[command(flatten)]
    pub signer_source: SignerSourceFlags,

    /// The network comes from the profile when absent.
    /// When supplied, this flag must equal the profile's chain.
    #[arg(long, value_name = "NETWORK")]
    pub network: Option<TargetNetwork>,

    /// The RPC endpoint comes from the profile when absent.
    /// On testnet, this flag overrides the profile endpoint.
    /// On mainnet, this flag is refused, including equal values.
    /// URL credentials are refused.
    #[arg(long, value_name = "URL", value_parser = EndpointUrlFlag)]
    pub rpc_url: Option<String>,

    /// The secondary endpoint comes from the profile when absent.
    /// On testnet, this flag overrides the profile endpoint.
    /// On mainnet, this flag is refused, including equal values.
    /// URL credentials are refused.
    #[arg(long, value_name = "URL", value_parser = EndpointUrlFlag)]
    pub secondary_rpc_url: Option<String>,

    /// Submission timeout in seconds.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECONDS, value_name = "SECONDS")]
    pub timeout_seconds: u64,

    /// Construct the migration plan without submitting any transactions.
    ///
    /// When set, the command performs all pre-flight checks (hash lookup,
    /// audit status, mutability) and returns the plan JSON envelope without
    /// signing or submitting any transactions.  Mainnet is allowed in dry-run
    /// mode (read-only RPC calls only).
    #[arg(long)]
    pub dry_run: bool,
}

impl CommonArgsView for MigrateVerifierArgs {
    fn account(&self) -> &str {
        &self.account
    }

    fn profile(&self) -> Option<&str> {
        self.profile.as_deref()
    }

    fn signer_source(&self) -> &SignerSourceFlags {
        &self.signer_source
    }

    fn network(&self) -> Option<TargetNetwork> {
        self.network
    }

    fn rpc_url(&self) -> Option<&str> {
        self.rpc_url.as_deref()
    }

    fn secondary_rpc_url(&self) -> Option<&str> {
        self.secondary_rpc_url.as_deref()
    }

    fn timeout_seconds(&self) -> u64 {
        self.timeout_seconds
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Result envelope types
// ─────────────────────────────────────────────────────────────────────────────

/// Per-step summary in the dry-run or submit result envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrateStepResult {
    /// On-chain signer ID.
    pub signer_id: u32,
    /// First-8 hex chars of the old verifier wasm hash.
    pub current_hash_first8: String,
    /// The key data the step's add restores on the destination verifier, as
    /// lower-case hex, taken from the plan's add argument. With
    /// `--signer-external <to_verifier_address>` it rebuilds the step's
    /// `signers add` from the plan alone. Empty only for an add argument that
    /// is not an `External` signer, which the planner never builds.
    pub key_data_hex: String,
    /// Confirmed 64-character `remove_signer` tx hash.
    ///
    /// `null` in dry-run mode; populated on submit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remove_tx_hash: Option<String>,
    /// Confirmed 64-character `add_signer` tx hash.
    ///
    /// `null` in dry-run mode; populated on submit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub add_tx_hash: Option<String>,
    /// The id the chain assigned to the restored signer; set for a
    /// completed pair.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_signer_id: Option<u32>,
}

/// The add that completes a pair whose removal was sent, in the result
/// envelope of a migration that stopped after the send.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigratePendingAdd {
    /// The rule the pair migrates.
    pub rule_id: u32,
    /// The id of the removed signer.
    pub signer_id: u32,
    /// The destination verifier C-strkey the add names.
    pub to_verifier_address: String,
    /// The removed signer's key data, as lower-case hex.
    pub key_data_hex: String,
    /// The removal's 64-character transaction hash.
    pub remove_tx_hash: String,
    /// Whether the removal confirmed; `false` only when its outcome is
    /// unknown.
    pub remove_confirmed: bool,
    /// The add's 64-character transaction hash, set only when the add was
    /// sent and its outcome is unknown.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub add_tx_hash: Option<String>,
    /// The `signers add` command that completes the pair, with the
    /// signer-source, `--profile`, `--network` and `--timeout-seconds` flags
    /// of the invocation. The endpoint flags are not echoed, since a URL can
    /// carry a credential; the operator adds those of the invocation.
    pub recovery_command: String,
}

/// Per-rule summary in the result envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrateRuleResult {
    /// Context-rule identifier.
    pub rule_id: u32,
    /// First-8 hex chars of the current verifier wasm hash for this rule.
    pub current_hash_first8: String,
    /// Number of on-chain transactions required for this rule (`2 * signer_steps`).
    pub transaction_count: usize,
    /// Per-signer steps within this rule.
    pub signer_steps: Vec<MigrateStepResult>,
}

/// Result envelope for `smart-account migrate-verifier`.
///
/// Shared by both dry-run and submit modes.  `dry_run: true` ↔ no tx hashes
/// in `affected_rules[*].signer_steps[*].{remove_tx_hash,add_tx_hash}`.
///
/// On partial failure, `failed_step_index` is set and `submitted_steps_count`
/// reflects the number of successfully completed signer-step pairs before the
/// failure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrateVerifierResult {
    /// Smart-account C-strkey.
    pub smart_account: String,
    /// First-8 hex chars of the source verifier WASM hash.
    pub from_hash_first8: String,
    /// First-8 hex chars of the destination verifier WASM hash (queried from chain).
    pub to_hash_first8: String,
    /// Destination verifier C-strkey (caller-supplied `--to`).
    pub to_verifier_address: String,
    /// Destination verifier audit status label.
    ///
    /// Format: `"audited:<YYYY-MM-DD>"`, `"provisional:<YYYY-MM-DD>"`, `"unaudited"`.
    /// Pre-flight refuses `revoked` and `retired`.
    pub destination_audit_status: String,
    /// Total number of on-chain transactions required (or that would be required
    /// in dry-run mode).
    pub total_transaction_count: usize,
    /// Per-rule migration entries.
    pub affected_rules: Vec<MigrateRuleResult>,
    /// Number of signer-step pairs successfully submitted.
    ///
    /// `0` in dry-run mode.
    pub submitted_steps_count: usize,
    /// Zero-based index of the first step that failed.
    ///
    /// `null` on complete success or in dry-run mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failed_step_index: Option<usize>,
    /// The confirmed remove tx hash of the failed pair, when its removal
    /// confirmed and its add did not. A removal whose outcome is unknown
    /// carries its hash in `pending_add` alone.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failed_step_remove_tx_hash: Option<String>,
    /// The add that completes the failed pair, when its removal was sent and
    /// its add did not confirm.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending_add: Option<MigratePendingAdd>,
    /// Whether this is a dry-run (no transactions submitted).
    pub dry_run: bool,
    /// Per-request correlation UUID.
    pub request_id: String,
    /// CAIP-2 chain identifier (e.g. `"stellar:testnet"`).
    ///
    /// Mirrors the `chain_id` field on `VerifyPinsResult`.
    pub chain_id: String,
    /// Operator advisories.
    ///
    /// Non-empty when `total_transaction_count > 2`.  Contains the
    /// inter-transaction failure-mode advisory.
    pub warnings: Vec<String>,
    /// Number of rule IDs the enumeration skipped during the `plan_build`
    /// phase: IDs whose `get_rule` simulation failed, plus deleted or
    /// unallocated IDs below the scan bound. A rule the wallet cannot read in
    /// full refuses the plan and is never counted here.
    pub rules_skipped_count: usize,
}

// ─────────────────────────────────────────────────────────────────────────────
// run
// ─────────────────────────────────────────────────────────────────────────────

/// Builds a read-only [`SignersManager`] for the dry-run path.
///
/// Opens the audit writer via [`open_audit_writer_read_only`] then constructs the manager
/// via [`construct_signers_manager_from_fields`].  Does not resolve a signer source.
///
/// # Errors
///
/// - Audit-log directory creation or [`stellar_agent_core::audit_log::writer::AuditWriter::open`]
///   fails → propagated from [`open_audit_writer_read_only`].
/// - [`stellar_agent_smart_account::managers::signers::SignersManager::new`] fails →
///   propagated from [`construct_signers_manager_from_fields`].
fn dry_run_signers_manager(
    context: &NetworkContext,
    args: &MigrateVerifierArgs,
    profile: &stellar_agent_core::profile::Profile,
    origin: crate::common::profile_access::ProfileOrigin,
    resolved_profile: &crate::common::ResolvedProfileName,
) -> Result<(SignersManager, String), WalletError> {
    let profile_name = resolved_profile.name.clone();
    let chain_id = context.chain_id.caip2_str().to_owned();
    let timeout = Duration::from_secs(args.timeout_seconds);
    let (audit_writer, audit_log_path) =
        open_audit_writer_read_only(profile, origin, &resolved_profile.name)?;
    let manager = construct_signers_manager_from_fields(
        &profile_name,
        context,
        timeout,
        audit_writer,
        &audit_log_path,
    )?;
    Ok((manager, chain_id))
}

/// Runs `smart-account migrate-verifier`.
///
/// Returns an exit code: `0` on success, `1` on any error.
///
/// # Errors
///
/// Never returns `Err` — all errors are captured into the envelope and exit code.
///
/// # Panics
///
/// Never panics.
pub async fn run(args: &MigrateVerifierArgs) -> i32 {
    let request_id = Uuid::new_v4().to_string();
    let resolved_profile = resolve_profile_name(args.profile.as_deref());
    let (profile, origin) = match load_command_profile(&resolved_profile) {
        Ok(loaded) => loaded,
        Err(error) => {
            let e = map_access_error(&error, &resolved_profile.name);
            return emit_error(&e, &request_id);
        }
    };
    let context = match network_context_for_command(
        &profile,
        &resolved_profile.name,
        EndpointFlags {
            network: args.network,
            rpc_url: args.rpc_url.as_deref(),
            secondary_rpc_url: args.secondary_rpc_url.as_deref(),
        },
    ) {
        Ok(context) => context,
        Err(e) => {
            return emit_error(&e, &request_id);
        }
    };

    // The context has passed the flag rules. Submit refuses mainnet before
    // signer access or RPC. Dry-run on mainnet stays allowed
    // (read-only).
    if let Some(err) = mainnet_submit_refusal(context.chain_id, args.dry_run) {
        return emit_error(&err, &request_id);
    }

    // Parse the `--from` hex hash.
    let from_hash = match parse_hex_hash(&args.from) {
        Ok(h) => h,
        Err(detail) => {
            return emit_error(
                &WalletError::Validation(ValidationError::AddressInvalid {
                    input: format!("--from: {detail}"),
                }),
                &request_id,
            );
        }
    };

    // Parse the `--to` destination verifier C-strkey.
    let to_verifier_addr = match parse_c_strkey_to_smart_account(&args.to_verifier) {
        Ok(a) => a,
        Err(e) => {
            return emit_error(
                &WalletError::Validation(ValidationError::AddressInvalid {
                    input: format!("--to: {e}"),
                }),
                &request_id,
            );
        }
    };

    let smart_account_addr = match parse_c_strkey_to_smart_account(&args.account) {
        Ok(a) => a,
        Err(e) => {
            return emit_error(
                &WalletError::Validation(ValidationError::AddressInvalid {
                    input: format!("--account: {e}"),
                }),
                &request_id,
            );
        }
    };

    if args.dry_run {
        let (manager, chain_id) =
            match dry_run_signers_manager(&context, args, &profile, origin, &resolved_profile) {
                Ok(ctx) => ctx,
                Err(e) => return emit_error(&e, &request_id),
            };

        info!(
            account = %redact_strkey_first5_last5(&args.account),
            to_verifier = %redact_strkey_first5_last5(&args.to_verifier),
            dry_run = args.dry_run,
            request_id = %request_id,
            "smart-account migrate-verifier: building migration plan"
        );

        let planner = MigrationPlanner::new(&manager);
        let plan = match planner
            .build(smart_account_addr, from_hash, to_verifier_addr, &request_id)
            .await
        {
            Ok(p) => p,
            Err(e) => return emit_error_sa(&e, &request_id),
        };

        info!(
            account = %redact_strkey_first5_last5(&args.account),
            from_hash_first8 = %plan.from_hash_first8(),
            to_hash_first8 = %plan.to_hash_first8(),
            affected_rule_count = plan.affected_rules.len(),
            total_transaction_count = plan.total_transaction_count(),
            dry_run = args.dry_run,
            request_id = %request_id,
            "smart-account migrate-verifier: plan constructed"
        );

        let result =
            migration_plan_to_result_dry_run(&plan, &args.account, &args.to_verifier, &chain_id);
        return emit_success(&result, &request_id);
    }

    // Build handler context: resolves signer, opens audit writer, constructs RPC handles.
    let ctx =
        match CommonHandlerContext::new(args, resolved_profile, profile, origin, &context).await {
            Ok(ctx) => ctx,
            Err(e) => return emit_error(&e, &request_id),
        };

    // Build the SignersManager — needed by MigrationPlanner for RPC access.
    let manager = match ctx.signers_manager() {
        Ok(m) => m,
        Err(e) => return emit_error(&e, &request_id),
    };

    info!(
        account = %redact_strkey_first5_last5(&args.account),
        to_verifier = %redact_strkey_first5_last5(&args.to_verifier),
        dry_run = args.dry_run,
        request_id = %request_id,
        "smart-account migrate-verifier: building migration plan"
    );

    let planner = MigrationPlanner::new(&manager);
    let plan = match planner
        .build(
            ctx.smart_account.clone(),
            from_hash,
            to_verifier_addr,
            &request_id,
        )
        .await
    {
        Ok(p) => p,
        Err(e) => return emit_error_sa(&e, &request_id),
    };

    info!(
        account = %redact_strkey_first5_last5(&args.account),
        from_hash_first8 = %plan.from_hash_first8(),
        to_hash_first8 = %plan.to_hash_first8(),
        affected_rule_count = plan.affected_rules.len(),
        total_transaction_count = plan.total_transaction_count(),
        dry_run = args.dry_run,
        request_id = %request_id,
        "smart-account migrate-verifier: plan constructed"
    );

    // Submit path.
    if plan.affected_rules.is_empty() {
        // No affected rules — return early with empty success.
        warn!(
            account = %redact_strkey_first5_last5(&args.account),
            request_id = %request_id,
            "smart-account migrate-verifier: no affected rules found; nothing to submit"
        );
        let result = migration_plan_to_result_dry_run(
            &plan,
            &args.account,
            &args.to_verifier,
            ctx.context.chain_id.caip2_str(),
        );
        // Return as a submit result with 0 submitted steps.
        let mut submit_result = result;
        submit_result.dry_run = false;
        return emit_success(&submit_result, &request_id);
    }

    info!(
        account = %redact_strkey_first5_last5(&args.account),
        total_transaction_count = plan.total_transaction_count(),
        request_id = %request_id,
        "smart-account migrate-verifier: executing submit path"
    );

    let submit_result = plan
        .submit(ctx.signer.as_ref(), &manager, &request_id)
        .await;

    let result = migration_plan_to_result_submitted(
        &context,
        &plan,
        &submit_result,
        args,
        ctx.context.chain_id.caip2_str(),
    );

    // If the submission failed at any step, emit the error alongside the
    // partial result and return exit code 1.  The canonical
    // `Envelope::partial_failure_with_request_id` constructor is used so the
    // CLI emits a single JSON root carrying both `data` and `error` fields.
    // A pair that stopped after its removal was sent prints the command that
    // completes it first.
    if let Some(ref err) = submit_result.failed_step_error {
        if let Some(line) = partial_failure_recovery_line(&context, args, &result, err) {
            #[allow(
                clippy::print_stderr,
                reason = "the operator's recovery instruction, beside the JSON envelope on stdout"
            )]
            {
                eprintln!("{line}");
            }
        }
        let wrapped = WalletError::SmartAccount {
            wire_code: err.wire_code(),
            message: err.to_string(),
        };
        let partial = Envelope::partial_failure_with_request_id(result, &wrapped, request_id);
        render_json(&partial);
        return 1;
    }

    emit_success(&result, &request_id)
}

// ─────────────────────────────────────────────────────────────────────────────
// Private helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Structural mainnet-submit refusal, evaluated first in [`run`].
///
/// Dry-run on mainnet is allowed (read-only).  On-chain submit refuses mainnet
/// before any signing, key access, or RPC call: the network submit layer
/// forbids mainnet writes unconditionally in this alpha, so the command
/// surface refuses up front with the same wire code as every other write
/// surface (`network.mainnet_write_forbidden`).
fn mainnet_submit_refusal(network: Caip2, dry_run: bool) -> Option<WalletError> {
    (network.is_mainnet() && !dry_run)
        .then_some(WalletError::Network(NetworkError::MainnetWriteForbidden))
}

/// Parses a 64-char lowercase hex string into a 32-byte WASM hash.
///
/// # Errors
///
/// Returns a human-readable error string if the input is not exactly 64 hex chars
/// or contains non-hex characters.
fn parse_hex_hash(hex: &str) -> Result<[u8; 32], String> {
    let hex = hex.trim();
    if hex.len() != 64 {
        return Err(format!(
            "expected 64 hex chars (32-byte SHA-256), got {} chars: {:?}",
            hex.len(),
            hex
        ));
    }
    let mut out = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let hi = hex_nibble(chunk[0]).ok_or_else(|| {
            format!(
                "invalid hex char '{}' at position {}",
                chunk[0] as char,
                i * 2
            )
        })?;
        let lo = hex_nibble(chunk[1]).ok_or_else(|| {
            format!(
                "invalid hex char '{}' at position {}",
                chunk[1] as char,
                i * 2 + 1
            )
        })?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

/// Converts a single ASCII hex nibble to its numeric value.
fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Converts a [`MigrationPlan`] into a dry-run [`MigrateVerifierResult`].
fn migration_plan_to_result_dry_run(
    plan: &MigrationPlan,
    account_strkey: &str,
    to_verifier_strkey: &str,
    chain_id: &str,
) -> MigrateVerifierResult {
    let affected_rules = plan
        .affected_rules
        .iter()
        .map(|r| MigrateRuleResult {
            rule_id: r.rule_id,
            current_hash_first8: r.current_hash_first8.clone(),
            transaction_count: r.transaction_count(),
            signer_steps: r
                .signer_steps
                .iter()
                .map(|s| MigrateStepResult {
                    signer_id: s.signer_id,
                    current_hash_first8: s.current_hash_first8.clone(),
                    key_data_hex: add_step_key_data_hex(s),
                    remove_tx_hash: None,
                    add_tx_hash: None,
                    new_signer_id: None,
                })
                .collect(),
        })
        .collect();

    MigrateVerifierResult {
        smart_account: account_strkey.to_owned(),
        from_hash_first8: plan.from_hash_first8(),
        to_hash_first8: plan.to_hash_first8(),
        to_verifier_address: to_verifier_strkey.to_owned(),
        destination_audit_status: audit_status_label(&plan.destination_audit_status),
        total_transaction_count: plan.total_transaction_count(),
        affected_rules,
        submitted_steps_count: 0,
        failed_step_index: None,
        failed_step_remove_tx_hash: None,
        pending_add: None,
        dry_run: true,
        request_id: plan.request_id.clone(),
        chain_id: chain_id.to_owned(),
        warnings: plan.warnings.clone(),
        rules_skipped_count: plan.rules_skipped_count,
    }
}

/// Converts a [`MigrationPlan`] + [`MigrationSubmitResult`] into a
/// submitted [`MigrateVerifierResult`].
fn migration_plan_to_result_submitted(
    context: &NetworkContext,
    plan: &MigrationPlan,
    submit_result: &MigrationSubmitResult,
    args: &MigrateVerifierArgs,
    chain_id: &str,
) -> MigrateVerifierResult {
    // The submitted hashes and the assigned id of each pair, by
    // (rule_id, signer_id).
    let mut step_lookup: std::collections::HashMap<(u32, u32), SubmittedStep> = submit_result
        .successful_steps
        .iter()
        .map(|s| {
            (
                (s.rule_id, s.signer_id),
                SubmittedStep {
                    remove_tx_hash: Some(s.remove_tx_hash.clone()),
                    add_tx_hash: Some(s.add_tx_hash.clone()),
                    new_signer_id: Some(s.new_signer_id),
                },
            )
        })
        .collect();
    if let (Some(failed_index), Some(remove_tx_hash)) = (
        submit_result.failed_step_index,
        submit_result.failed_step_remove_tx_hash.as_deref(),
    ) && let Some((rule_id, signer_id)) = flattened_step_key(plan, failed_index)
    {
        step_lookup.insert(
            (rule_id, signer_id),
            SubmittedStep {
                remove_tx_hash: Some(remove_tx_hash.to_owned()),
                add_tx_hash: None,
                new_signer_id: None,
            },
        );
    }

    let affected_rules = plan
        .affected_rules
        .iter()
        .map(|r| MigrateRuleResult {
            rule_id: r.rule_id,
            current_hash_first8: r.current_hash_first8.clone(),
            transaction_count: r.transaction_count(),
            signer_steps: r
                .signer_steps
                .iter()
                .map(|s| {
                    let submitted = step_lookup.remove(&(r.rule_id, s.signer_id));
                    MigrateStepResult {
                        signer_id: s.signer_id,
                        current_hash_first8: s.current_hash_first8.clone(),
                        key_data_hex: add_step_key_data_hex(s),
                        remove_tx_hash: submitted
                            .as_ref()
                            .and_then(|step| step.remove_tx_hash.clone()),
                        add_tx_hash: submitted.as_ref().and_then(|step| step.add_tx_hash.clone()),
                        new_signer_id: submitted.and_then(|step| step.new_signer_id),
                    }
                })
                .collect(),
        })
        .collect();

    let pending_add = submit_result
        .pending_add
        .as_ref()
        .map(|pending| MigratePendingAdd {
            rule_id: pending.rule_id,
            signer_id: pending.signer_id,
            to_verifier_address: args.to_verifier.clone(),
            key_data_hex: hex::encode(&pending.key_data),
            remove_tx_hash: pending.remove_tx_hash.clone(),
            remove_confirmed: pending.remove_confirmed,
            add_tx_hash: pending.add_tx_hash.clone(),
            recovery_command: recovery_command(context, args, pending),
        });

    MigrateVerifierResult {
        smart_account: args.account.clone(),
        from_hash_first8: plan.from_hash_first8(),
        to_hash_first8: plan.to_hash_first8(),
        to_verifier_address: args.to_verifier.clone(),
        destination_audit_status: audit_status_label(&plan.destination_audit_status),
        total_transaction_count: plan.total_transaction_count(),
        affected_rules,
        submitted_steps_count: submit_result.successful_steps.len(),
        failed_step_index: submit_result.failed_step_index,
        failed_step_remove_tx_hash: submit_result.failed_step_remove_tx_hash.clone(),
        pending_add,
        dry_run: false,
        request_id: plan.request_id.clone(),
        chain_id: chain_id.to_owned(),
        warnings: plan.warnings.clone(),
        rules_skipped_count: plan.rules_skipped_count,
    }
}

/// What a submission recorded for one plan step.
struct SubmittedStep {
    remove_tx_hash: Option<String>,
    add_tx_hash: Option<String>,
    new_signer_id: Option<u32>,
}

/// The key data the add step of `step` restores, as lower-case hex: the
/// `Bytes` item of the `Signer::External` value the planner built. Empty
/// when the add argument is not an `External` signer.
fn add_step_key_data_hex(step: &SignerMigrationStep) -> String {
    let HostFunction::InvokeContract(invoke) = &step.add_host_function else {
        return String::new();
    };
    match invoke.args.get(1).map(decode_signer_scval_full) {
        Some(Ok(DecodedOnChainSigner::External { key_data, .. })) => hex::encode(key_data),
        _ => String::new(),
    }
}

/// `value` as one POSIX shell word: unchanged when it holds only characters
/// no shell interprets, otherwise single-quoted.
fn shell_word(value: &str) -> String {
    let plain = !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/' | ':' | '@'));
    if plain {
        value.to_owned()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

/// The signer-source, `--profile`, `--network` and `--timeout-seconds`
/// flags of the invocation, each preceded by a space. The endpoint flags
/// are omitted: a URL can carry a credential.
fn invocation_flags(context: &NetworkContext, args: &MigrateVerifierArgs) -> String {
    let mut flags = String::new();
    if let Some(var) = &args.signer_source.signer_secret_env {
        flags.push_str(&format!(" --signer-secret-env {}", shell_word(var)));
    } else if args.signer_source.sign_with_ledger {
        flags.push_str(&format!(
            " --sign-with-ledger --account-index {}",
            args.signer_source.account_index.unwrap_or(0)
        ));
    }
    if let Some(profile) = &args.profile {
        flags.push_str(&format!(" --profile {}", shell_word(profile)));
    }
    flags.push_str(&format!(
        " --network {} --timeout-seconds {}",
        if context.chain_id.is_mainnet() {
            "mainnet"
        } else {
            "testnet"
        },
        args.timeout_seconds
    ));
    flags
}

/// The `signers add` command that completes the pair of `pending`, with the
/// invocation's flags ([`invocation_flags`]). The destination is the `--to`
/// verifier the plan's destination was parsed from.
fn recovery_command(
    context: &NetworkContext,
    args: &MigrateVerifierArgs,
    pending: &PendingAddStep,
) -> String {
    format!(
        "stellar-agent smart-account signers add --account {} --rule-id {} \
         --signer-external {} --signer-key-data {}{}",
        shell_word(&args.account),
        pending.rule_id,
        shell_word(&args.to_verifier),
        hex::encode(&pending.key_data),
        invocation_flags(context, args),
    )
}

/// The `signers refresh --accept-divergence` command that records the chain
/// state of rule `rule_id`, with the invocation's flags.
fn refresh_command(context: &NetworkContext, args: &MigrateVerifierArgs, rule_id: u32) -> String {
    format!(
        "stellar-agent smart-account signers refresh --account {} --rule-id {rule_id} \
         --accept-divergence{}",
        shell_word(&args.account),
        invocation_flags(context, args),
    )
}

/// One step of a printed recovery.
enum RecoveryStep {
    /// A command to run.
    Run(String),
    /// A re-run of `migrate-verifier` for the remaining signers of the rule.
    ReRunRemaining(u32),
}

/// Renders `steps` as one instruction, in order: the first as `run: <command>`
/// or the re-run, each later one as `then: <command>` or `then` and the
/// re-run, separated by commas.
fn render_steps(steps: &[RecoveryStep]) -> String {
    let rendered: Vec<String> = steps
        .iter()
        .enumerate()
        .map(|(position, step)| match (position, step) {
            (0, RecoveryStep::Run(command)) => format!("run: {command}"),
            (_, RecoveryStep::Run(command)) => format!("then: {command}"),
            (0, RecoveryStep::ReRunRemaining(rule_id)) => {
                format!("re-run migrate-verifier for the remaining signers of rule {rule_id}")
            }
            (_, RecoveryStep::ReRunRemaining(rule_id)) => {
                format!("then re-run migrate-verifier for the remaining signers of rule {rule_id}")
            }
        })
        .collect();
    rendered.join(", ")
}

/// The stderr line that tells the operator how to complete the pair a
/// migration stopped on. `None` when it stopped before a removal was sent
/// (`result.pending_add` is `None`), and the error alone is printed.
///
/// The case is decided on the variant of `error`, the pair's error:
///
/// - [`SaError::BaselineWriteFailed`] and [`SaError::SignerSetDiverged`]:
///   the rule's newest state row is not the chain's state, so the refresh
///   comes first, then the `signers add`;
/// - [`SaError::SubmissionUnresolved`] of the removal: wait for the removal,
///   then the refresh and the `signers add`, or re-run the migration when the
///   removal is not found;
/// - [`SaError::SubmissionUnresolved`] of the add: wait for the add, then the
///   refresh, or the `signers add` when the add is not found;
/// - every other error: the `signers add`.
///
/// When the plan holds a later step on the same rule that was not submitted,
/// the re-run for the remaining signers comes after the repair step and
/// before the `signers add`. The rule's pin record already names the
/// destination, so the `signers add` is refused with `sa.verifier_hash_drift`
/// while a source signer is still on the rule. The re-run compares the rule
/// with its newest state row, so it follows the refresh.
fn partial_failure_recovery_line(
    context: &NetworkContext,
    args: &MigrateVerifierArgs,
    result: &MigrateVerifierResult,
    error: &SaError,
) -> Option<String> {
    let pending = result.pending_add.as_ref()?;
    let add = || RecoveryStep::Run(pending.recovery_command.clone());
    let refresh = || RecoveryStep::Run(refresh_command(context, args, pending.rule_id));
    let remaining = has_later_step_on_rule(result, pending.rule_id).then_some(pending.rule_id);
    let steps = |repair: Option<RecoveryStep>, then_add: bool| -> String {
        let mut steps: Vec<RecoveryStep> = repair.into_iter().collect();
        if let Some(rule_id) = remaining {
            steps.push(RecoveryStep::ReRunRemaining(rule_id));
        }
        if then_add {
            steps.push(add());
        }
        render_steps(&steps)
    };
    let line = match (error, pending.add_tx_hash.as_deref()) {
        (SaError::BaselineWriteFailed { .. } | SaError::SignerSetDiverged { .. }, _) => {
            steps(Some(refresh()), true)
        }
        (SaError::SubmissionUnresolved { .. }, _) if !pending.remove_confirmed => format!(
            "the remove transaction {} has an unknown outcome. Once it is confirmed, {}. If it \
             is not found, re-run migrate-verifier.",
            pending.remove_tx_hash,
            steps(Some(refresh()), true)
        ),
        (SaError::SubmissionUnresolved { .. }, Some(add_tx_hash)) => format!(
            "the add transaction {add_tx_hash} has an unknown outcome. Once it is confirmed, \
             {}. If it is not found, {}.",
            steps(Some(refresh()), false),
            steps(None, true)
        ),
        _ => steps(None, true),
    };
    Some(line)
}

/// Whether the plan `result` renders holds a step on rule `rule_id` after
/// the failed step, which the run therefore did not submit.
fn has_later_step_on_rule(result: &MigrateVerifierResult, rule_id: u32) -> bool {
    let Some(failed_index) = result.failed_step_index else {
        return false;
    };
    result
        .affected_rules
        .iter()
        .flat_map(|rule| rule.signer_steps.iter().map(move |_| rule.rule_id))
        .enumerate()
        .any(|(index, step_rule_id)| index > failed_index && step_rule_id == rule_id)
}

fn flattened_step_key(plan: &MigrationPlan, target_index: usize) -> Option<(u32, u32)> {
    let mut index = 0usize;
    for rule in &plan.affected_rules {
        for step in &rule.signer_steps {
            if index == target_index {
                return Some((rule.rule_id, step.signer_id));
            }
            index = index.saturating_add(1);
        }
    }
    None
}

/// Returns a human-readable label for a [`VerifierAuditStatus`].
fn audit_status_label(status: &VerifierAuditStatus) -> String {
    match status {
        VerifierAuditStatus::Audited { audited_at, .. } => format!("audited:{audited_at}"),
        VerifierAuditStatus::Provisional { attested_at, .. } => {
            format!("provisional:{attested_at}")
        }
        VerifierAuditStatus::Unaudited => "unaudited".to_owned(),
        VerifierAuditStatus::Revoked { revoked_at, .. } => format!("revoked:{revoked_at}"),
        VerifierAuditStatus::Retired { retired_at, .. } => format!("retired:{retired_at}"),
        // VerifierAuditStatus is #[non_exhaustive]; future variants default to the Display class name.
        _ => {
            warn!(
                "audit_status_label: unrecognised VerifierAuditStatus variant; \
                 falling back to Display representation"
            );
            status.to_string()
        }
    }
}

/// Renders an [`Ok`] envelope and returns exit code `0`.
fn emit_success(result: &MigrateVerifierResult, request_id: &str) -> i32 {
    let envelope = Envelope::ok_with_request_id(result.clone(), request_id.to_owned());
    render_json(&envelope);
    0
}

/// Renders a [`WalletError`] envelope and returns exit code `1`.
fn emit_error(err: &WalletError, request_id: &str) -> i32 {
    let envelope = Envelope::<()>::err_with_request_id(err, request_id.to_owned());
    render_json(&envelope);
    1
}

/// Maps a [`SaError`] into the `WalletError::SmartAccount` envelope shape.
fn emit_error_sa(err: &SaError, request_id: &str) -> i32 {
    emit_error(&wrap_sa_error(err), request_id)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, reason = "test fixture assertions")]
    use super::*;
    use stellar_agent_smart_account::managers::migration::{
        RuleMigration, SignerStepSubmitOutcome,
    };
    use stellar_xdr::ScVal;

    /// A smart-account C-strkey for the recovery fixtures.
    const ACCOUNT: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";

    /// A destination verifier C-strkey for the recovery fixtures.
    const DESTINATION: &str = "CCVTVW2CVA7JLH4ROQGP3CU4T3EXVCK66AZGSM4MUQPXAI4QHCZPOATS";

    /// The submit args of the recovery fixtures: an env-var signer, a named
    /// profile, testnet and a 90 s timeout, with endpoint flags that must not
    /// be echoed.
    fn recovery_args() -> MigrateVerifierArgs {
        let mut args = minimal_args();
        args.account = ACCOUNT.to_owned();
        args.to_verifier = DESTINATION.to_owned();
        args.signer_source.signer_secret_env = Some("MIGRATE_SEED".to_owned());
        args.profile = Some("ops".to_owned());
        args.rpc_url = Some("https://user:secret@rpc.example".to_owned());
        args.secondary_rpc_url = Some("https://user:secret@rpc2.example".to_owned());
        args.timeout_seconds = 90;
        args
    }

    /// The context a testnet profile yields for the endpoint flags of `args`.
    fn flag_context(args: &MigrateVerifierArgs) -> NetworkContext {
        NetworkContext::new(
            args.network.unwrap_or(TargetNetwork::Testnet).caip2(),
            args.rpc_url
                .clone()
                .unwrap_or_else(|| crate::common::network::TESTNET_RPC_URL.to_owned()),
        )
    }

    /// The pending add of signer 7 of rule 1 on [`DESTINATION`].
    #[allow(clippy::unwrap_used, reason = "test-only; the fixture strkey parses")]
    fn pending_step(remove_confirmed: bool, add_tx_hash: Option<String>) -> PendingAddStep {
        PendingAddStep::new_for_test(
            1,
            7,
            parse_c_strkey_to_smart_account(DESTINATION).unwrap(),
            vec![0xab; 4],
            "a".repeat(64),
            remove_confirmed,
            add_tx_hash,
        )
    }

    /// The step of a plan on rule 1 that removes signer `signer_id` and adds
    /// `key` on [`DESTINATION`], as the planner builds it.
    #[allow(clippy::unwrap_used, reason = "test-only; the fixture values encode")]
    fn plan_step(signer_id: u32, key: &[u8]) -> SignerMigrationStep {
        use stellar_xdr::{InvokeContractArgs, ScBytes, ScSymbol, ScVec};
        let call = |name: &str, args: Vec<ScVal>| {
            HostFunction::InvokeContract(InvokeContractArgs {
                contract_address: parse_c_strkey_to_smart_account(ACCOUNT).unwrap(),
                function_name: ScSymbol::try_from(name).unwrap(),
                args: args.try_into().unwrap(),
            })
        };
        let external = ScVal::Vec(Some(ScVec(
            vec![
                ScVal::Symbol(ScSymbol::try_from("External").unwrap()),
                ScVal::Address(parse_c_strkey_to_smart_account(DESTINATION).unwrap()),
                ScVal::Bytes(ScBytes(key.to_vec().try_into().unwrap())),
            ]
            .try_into()
            .unwrap(),
        )));
        SignerMigrationStep::new_for_test(
            signer_id,
            "aabbccdd",
            call("remove_signer", vec![ScVal::U32(1), ScVal::U32(signer_id)]),
            call("add_signer", vec![ScVal::U32(1), external]),
        )
    }

    /// A plan on rule 1 migrating signer 7 (key `0xab` x 4), then
    /// `later_steps` more signers from id 8 on.
    #[allow(clippy::unwrap_used, reason = "test-only; the fixture strkeys parse")]
    fn plan_with(later_steps: u32) -> MigrationPlan {
        let mut steps = vec![plan_step(7, &[0xab; 4])];
        steps.extend((0..later_steps).map(|offset| plan_step(8 + offset, &[0xcd; 4])));
        MigrationPlan::new_for_test(
            parse_c_strkey_to_smart_account(ACCOUNT).unwrap(),
            [0xaa; 32],
            [0x11; 32],
            parse_c_strkey_to_smart_account(DESTINATION).unwrap(),
            vec![RuleMigration::new_for_test(1, "aabbccdd", steps)],
            VerifierAuditStatus::Unaudited,
            "req-partial",
        )
    }

    /// The envelope data the production converter renders for a plan with
    /// `later_steps` after step 0. Step 0 failed with `pending` as its
    /// pending add and `failed_step_remove_tx_hash` as the confirmed
    /// removal's hash the library reports.
    fn partial_result(
        args: &MigrateVerifierArgs,
        pending: Option<PendingAddStep>,
        failed_step_remove_tx_hash: Option<String>,
        later_steps: u32,
    ) -> MigrateVerifierResult {
        let submitted = MigrationSubmitResult::new_for_test(
            vec![],
            Some(0),
            None,
            failed_step_remove_tx_hash,
            pending,
            1,
        );
        migration_plan_to_result_submitted(
            &flag_context(args),
            &plan_with(later_steps),
            &submitted,
            args,
            "stellar:testnet",
        )
    }

    /// Renders `result` with `error` as the partial-failure envelope and
    /// returns it parsed, asserting it is one JSON root.
    #[allow(
        clippy::unwrap_used,
        reason = "test-only; unwrap on expected-Ok is the assertion"
    )]
    fn partial_envelope(result: MigrateVerifierResult, error: &SaError) -> serde_json::Value {
        let wrapped = WalletError::SmartAccount {
            wire_code: error.wire_code(),
            message: error.to_string(),
        };
        let envelope =
            Envelope::partial_failure_with_request_id(result, &wrapped, "req-partial".to_owned());
        let json = serde_json::to_string(&envelope).unwrap();
        let roots = serde_json::Deserializer::from_str(&json)
            .into_iter::<serde_json::Value>()
            .count();
        assert_eq!(roots, 1, "partial failure output must be one JSON root");
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["ok"], false, "ok must be false for partial failure");
        assert!(value.get("error").is_some(), "error must be present");
        assert_eq!(value["request_id"], "req-partial");
        value
    }

    fn redacted() -> stellar_agent_core::observability::RedactedStrkey {
        stellar_agent_core::observability::RedactedStrkey::from_already_redacted("CAAAA...AD2KM")
    }

    fn baseline_write_failed() -> SaError {
        SaError::BaselineWriteFailed {
            rule_id: 1,
            smart_account_redacted: redacted(),
            tx_hash: Some("a".repeat(64)),
            stage: "write",
            reason: "the audit writer is poisoned".to_owned(),
            request_id: "req-partial".to_owned(),
        }
    }

    /// A `SignerSetDiverged` of rule 1 carrying `tx_hash`: the removal's hash
    /// when the confirmed removal left another state, none when the chain
    /// changed between the two steps.
    fn diverged(tx_hash: Option<String>) -> SaError {
        use stellar_agent_core::audit_log::signer_set::{SignerSetSnapshotV2, SignerSetView};
        let empty = || {
            SignerSetView::V2(SignerSetSnapshotV2 {
                signers: vec![],
                threshold: None,
            })
        };
        SaError::SignerSetDiverged {
            rule_id: 1,
            expected: empty(),
            observed: empty(),
            tx_hash,
            smart_account_redacted: redacted(),
            request_id: "req-partial".to_owned(),
        }
    }

    fn unresolved(tx_hash: String) -> SaError {
        SaError::SubmissionUnresolved {
            kind: stellar_agent_smart_account::SubmissionUnresolvedKind::Timeout,
            message: "the transaction was not confirmed in time".to_owned(),
            tx_hash: Some(tx_hash),
            envelope_hash: Some("c".repeat(64)),
            timeout_seconds: Some(90),
        }
    }

    /// The partial-failure envelope is one JSON root carrying the converted
    /// result, its pending add and the error. The stderr line printed before
    /// it matches the case the pair's error decides, with the re-run for
    /// remaining signers after the repair step and before the add.
    #[test]
    fn partial_failure_envelope_serializes_as_single_json_root() {
        let args = recovery_args();
        let refresh = format!(
            "stellar-agent smart-account signers refresh --account {ACCOUNT} --rule-id 1 \
             --accept-divergence --signer-secret-env MIGRATE_SEED --profile ops \
             --network testnet --timeout-seconds 90"
        );
        let remaining = "re-run migrate-verifier for the remaining signers of rule 1";
        let confirmed_hash = Some("a".repeat(64));

        // (a) The removal confirmed and was recorded; the add failed.
        let pending = pending_step(true, None);
        let command = recovery_command(&flag_context(&args), &args, &pending);
        let error = SaError::VerifierMigrationFailed {
            phase: "submit_simulate",
            smart_account_redacted: redacted(),
            detail: "add_signer migration step failed".to_owned(),
            request_id: "req-partial".to_owned(),
        };
        let result = partial_result(&args, Some(pending.clone()), confirmed_hash.clone(), 0);
        assert_eq!(
            partial_failure_recovery_line(&flag_context(&args), &args, &result, &error).as_deref(),
            Some(format!("run: {command}").as_str())
        );
        let value = partial_envelope(result, &error);
        let data = &value["data"];
        assert_eq!(data["failed_step_remove_tx_hash"], "a".repeat(64));
        assert_eq!(data["pending_add"]["rule_id"], 1);
        assert_eq!(data["pending_add"]["signer_id"], 7);
        assert_eq!(data["pending_add"]["to_verifier_address"], DESTINATION);
        assert_eq!(data["pending_add"]["key_data_hex"], "abababab");
        assert_eq!(data["pending_add"]["remove_tx_hash"], "a".repeat(64));
        assert_eq!(data["pending_add"]["remove_confirmed"], true);
        assert!(data["pending_add"].get("add_tx_hash").is_none());
        assert_eq!(data["pending_add"]["recovery_command"], command.as_str());
        let failed_row = &data["affected_rules"][0]["signer_steps"][0];
        assert_eq!(failed_row["key_data_hex"], "abababab");
        assert_eq!(failed_row["remove_tx_hash"], "a".repeat(64));
        assert!(failed_row.get("add_tx_hash").is_none());
        assert!(failed_row.get("new_signer_id").is_none());
        assert_eq!(value["error"]["code"], "sa.verifier_migration_failed");

        // A later step on the rule: the re-run precedes the add.
        let result = partial_result(&args, Some(pending.clone()), confirmed_hash.clone(), 1);
        assert_eq!(
            partial_failure_recovery_line(&flag_context(&args), &args, &result, &error).as_deref(),
            Some(format!("{remaining}, then: {command}").as_str())
        );

        // (b) The removal's state row was not written: the refresh first.
        let error = baseline_write_failed();
        let result = partial_result(&args, Some(pending.clone()), confirmed_hash.clone(), 0);
        assert_eq!(
            partial_failure_recovery_line(&flag_context(&args), &args, &result, &error).as_deref(),
            Some(format!("run: {refresh}, then: {command}").as_str())
        );
        let value = partial_envelope(result, &error);
        assert_eq!(value["error"]["code"], "sa.baseline_write_failed");

        // (b) with a later step on the rule: refresh, the re-run, the add.
        let result = partial_result(&args, Some(pending.clone()), confirmed_hash.clone(), 1);
        assert_eq!(
            partial_failure_recovery_line(&flag_context(&args), &args, &result, &error).as_deref(),
            Some(format!("run: {refresh}, then {remaining}, then: {command}").as_str())
        );

        // (b) The confirmed removal left another state (the removal's hash),
        // and the chain changed between the steps (no hash): the newest
        // state row is not the chain's in both, so the refresh comes first.
        for tx_hash in [Some("a".repeat(64)), None] {
            let error = diverged(tx_hash.clone());
            let result = partial_result(&args, Some(pending.clone()), confirmed_hash.clone(), 0);
            assert_eq!(
                partial_failure_recovery_line(&flag_context(&args), &args, &result, &error)
                    .as_deref(),
                Some(format!("run: {refresh}, then: {command}").as_str()),
                "{tx_hash:?}"
            );
            let value = partial_envelope(result, &error);
            assert_eq!(value["error"]["code"], "sa.signer_set_diverged");
        }

        // A pair that stopped before its removal was sent prints no line:
        // the error's own Display names the refresh.
        let error = baseline_write_failed();
        let result = partial_result(&args, None, None, 0);
        assert_eq!(
            partial_failure_recovery_line(&flag_context(&args), &args, &result, &error),
            None
        );
        let value = partial_envelope(result, &error);
        assert!(value["data"].get("pending_add").is_none());
        assert!(value["data"].get("failed_step_remove_tx_hash").is_none());

        // (c) The removal's outcome is unknown: its hash is in the pending
        // add alone.
        let pending = pending_step(false, None);
        let error = unresolved("a".repeat(64));
        let result = partial_result(&args, Some(pending.clone()), None, 1);
        assert_eq!(
            partial_failure_recovery_line(&flag_context(&args), &args, &result, &error).as_deref(),
            Some(
                format!(
                    "the remove transaction {} has an unknown outcome. Once it is confirmed, \
                     run: {refresh}, then {remaining}, then: {command}. If it is not found, \
                     re-run migrate-verifier.",
                    "a".repeat(64)
                )
                .as_str()
            )
        );
        let value = partial_envelope(result, &error);
        assert!(value["data"].get("failed_step_remove_tx_hash").is_none());
        assert_eq!(value["data"]["pending_add"]["remove_confirmed"], false);
        assert_eq!(
            value["data"]["pending_add"]["remove_tx_hash"],
            "a".repeat(64)
        );
        assert!(
            value["data"]["affected_rules"][0]["signer_steps"][0]
                .get("remove_tx_hash")
                .is_none()
        );
        assert_eq!(value["error"]["code"], "submission.tx_timeout");

        // (c) The add's outcome is unknown.
        let pending = pending_step(true, Some("b".repeat(64)));
        let error = unresolved("b".repeat(64));
        let result = partial_result(&args, Some(pending.clone()), confirmed_hash.clone(), 0);
        assert_eq!(
            partial_failure_recovery_line(&flag_context(&args), &args, &result, &error).as_deref(),
            Some(
                format!(
                    "the add transaction {} has an unknown outcome. Once it is confirmed, \
                     run: {refresh}. If it is not found, run: {command}.",
                    "b".repeat(64)
                )
                .as_str()
            )
        );
        let value = partial_envelope(result, &error);
        assert_eq!(value["data"]["pending_add"]["add_tx_hash"], "b".repeat(64));

        // (c) The add's outcome is unknown with a later step on the rule.
        let result = partial_result(&args, Some(pending), confirmed_hash, 1);
        assert_eq!(
            partial_failure_recovery_line(&flag_context(&args), &args, &result, &error).as_deref(),
            Some(
                format!(
                    "the add transaction {} has an unknown outcome. Once it is confirmed, \
                     run: {refresh}, then {remaining}. If it is not found, {remaining}, \
                     then: {command}.",
                    "b".repeat(64)
                )
                .as_str()
            )
        );
    }

    /// A completed step renders both transaction hashes and the restored
    /// signer's id; a step that failed before its removal was sent renders
    /// neither, and the result carries no pending add.
    #[test]
    fn a_submitted_result_renders_the_completed_and_the_failed_step() {
        let args = recovery_args();
        let submitted = MigrationSubmitResult::new_for_test(
            vec![SignerStepSubmitOutcome::new_for_test(
                1,
                7,
                "a".repeat(64),
                "b".repeat(64),
                21,
            )],
            Some(1),
            None,
            None,
            None,
            2,
        );
        let result = migration_plan_to_result_submitted(
            &flag_context(&args),
            &plan_with(1),
            &submitted,
            &args,
            "stellar:testnet",
        );
        assert_eq!(result.submitted_steps_count, 1);
        assert_eq!(result.failed_step_index, Some(1));
        assert!(result.pending_add.is_none());
        let rows = &result.affected_rules[0].signer_steps;
        assert_eq!(rows[0].signer_id, 7);
        assert_eq!(
            rows[0].remove_tx_hash.as_deref(),
            Some("a".repeat(64).as_str())
        );
        assert_eq!(
            rows[0].add_tx_hash.as_deref(),
            Some("b".repeat(64).as_str())
        );
        assert_eq!(rows[0].new_signer_id, Some(21));
        assert_eq!(rows[0].key_data_hex, "abababab");
        assert_eq!(rows[1].signer_id, 8);
        assert_eq!(rows[1].remove_tx_hash, None);
        assert_eq!(rows[1].add_tx_hash, None);
        assert_eq!(rows[1].new_signer_id, None);
        assert_eq!(rows[1].key_data_hex, "cdcdcdcd");
    }

    /// The recovery command names the account, the rule, the destination
    /// and the key data, then the invocation's signer-source, profile,
    /// network and timeout flags. It never echoes an endpoint URL, and a
    /// value a shell would interpret is quoted.
    #[test]
    fn recovery_command_renders_the_signers_add_of_the_pending_step() {
        let args = recovery_args();
        let command = recovery_command(&flag_context(&args), &args, &pending_step(true, None));
        assert_eq!(
            command,
            format!(
                "stellar-agent smart-account signers add --account {ACCOUNT} --rule-id 1 \
                 --signer-external {DESTINATION} --signer-key-data abababab \
                 --signer-secret-env MIGRATE_SEED --profile ops --network testnet \
                 --timeout-seconds 90"
            )
        );
        assert!(!command.contains("rpc"), "{command}");
        assert!(!command.contains("secret@"), "{command}");

        let mut ledger = recovery_args();
        ledger.signer_source.signer_secret_env = None;
        ledger.signer_source.sign_with_ledger = true;
        ledger.signer_source.account_index = Some(3);
        ledger.profile = Some("ops team's".to_owned());
        let command = recovery_command(&flag_context(&args), &ledger, &pending_step(true, None));
        assert!(
            command.ends_with(
                " --sign-with-ledger --account-index 3 --profile 'ops team'\\''s' \
                 --network testnet --timeout-seconds 90"
            ),
            "{command}"
        );
    }

    /// Baseline args: valid strkeys/hash, unroutable RPC, no signer source.
    ///
    /// `to_verifier` is a checksum-valid production contract strkey (the
    /// Reflector oracle pin) so tests that reach `--to` parsing pass it.
    fn minimal_args() -> MigrateVerifierArgs {
        MigrateVerifierArgs {
            account: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".to_owned(),
            from: "a".repeat(64),
            to_verifier: "CCVTVW2CVA7JLH4ROQGP3CU4T3EXVCK66AZGSM4MUQPXAI4QHCZPOATS".to_owned(),
            profile: None,
            signer_source: SignerSourceFlags {
                signer_secret_env: None,
                sign_with_ledger: false,
                account_index: Some(0),
            },
            network: Some(TargetNetwork::Testnet),
            rpc_url: Some("http://127.0.0.1:1".to_owned()),
            secondary_rpc_url: None,
            timeout_seconds: 1,
            dry_run: false,
        }
    }

    /// Mainnet submit is the FIRST structural refusal, with its exact wire code.
    #[test]
    #[allow(
        clippy::expect_used,
        reason = "test-only; expect on expected-Some is the assertion"
    )]
    fn mainnet_submit_refused_with_mainnet_write_forbidden() {
        let err = mainnet_submit_refusal(TargetNetwork::Mainnet.caip2(), false)
            .expect("mainnet submit must refuse");
        assert_eq!(err.code(), "network.mainnet_write_forbidden");
    }

    /// Mainnet dry-run and testnet submit are not structurally refused.
    #[test]
    fn mainnet_dry_run_and_testnet_submit_pass_the_structural_gate() {
        assert!(
            mainnet_submit_refusal(TargetNetwork::Mainnet.caip2(), true).is_none(),
            "mainnet dry-run must stay available (read-only)"
        );
        assert!(
            mainnet_submit_refusal(TargetNetwork::Testnet.caip2(), false).is_none(),
            "testnet submit must pass the structural gate"
        );
    }

    /// Test-only env guard; mirrors `policy_engine`'s `TestEnvVarGuard`.
    struct TestEnvVarGuard {
        var: &'static str,
    }
    impl TestEnvVarGuard {
        fn set(var: &'static str, value: &std::ffi::OsStr) -> Self {
            #[allow(
                unsafe_code,
                reason = "test-only env mutation; serialised by #[serial]"
            )]
            // SAFETY: serialised by the caller's `#[serial]`; restored on Drop.
            unsafe {
                std::env::set_var(var, value);
            }
            Self { var }
        }
    }
    impl Drop for TestEnvVarGuard {
        fn drop(&mut self) {
            #[allow(unsafe_code, reason = "test-only env cleanup")]
            // SAFETY: same as `set`; serialised by the caller's `#[serial]`.
            unsafe {
                std::env::remove_var(self.var);
            }
        }
    }

    /// A mainnet profile's submit exits 1 before any request reaches the
    /// profile's endpoint. The binary tests in
    /// `tests/profile_env_var_resolution.rs` pin the refusal's wire code.
    #[tokio::test]
    #[serial_test::serial]
    async fn run_mainnet_profile_submit_reaches_no_endpoint() {
        let guard_rpc =
            stellar_agent_test_support::ConnectionCounter::start().expect("connection counter");
        let (_guard_dir, _guard_home, _guard_env) =
            crate::common::profile_access::test_fixtures::mainnet_guard_fixture(
                &guard_rpc.https_uri(),
            );
        const SIGNER_ENV: &str = "MIGRATE_VERIFIER_MAINNET_GATE_TEST_SEED";
        let seed = stellar_strkey::ed25519::PrivateKey([7u8; 32])
            .as_unredacted()
            .to_string()
            .to_string();
        let _guard = TestEnvVarGuard::set(SIGNER_ENV, std::ffi::OsStr::new(&seed));

        let mut args = minimal_args();
        args.network = Some(TargetNetwork::Mainnet);
        args.profile = Some("guard-mainnet".into());
        args.rpc_url = None;
        args.signer_source.signer_secret_env = Some(SIGNER_ENV.to_owned());
        let code = run(&args).await;
        assert_eq!(code, 1, "a mainnet submit must exit 1");
        assert_eq!(
            guard_rpc.accepted().expect("connection count"),
            0,
            "no connection may reach the profile's endpoint"
        );
    }

    /// `--network mainnet` with no profile exits 1 before any request reaches
    /// the primary or the secondary endpoint the flags name. The binary tests
    /// pin the wire code.
    #[tokio::test]
    #[serial_test::serial]
    async fn run_mainnet_flag_without_profile_reaches_no_endpoint() {
        let primary = wiremock::MockServer::start().await;
        let secondary = wiremock::MockServer::start().await;
        let guard_home = tempfile::tempdir().expect("home");
        let _guard_home = stellar_agent_test_support::StellarAgentHomeGuard::new(guard_home.path());
        let _guard_env = stellar_agent_test_support::ProfileEnvVarGuard::cleared();
        const SIGNER_ENV: &str = "MIGRATE_VERIFIER_MAINNET_GATE_TEST_SEED";
        let seed = stellar_strkey::ed25519::PrivateKey([7u8; 32])
            .as_unredacted()
            .to_string()
            .to_string();
        let _guard = TestEnvVarGuard::set(SIGNER_ENV, std::ffi::OsStr::new(&seed));

        let mut args = minimal_args();
        args.network = Some(TargetNetwork::Mainnet);
        args.rpc_url = Some(primary.uri());
        args.secondary_rpc_url = Some(secondary.uri());
        args.signer_source.signer_secret_env = Some(SIGNER_ENV.to_owned());
        let code = run(&args).await;
        assert_eq!(code, 1, "a mainnet submit must exit 1");
        for endpoint in [&primary, &secondary] {
            assert!(
                endpoint
                    .received_requests()
                    .await
                    .expect("requests")
                    .is_empty()
            );
        }
    }

    #[test]
    fn audit_status_label_formats_provisional_with_date() {
        let status = VerifierAuditStatus::Provisional {
            attested_by: "OpenZeppelin",
            attested_at: "2026-07-04",
        };
        assert_eq!(audit_status_label(&status), "provisional:2026-07-04");
    }

    #[test]
    fn audit_status_label_formats_audited_with_date() {
        let status = VerifierAuditStatus::Audited {
            auditor: "OpenZeppelin",
            audited_at: "2026-07-04",
        };
        assert_eq!(audit_status_label(&status), "audited:2026-07-04");
    }
}
