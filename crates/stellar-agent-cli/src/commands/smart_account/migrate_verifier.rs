//! `stellar-agent smart-account migrate-verifier` subcommand.
//!
//! Constructs a [`MigrationPlan`] for migrating all `External` signers on a
//! smart account from a source verifier (`--from <HASH_HEX>`) to a destination
//! verifier contract (`--to <C_STRKEY>`), then either:
//!
//! - **Dry-run** (`--dry-run`): renders the plan as a JSON envelope without
//!   submitting any transactions.
//! - **Submit** (default): signs + submits each `remove_signer` / `add_signer`
//!   pair sequentially and renders a `MigrateVerifierResult` with per-step
//!   tx hashes.
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
//! - `network.mainnet_write_forbidden` — structural mainnet-submit refusal
//! - `sa.verifier_migration_failed` — [`SaError::VerifierMigrationFailed`]
//! - `sa.verifier_wasm_revoked` — [`SaError::VerifierWasmRevoked`]
//! - `sa.verifier_wasm_retired` — [`SaError::VerifierWasmRetired`]
//! - `network.rpc_divergence` — [`SaError::NetworkRpcDivergence`]

use clap::Args;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::{NetworkError, ValidationError, WalletError};
use stellar_agent_core::observability::redact_strkey_first5_last5;
use stellar_agent_smart_account::error::SaError;
use stellar_agent_smart_account::managers::migration::{
    MigrationPlan, MigrationPlanner, MigrationSubmitResult,
};
use stellar_agent_smart_account::managers::rules::parse_c_strkey_to_smart_account;
use stellar_agent_smart_account::managers::signers::SignersManager;
use stellar_agent_smart_account::verifier_allowlist::VerifierAuditStatus;
use tracing::{info, warn};
use uuid::Uuid;

use crate::commands::smart_account::common::{
    CommonArgsView, CommonHandlerContext, SignerSourceFlags, construct_signers_manager_from_fields,
    network_to_chain_id, open_profile_audit_writer_read_only, wrap_sa_error,
};
use crate::common::network::TargetNetwork;
use crate::common::render::render_json;
use crate::common::resolve_profile_name;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Default submission timeout in seconds.
const DEFAULT_TIMEOUT_SECONDS: u64 = 60;

/// Default Stellar testnet Soroban RPC endpoint.
const TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";

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
paired remove_signer / add_signer transactions the rule's signer set is degraded. If \
add_signer fails after remove_signer succeeds, the rule may be left without its \
authorisation signer. The `warnings` field in the JSON envelope is non-empty when \
total_transaction_count > 2. Re-running migrate-verifier after a partial failure \
re-plans from the current on-chain state (already-migrated signers no longer match \
from_hash)."
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

    /// Target network (`testnet` or `mainnet`).
    ///
    /// Mainnet dry-run is allowed (read-only).  Mainnet submit is structurally
    /// refused (`network.mainnet_write_forbidden`).
    #[arg(long, default_value_t = TargetNetwork::Testnet, value_name = "NETWORK")]
    pub network: TargetNetwork,

    /// Primary Soroban RPC URL.
    #[arg(long, default_value = TESTNET_RPC_URL, value_name = "URL")]
    pub rpc_url: String,

    /// Secondary Soroban RPC URL for two-RPC consultation.
    ///
    /// Defaults to `--rpc-url` (degrades to single-RPC consultation where
    /// primary and secondary trivially agree).
    #[arg(long, value_name = "URL")]
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
    /// Remove tx hash for the failed step when remove succeeded and add failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failed_step_remove_tx_hash: Option<String>,
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
    /// Number of context rules that were fetched but could not be decoded
    /// during the `plan_build` phase.
    ///
    /// `0` on a clean run.  Non-zero means at least one rule was silently
    /// skipped.
    pub rules_skipped_count: usize,
}

// ─────────────────────────────────────────────────────────────────────────────
// run
// ─────────────────────────────────────────────────────────────────────────────

/// Builds a read-only [`SignersManager`] for the dry-run path.
///
/// Opens the audit writer via [`open_audit_writer`] then constructs the manager
/// via [`construct_signers_manager_from_fields`].  Does not resolve a signer source.
///
/// # Errors
///
/// - Audit-log directory creation or [`stellar_agent_core::audit_log::writer::AuditWriter::open`]
///   fails → propagated from [`open_audit_writer`].
/// - [`stellar_agent_smart_account::managers::signers::SignersManager::new`] fails →
///   propagated from [`construct_signers_manager_from_fields`].
fn dry_run_signers_manager(
    args: &MigrateVerifierArgs,
) -> Result<(SignersManager, String), WalletError> {
    let profile_name = resolve_profile_name(args.profile.as_deref());
    let chain_id = network_to_chain_id(args.network).to_owned();
    let timeout = Duration::from_secs(args.timeout_seconds);
    let secondary_rpc_url = args
        .secondary_rpc_url
        .as_deref()
        .unwrap_or(&args.rpc_url)
        .to_owned();
    let (_audit_profile, audit_writer, audit_log_path) =
        open_profile_audit_writer_read_only(&profile_name)?;
    let manager = construct_signers_manager_from_fields(
        &profile_name,
        args.network.passphrase(),
        &chain_id,
        &args.rpc_url,
        &secondary_rpc_url,
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

    // Structural mainnet refusal — first gate, before flag-value validation,
    // key access, or any RPC call.  Dry-run on mainnet stays allowed
    // (read-only).
    if let Some(err) = mainnet_submit_refusal(args.network, args.dry_run) {
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
        let (manager, chain_id) = match dry_run_signers_manager(args) {
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
    let ctx = match CommonHandlerContext::new(args).await {
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
            &ctx.chain_id,
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
        &plan,
        &submit_result,
        &args.account,
        &args.to_verifier,
        &ctx.chain_id,
    );

    // If the submission failed at any step, emit the error alongside the
    // partial result and return exit code 1.  The canonical
    // `Envelope::partial_failure_with_request_id` constructor is used so the
    // CLI emits a single JSON root carrying both `data` and `error` fields.
    if let Some(ref err) = submit_result.failed_step_error {
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
fn mainnet_submit_refusal(network: TargetNetwork, dry_run: bool) -> Option<WalletError> {
    (network == TargetNetwork::Mainnet && !dry_run)
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
                    remove_tx_hash: None,
                    add_tx_hash: None,
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
    plan: &MigrationPlan,
    submit_result: &MigrationSubmitResult,
    account_strkey: &str,
    to_verifier_strkey: &str,
    chain_id: &str,
) -> MigrateVerifierResult {
    // Build a lookup from (rule_id, signer_id) → optional (remove_tx, add_tx).
    let mut step_lookup: std::collections::HashMap<(u32, u32), Option<(&str, &str)>> =
        submit_result
            .successful_steps
            .iter()
            .map(|s| {
                (
                    (s.rule_id, s.signer_id),
                    Some((s.remove_tx_hash.as_str(), s.add_tx_hash.as_str())),
                )
            })
            .collect();
    if let (Some(failed_index), Some(remove_tx_hash)) = (
        submit_result.failed_step_index,
        submit_result.failed_step_remove_tx_hash.as_deref(),
    ) && let Some((rule_id, signer_id)) = flattened_step_key(plan, failed_index)
    {
        step_lookup.insert((rule_id, signer_id), Some((remove_tx_hash, "")));
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
                    let txs = step_lookup.get(&(r.rule_id, s.signer_id)).and_then(|v| *v);
                    let (remove_tx, add_tx) = txs.unwrap_or(("", ""));
                    MigrateStepResult {
                        signer_id: s.signer_id,
                        current_hash_first8: s.current_hash_first8.clone(),
                        remove_tx_hash: if remove_tx.is_empty() {
                            None
                        } else {
                            Some(remove_tx.to_owned())
                        },
                        add_tx_hash: if add_tx.is_empty() {
                            None
                        } else {
                            Some(add_tx.to_owned())
                        },
                    }
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
        submitted_steps_count: submit_result.successful_steps.len(),
        failed_step_index: submit_result.failed_step_index,
        failed_step_remove_tx_hash: submit_result.failed_step_remove_tx_hash.clone(),
        dry_run: false,
        request_id: plan.request_id.clone(),
        chain_id: chain_id.to_owned(),
        warnings: plan.warnings.clone(),
        rules_skipped_count: plan.rules_skipped_count,
    }
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
    use super::*;
    use stellar_agent_core::error::{ValidationError, WalletError};

    /// Verifies that `Envelope::partial_failure_with_request_id` produces a
    /// single JSON root containing `ok: false`, `data`, `error`, and
    /// `request_id`.
    #[test]
    #[allow(
        clippy::unwrap_used,
        reason = "test-only; unwrap on expected-Ok is the assertion"
    )]
    fn partial_failure_envelope_serializes_as_single_json_root() {
        let result = MigrateVerifierResult {
            smart_account: "CAAAA...ZZZZZ".to_owned(),
            from_hash_first8: "aabbccdd".to_owned(),
            to_hash_first8: "11223344".to_owned(),
            to_verifier_address: "CBBBB...YYYYY".to_owned(),
            destination_audit_status: "unaudited".to_owned(),
            total_transaction_count: 2,
            affected_rules: vec![MigrateRuleResult {
                rule_id: 1,
                current_hash_first8: "aabbccdd".to_owned(),
                transaction_count: 2,
                signer_steps: vec![MigrateStepResult {
                    signer_id: 7,
                    current_hash_first8: "aabbccdd".to_owned(),
                    remove_tx_hash: Some("a".repeat(64)),
                    add_tx_hash: None,
                }],
            }],
            submitted_steps_count: 0,
            failed_step_index: Some(0),
            failed_step_remove_tx_hash: Some("a".repeat(64)),
            dry_run: false,
            request_id: "req-partial".to_owned(),
            chain_id: "stellar:testnet".to_owned(),
            warnings: vec![],
            rules_skipped_count: 0,
        };

        let err = WalletError::Validation(ValidationError::AddressInvalid {
            input: "sa.verifier_migration_failed: failed".to_owned(),
        });
        let envelope =
            Envelope::partial_failure_with_request_id(result, &err, "req-partial".to_owned());
        let json = serde_json::to_string(&envelope).unwrap();

        // Single JSON root — no stray concatenated objects.
        let roots = serde_json::Deserializer::from_str(&json)
            .into_iter::<serde_json::Value>()
            .count();
        assert_eq!(roots, 1, "partial failure output must be one JSON root");

        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["ok"], false, "ok must be false for partial failure");
        assert!(
            value.get("data").is_some(),
            "data must be present (partial progress)"
        );
        assert!(
            value.get("error").is_some(),
            "error must be present (terminal failure)"
        );
        assert_eq!(
            value["request_id"], "req-partial",
            "request_id must be threaded through"
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
            network: TargetNetwork::Testnet,
            rpc_url: "http://127.0.0.1:1".to_owned(),
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
        let err = mainnet_submit_refusal(TargetNetwork::Mainnet, false)
            .expect("mainnet submit must refuse");
        assert_eq!(err.code(), "network.mainnet_write_forbidden");
    }

    /// Mainnet dry-run and testnet submit are not structurally refused.
    #[test]
    fn mainnet_dry_run_and_testnet_submit_pass_the_structural_gate() {
        assert!(
            mainnet_submit_refusal(TargetNetwork::Mainnet, true).is_none(),
            "mainnet dry-run must stay available (read-only)"
        );
        assert!(
            mainnet_submit_refusal(TargetNetwork::Testnet, false).is_none(),
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

    /// run()-level: the wired gate refuses a mainnet submit with no RPC
    /// attempt (the mock server records zero requests) and exit code 1.
    ///
    /// The fixture supplies a valid signer source and valid strkeys, so every
    /// earlier refusal path is out of play: if the gate were unwired from
    /// `run()`, execution would reach plan building, hit the mock server, and
    /// fail the zero-request assertion.
    #[tokio::test]
    #[serial_test::serial]
    async fn run_mainnet_submit_refused_before_any_network_call() {
        const SIGNER_ENV: &str = "MIGRATE_VERIFIER_MAINNET_GATE_TEST_SEED";

        let server = wiremock::MockServer::start().await;
        let seed = stellar_strkey::ed25519::PrivateKey([7u8; 32])
            .as_unredacted()
            .to_string()
            .to_string();
        let _guard = TestEnvVarGuard::set(SIGNER_ENV, std::ffi::OsStr::new(&seed));

        let mut args = minimal_args();
        args.network = TargetNetwork::Mainnet;
        args.rpc_url = server.uri();
        args.secondary_rpc_url = Some(server.uri());
        args.signer_source.signer_secret_env = Some(SIGNER_ENV.to_owned());

        let code = run(&args).await;
        assert_eq!(code, 1, "mainnet submit must exit with code 1");

        let request_count = server
            .received_requests()
            .await
            .map(|reqs| reqs.len())
            .unwrap_or_default();
        assert_eq!(
            request_count, 0,
            "mainnet submit must be refused before any RPC request"
        );
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
