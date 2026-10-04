//! `stellar_rules_list` / `stellar_rules_get` MCP tools: read-only context-rule
//! and spending-limit-policy observability (GH issue #7).
//!
//! Both tools are read-only (`read_only_hint = true`, `destructive_hint =
//! false`): no signing, no submission, no write-tool authority is conferred.
//! An unidentifiable policy is reported as `identified_kind: "unknown"`, and
//! an unreadable spending-limit budget leaves out the budget block. A rule the
//! wallet cannot read in full, such as one holding a signer it cannot decode,
//! refuses `stellar_rules_get` with the decoder's wire code.
//!
//! # Point-in-time caveat
//!
//! `in_window_spent` / `remaining_budget` (when present) are exact only as of
//! `as_of_ledger`. Forward ledger movement past that point only grows
//! headroom (older entries fall out of the rolling window through eviction),
//! but an intervening spend shrinks it — these numbers are a point-in-time
//! estimate, not a guarantee for a future submission, which can still fail
//! `SpendingLimitExceeded` (OZ error 3221).

use rmcp::{
    handler::server::wrapper::Parameters,
    model::{CallToolResult, Content},
    schemars, serde, tool, tool_router,
};
use serde_json::json;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use stellar_agent_mcp_macros::mcp_tool_router;

use stellar_agent_core::audit_log::writer::{AuditWriter, AuditWriterRegistry};
use stellar_agent_core::profile::schema::default_audit_log_path_for;
use stellar_agent_network::NetworkContext;
use stellar_agent_smart_account::error::SaError;
use stellar_agent_smart_account::managers::rules::{
    ContextRuleManager, ContextRuleManagerConfig, DEFAULT_MAX_SCAN_ID,
    parse_c_strkey_to_smart_account,
};
use stellar_agent_smart_account::managers::signers::{SignersManager, SignersManagerConfig};
use stellar_agent_smart_account::managers::spending_limit_data::compute_spending_window;
use stellar_agent_smart_account::signers::PolicyIdentifiedKind;

use crate::server::WalletServer;
use crate::tools::common::redact_rpc_error_detail;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Well-known interop deployer G-strkey, derived from the publicly-documented
/// SHA256("openzeppelin-smart-account-kit") seed. Used as the simulate-only
/// source account for the `getLedgerEntries` / `simulateTransaction` calls
/// this file issues — no signing, no fee is ever charged against it.
///
/// Mirrors the identical constant already used by the CLI's
/// `smart-account list-rules` (`crates/stellar-agent-cli/src/commands/smart_account/list_rules.rs`)
/// for the same purpose: neither tool exposes a `--source-account`/`source_account`
/// parameter to the caller.
const INTEROP_DEPLOYER_G: &str = "GAAH4OT36RRCCAGKARGPN2HLHT2NOBVFHO4GUHA6CF7UKQ4MMV24WQ4N";

/// Default submission-equivalent timeout (simulate only) in seconds.
const DEFAULT_TIMEOUT_SECONDS: u64 = 60;

/// Profile name used for the audit-log path these read-only tools open.
///
/// Neither tool writes an audit row (no `SaXxx` event is emitted), but
/// `SignersManagerConfig::new` requires an audit writer + path as mandatory
/// constructor arguments. A fixed profile name keeps the on-disk audit-log
/// file stable across calls (via `AuditWriterRegistry::get_or_open`'s
/// per-profile-name cache) without depending on CLI profile resolution
/// inside the MCP server process.
///
/// RESERVED NAME: this is the one permitted unkeyed, name-derived
/// registration in the registry (see `tests/registry_walk.rs`'s discipline
/// scan). It never collides with an operator profile's keyed registration
/// because no real profile shares this name; an operator profile literally
/// named `mcp-rules-observability` would contend for this registry slot and
/// is unsupported.
const RULES_OBSERVABILITY_PROFILE: &str = "mcp-rules-observability";

// ─────────────────────────────────────────────────────────────────────────────
// Manager construction helpers
// ─────────────────────────────────────────────────────────────────────────────

/// The signers-manager configuration for `context`.
///
/// The primary endpoint is the context's primary. The secondary is the
/// context's secondary, or the primary again when the context has none, which
/// is the manager's degraded single-endpoint mode. Every signers manager the
/// MCP server builds takes its configuration from this function.
pub(super) fn signers_manager_config(
    context: &NetworkContext,
    audit_writer: Arc<Mutex<AuditWriter>>,
    audit_log_path: PathBuf,
    profile_name: String,
    timeout: Duration,
) -> SignersManagerConfig {
    SignersManagerConfig::new(
        context.rpc_url.clone(),
        context
            .secondary_rpc_url
            .clone()
            .unwrap_or_else(|| context.rpc_url.clone()),
        audit_writer,
        audit_log_path,
        context.network_passphrase().to_owned(),
        profile_name,
        timeout,
        context.chain_id.caip2_str().to_owned(),
    )
}

/// The context-rule-manager configuration for `context`, carrying the
/// context's secondary endpoint when it has one. Every rule manager the MCP
/// server builds takes its configuration from this function.
pub(super) fn context_rule_manager_config(
    context: &NetworkContext,
    timeout: Duration,
) -> ContextRuleManagerConfig {
    let config = ContextRuleManagerConfig::new(
        context.rpc_url.clone(),
        context.network_passphrase().to_owned(),
        timeout,
        context.chain_id.caip2_str().to_owned(),
    );
    match context.secondary_rpc_url.clone() {
        Some(url) => config.with_secondary_rpc_url(url),
        None => config,
    }
}

/// Builds a read-only [`ContextRuleManager`] for `context`, reading
/// `audit_writer`'s log when one is given.
#[allow(
    clippy::result_large_err,
    reason = "SaError::SignerSetDiverged carries full diagnostic state by design \
              (see stellar-agent-smart-account's crate-level allow); this fn simply \
              propagates it"
)]
fn build_context_rule_manager(
    context: &NetworkContext,
    audit_writer: Option<Arc<Mutex<AuditWriter>>>,
) -> Result<ContextRuleManager, SaError> {
    let config = context_rule_manager_config(context, Duration::from_secs(DEFAULT_TIMEOUT_SECONDS));
    ContextRuleManager::new(match audit_writer {
        Some(writer) => config.with_audit_writer(writer),
        None => config,
    })
}

/// Builds a [`SignersManager`] for `context`.
///
/// Opens (or reuses, via [`AuditWriterRegistry::get_or_open`]'s per-profile
/// cache) the audit-log writer for [`RULES_OBSERVABILITY_PROFILE`].  Neither
/// `stellar_rules_list` nor `stellar_rules_get` writes any audit row; the
/// writer is required only because `SignersManagerConfig::new` mandates one.
#[allow(
    clippy::result_large_err,
    reason = "SaError::SignerSetDiverged carries full diagnostic state by design \
              (see stellar-agent-smart-account's crate-level allow); this fn simply \
              propagates it"
)]
fn build_signers_manager(context: &NetworkContext) -> Result<SignersManager, SaError> {
    let log_path = default_audit_log_path_for(RULES_OBSERVABILITY_PROFILE);
    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| SaError::AuditWriterIo {
            detail: e.to_string(),
            path: log_path.clone(),
        })?;
    }
    let writer: Arc<Mutex<AuditWriter>> =
        AuditWriterRegistry::get_or_open_unkeyed(RULES_OBSERVABILITY_PROFILE, &log_path).map_err(
            |e| SaError::AuditWriterIo {
                detail: e.to_string(),
                path: log_path.clone(),
            },
        )?;

    SignersManager::new(signers_manager_config(
        context,
        writer,
        log_path,
        RULES_OBSERVABILITY_PROFILE.to_owned(),
        Duration::from_secs(DEFAULT_TIMEOUT_SECONDS),
    ))
}

/// The profile's audit writer, for the `baseline` the rule tools report, or
/// `None` with a warning when the log cannot be opened (no chain-root key,
/// the log cannot open, a tip-anchor mismatch). Without a writer every rule
/// reports `unknown`, and the tool still answers.
fn profile_audit_writer(
    server: &WalletServer,
    tool: &'static str,
) -> Option<Arc<Mutex<AuditWriter>>> {
    let profile_name = server.profile_name_for_approval();
    match super::value_audit::require_value_audit_writer(
        &server.profile,
        &profile_name,
        server.audit_binding,
    ) {
        Ok(writer) => Some(writer),
        Err(err) => {
            tracing::warn!(
                tool,
                profile = %profile_name,
                error = %err,
                "the profile's audit log is not readable; every rule's baseline reports unknown"
            );
            None
        }
    }
}

/// Maps an [`SaError`] to an MCP tool-level error result (`is_error = true`),
/// mirroring the `redacted_wallet_error_envelope` pattern used by the other
/// read-only tools in this crate.
fn sa_error_result(err: &SaError) -> CallToolResult {
    crate::tools::common::business_error_result(err.wire_code(), err.to_string())
}

// ─────────────────────────────────────────────────────────────────────────────
// stellar_rules_list
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for the `stellar_rules_list` MCP tool.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(crate = "rmcp::serde")]
pub struct StellarRulesListArgs {
    /// CAIP-2 chain identifier: `stellar:testnet` or `stellar:mainnet`.
    pub chain_id: String,

    /// Smart-account contract C-strkey to enumerate rules for.
    pub smart_account: String,
}

/// A single rule's metadata, as returned by `stellar_rules_list` and embedded
/// in `stellar_rules_get`.
#[derive(Debug, Clone, ::serde::Serialize)]
pub struct RuleListEntry {
    /// On-chain rule ID.
    pub rule_id: u32,
    /// Operator-visible rule name.
    pub name: String,
    /// Closed-set context-type label (`"default"`, `"call_contract"`,
    /// `"create_contract"`).
    pub context_type_label: &'static str,
    /// Optional ledger sequence at which the rule expires. `None` means
    /// permanent.
    pub valid_until: Option<u32>,
    /// Number of signers attached to the rule.
    pub signer_count: u32,
    /// Number of policies attached to the rule.
    pub policy_count: u32,
    /// The rule's signer-set baseline in the profile's audit log: `none`
    /// (no state row; a signature under the rule refuses until one
    /// `signers list --rule-id N` records it), `v1`, `v2`, `unreadable` (an
    /// audit-log integrity error), or `unknown` (the log was not read).
    pub baseline: String,
}

impl From<stellar_agent_smart_account::managers::rules::ContextRuleSummary> for RuleListEntry {
    fn from(s: stellar_agent_smart_account::managers::rules::ContextRuleSummary) -> Self {
        Self {
            rule_id: s.rule_id,
            name: s.name,
            context_type_label: s.context_type_label,
            valid_until: s.valid_until,
            signer_count: s.signer_count,
            policy_count: s.policy_count,
            baseline: s.baseline.as_str().to_owned(),
        }
    }
}

/// Result envelope for `stellar_rules_list`.
#[derive(Debug, Clone, ::serde::Serialize)]
pub struct StellarRulesListResult {
    /// Active rules, in ascending rule-ID order.
    pub rules: Vec<RuleListEntry>,
    /// Ledger sequence this enumeration was read as of.
    pub as_of_ledger: u32,
}

#[mcp_tool_router]
#[tool_router(router = rules_tool_router, vis = "pub(crate)")]
impl WalletServer {
    /// Enumerates active context rules on a smart account (read-only).
    ///
    /// Scans the on-chain OZ rule-ID space `[0, max_scan_id)`
    /// (`max_scan_id` = [`DEFAULT_MAX_SCAN_ID`], the same default the CLI
    /// `smart-account rules list` uses — the scan cannot silently truncate
    /// relative to the CLI view).
    #[mcp_tool_item(
        name = "stellar_rules_list",
        destructive_hint = false,
        read_only_hint = true,
        chain_id_required = true
    )]
    #[tool(
        name = "stellar_rules_list",
        description = "Enumerate active context rules on a smart account (read-only). Returns \
                       each rule's id, name, context_type_label, valid_until, signer_count, \
                       policy_count and baseline (the rule's signer-set baseline in the \
                       profile's audit log: none, v1, v2, unreadable or unknown; a rule \
                       reporting none refuses signing until its baseline is recorded), plus \
                       the as_of_ledger the scan was read at. Scans up to max_scan_id rule IDs \
                       (same default as the CLI `rules list`). Data comes from a single RPC \
                       endpoint (no two-RPC cross-check; advisory read, not a signing input). \
                       read_only_hint=true; destructive_hint=false.",
        annotations(read_only_hint = true, destructive_hint = false)
    )]
    async fn stellar_rules_list(
        &self,
        Parameters(args): Parameters<StellarRulesListArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let args_value = json!({
            "chain_id": &args.chain_id,
            "smart_account": &args.smart_account,
        });
        if let Err(e) = self
            .dispatch_gate("stellar_rules_list", &args_value, &args.chain_id)
            .await
        {
            return e.into_result();
        }

        let smart_account = match parse_c_strkey_to_smart_account(&args.smart_account) {
            Ok(a) => a,
            Err(e) => {
                return Err(rmcp::ErrorData::invalid_params(
                    format!("invalid smart_account (expected C-strkey): {e}"),
                    None,
                ));
            }
        };

        let manager = match build_context_rule_manager(
            &self.context,
            profile_audit_writer(self, "stellar_rules_list"),
        ) {
            Ok(m) => m,
            Err(err) => {
                return Err(rmcp::ErrorData::internal_error(
                    redact_rpc_error_detail("smart_account_manager_error", &err),
                    None,
                ));
            }
        };
        let signers_manager = match build_signers_manager(&self.context) {
            Ok(m) => m,
            Err(err) => {
                return Err(rmcp::ErrorData::internal_error(
                    redact_rpc_error_detail("smart_account_manager_error", &err),
                    None,
                ));
            }
        };

        let enumeration = match manager
            .list_active_context_rules(
                smart_account.clone(),
                INTEROP_DEPLOYER_G,
                DEFAULT_MAX_SCAN_ID,
            )
            .await
        {
            Ok(e) => e,
            Err(err) => return Ok(sa_error_result(&err)),
        };

        let as_of_ledger = match signers_manager
            .fetch_current_ledger(smart_account, Some(INTEROP_DEPLOYER_G))
            .await
        {
            Ok(l) => l,
            Err(err) => return Ok(sa_error_result(&err)),
        };

        let result = StellarRulesListResult {
            rules: enumeration
                .rules
                .into_iter()
                .map(RuleListEntry::from)
                .collect(),
            as_of_ledger,
        };
        let envelope = stellar_agent_core::envelope::Envelope::ok(result);
        let json = envelope
            .to_json_pretty()
            .unwrap_or_else(|_| String::from("{}"));
        Ok(CallToolResult::success(vec![Content::text(json)]))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// stellar_rules_get
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for the `stellar_rules_get` MCP tool.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(crate = "rmcp::serde")]
pub struct StellarRulesGetArgs {
    /// CAIP-2 chain identifier: `stellar:testnet` or `stellar:mainnet`.
    pub chain_id: String,

    /// Smart-account contract C-strkey.
    pub smart_account: String,

    /// Context rule ID to read.
    pub rule_id: u32,
}

/// A single policy attached to a rule, with its best-effort classification.
#[derive(Debug, Clone, ::serde::Serialize)]
pub struct PolicyEntry {
    /// Policy contract C-strkey.
    pub address: String,
    /// `"threshold"`, `"spending-limit"`, or `"unknown"` (degrade-on-failure —
    /// an unidentifiable policy never fails the read).
    pub identified_kind: String,
}

/// The spending-limit budget snapshot, present only when exactly one
/// attached policy identifies as `"spending-limit"`.
///
/// # Point-in-time caveat
///
/// `in_window_spent` / `remaining_budget` are exact only as of `as_of_ledger`
/// — see the module-level rustdoc for the full caveat.
#[derive(Debug, Clone, ::serde::Serialize)]
pub struct SpendingLimitBudget {
    /// The configured spending limit, in stroops, as a decimal string. A raw
    /// JSON number would lose precision above `2^53`.
    pub spending_limit: String,
    /// The rolling-window period, in ledgers.
    pub period_ledgers: u32,
    /// Sum of spend-history entries within the rolling window as of
    /// `as_of_ledger`, as a decimal string (see `spending_limit`).
    pub in_window_spent: String,
    /// `max(0, spending_limit - in_window_spent)`, as a decimal string (see
    /// `spending_limit`).
    pub remaining_budget: String,
    /// Ledger sequence the simulation observed.
    pub as_of_ledger: u32,
}

/// Result envelope for `stellar_rules_get`.
#[derive(Debug, Clone, ::serde::Serialize)]
pub struct StellarRulesGetResult {
    /// On-chain rule ID.
    pub rule_id: u32,
    /// Operator-visible rule name.
    pub name: String,
    /// Closed-set context-type label.
    pub context_type_label: &'static str,
    /// Optional ledger sequence at which the rule expires.
    pub valid_until: Option<u32>,
    /// Number of ledgers remaining until expiry, derived from
    /// `valid_until - as_of_ledger`. `None` when `valid_until` is `None`
    /// (permanent rule) or already in the past (saturates to `0`).
    pub expires_in_ledgers: Option<u32>,
    /// Number of signers attached to the rule.
    pub signer_count: u32,
    /// Number of policies attached to the rule.
    pub policy_count: u32,
    /// Every policy attached to the rule, with its best-effort classification.
    pub policies: Vec<PolicyEntry>,
    /// The spending-limit budget snapshot, present only when exactly one
    /// attached policy identifies as `"spending-limit"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spending_limit: Option<SpendingLimitBudget>,
    /// Ledger sequence this read was performed as of.
    pub as_of_ledger: u32,
    /// The rule's signer-set baseline in the profile's audit log: `none`
    /// (no state row; a signature under the rule refuses until one
    /// `signers list --rule-id N` records it), `v1`, `v2`, `unreadable` (an
    /// audit-log integrity error), or `unknown` (the log was not read).
    pub baseline: String,
}

#[mcp_tool_router]
#[tool_router(router = rules_get_tool_router, vis = "pub(crate)")]
impl WalletServer {
    /// Reads a single context rule's metadata, policy classification, and
    /// (when identifiable) spending-limit budget snapshot (read-only).
    ///
    /// A policy whose Wasm hash is unrecognised or unobservable is reported as
    /// `identified_kind: "unknown"`, and a spending-limit budget that cannot
    /// be read leaves out the `spending_limit` block. A failure to read the
    /// rule itself, including a rule holding a signer the wallet cannot
    /// decode, refuses the call with the error's wire code.
    #[mcp_tool_item(
        name = "stellar_rules_get",
        destructive_hint = false,
        read_only_hint = true,
        chain_id_required = true
    )]
    #[tool(
        name = "stellar_rules_get",
        description = "Read a single context rule's metadata (name, context_type_label, \
                       valid_until, expires_in_ledgers, signer_count, policy_count, and \
                       baseline: the rule's signer-set baseline in the profile's audit log, \
                       none, v1, v2, unreadable or unknown), its \
                       policies with best-effort identified_kind classification \
                       (threshold/spending-limit/unknown), and, when exactly one attached \
                       policy identifies as spending-limit, the budget snapshot (spending_limit, \
                       period_ledgers, in_window_spent, remaining_budget, as_of_ledger). \
                       in_window_spent/remaining_budget are exact only as of as_of_ledger: an \
                       intervening spend can still cause SpendingLimitExceeded on a later \
                       submission. Data comes from a single RPC endpoint (no two-RPC \
                       cross-check; advisory read, not a signing input). read_only_hint=true; \
                       destructive_hint=false.",
        annotations(read_only_hint = true, destructive_hint = false)
    )]
    async fn stellar_rules_get(
        &self,
        Parameters(args): Parameters<StellarRulesGetArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let args_value = json!({
            "chain_id": &args.chain_id,
            "smart_account": &args.smart_account,
            "rule_id": args.rule_id,
        });
        if let Err(e) = self
            .dispatch_gate("stellar_rules_get", &args_value, &args.chain_id)
            .await
        {
            return e.into_result();
        }

        let smart_account = match parse_c_strkey_to_smart_account(&args.smart_account) {
            Ok(a) => a,
            Err(e) => {
                return Err(rmcp::ErrorData::invalid_params(
                    format!("invalid smart_account (expected C-strkey): {e}"),
                    None,
                ));
            }
        };

        let manager = match build_context_rule_manager(
            &self.context,
            profile_audit_writer(self, "stellar_rules_get"),
        ) {
            Ok(m) => m,
            Err(err) => {
                return Err(rmcp::ErrorData::internal_error(
                    redact_rpc_error_detail("smart_account_manager_error", &err),
                    None,
                ));
            }
        };
        let signers_manager = match build_signers_manager(&self.context) {
            Ok(m) => m,
            Err(err) => {
                return Err(rmcp::ErrorData::internal_error(
                    redact_rpc_error_detail("smart_account_manager_error", &err),
                    None,
                ));
            }
        };

        // Reuse list_active_context_rules and filter for rule_id — avoids
        // duplicating the private summary-decode path. Rule sets are small
        // in practice (bounded by DEFAULT_MAX_SCAN_ID).
        let enumeration = match manager
            .list_active_context_rules(
                smart_account.clone(),
                INTEROP_DEPLOYER_G,
                DEFAULT_MAX_SCAN_ID,
            )
            .await
        {
            Ok(e) => e,
            Err(err) => return Ok(sa_error_result(&err)),
        };

        let Some(summary) = enumeration
            .rules
            .into_iter()
            .find(|r| r.rule_id == args.rule_id)
        else {
            let envelope = stellar_agent_core::envelope::Envelope::<()>::err_raw(
                "sa.rule_not_found",
                format!("context rule {} not found or not active", args.rule_id),
            );
            let json = envelope
                .to_json_pretty()
                .unwrap_or_else(|_| String::from("{}"));
            let mut result = CallToolResult::success(vec![Content::text(json)]);
            result.is_error = Some(true);
            return Ok(result);
        };

        let as_of_ledger = match signers_manager
            .fetch_current_ledger(smart_account.clone(), Some(INTEROP_DEPLOYER_G))
            .await
        {
            Ok(l) => l,
            Err(err) => return Ok(sa_error_result(&err)),
        };

        let expires_in_ledgers = summary.valid_until.map(|v| v.saturating_sub(as_of_ledger));

        let classified: Vec<(stellar_xdr::ScAddress, PolicyIdentifiedKind)> = match signers_manager
            .classify_rule_policies(smart_account, args.rule_id, Some(INTEROP_DEPLOYER_G))
            .await
        {
            Ok(classified) => classified,
            Err(err) => return Ok(sa_error_result(&err)),
        };

        // A non-Contract policy address fails LOUD rather than degrading: OZ
        // policies are always contracts, so this shape is structurally
        // unreachable — and emitting a fabricated placeholder identifier here
        // would hand the operator a plausible-looking but wrong address to
        // trust. Matches the CLI's typed refusal for the same case.
        let mut policies: Vec<PolicyEntry> = Vec::with_capacity(classified.len());
        for (addr, kind) in &classified {
            let stellar_xdr::ScAddress::Contract(stellar_xdr::ContractId(stellar_xdr::Hash(bytes))) =
                addr
            else {
                return Err(rmcp::ErrorData::internal_error(
                    format!(
                        "rule {} carries a non-contract policy address; refusing to \
                         report a fabricated identifier",
                        args.rule_id
                    ),
                    None,
                ));
            };
            policies.push(PolicyEntry {
                address: stellar_strkey::Contract(*bytes)
                    .to_string()
                    .as_str()
                    .to_owned(),
                identified_kind: kind.to_string(),
            });
        }

        let spending_limit_addrs: Vec<&stellar_xdr::ScAddress> = classified
            .iter()
            .filter(|(_, kind)| *kind == PolicyIdentifiedKind::SpendingLimit)
            .map(|(addr, _)| addr)
            .collect();

        let spending_limit = if spending_limit_addrs.len() == 1 {
            let policy_addr = spending_limit_addrs[0].clone();
            match signers_manager
                .get_spending_limit_data(
                    policy_addr,
                    args.rule_id,
                    smart_account_for_budget(&args.smart_account)?,
                    Some(INTEROP_DEPLOYER_G),
                    uuid::Uuid::new_v4().to_string(),
                )
                .await
            {
                Ok((data, budget_as_of_ledger)) => {
                    let window = compute_spending_window(&data, budget_as_of_ledger);
                    Some(SpendingLimitBudget {
                        spending_limit: data.spending_limit.to_string(),
                        period_ledgers: data.period_ledgers,
                        in_window_spent: window.in_window_spent.to_string(),
                        remaining_budget: window.remaining.to_string(),
                        as_of_ledger: budget_as_of_ledger,
                    })
                }
                // Degrade rather than fail the whole read: absence/ambiguity
                // at this stage still yields a valid metadata-only response.
                Err(_) => None,
            }
        } else {
            None
        };

        let result = StellarRulesGetResult {
            rule_id: summary.rule_id,
            name: summary.name,
            context_type_label: summary.context_type_label,
            valid_until: summary.valid_until,
            expires_in_ledgers,
            signer_count: summary.signer_count,
            policy_count: summary.policy_count,
            policies,
            spending_limit,
            as_of_ledger,
            baseline: summary.baseline.as_str().to_owned(),
        };
        let envelope = stellar_agent_core::envelope::Envelope::ok(result);
        let json = envelope
            .to_json_pretty()
            .unwrap_or_else(|_| String::from("{}"));
        Ok(CallToolResult::success(vec![Content::text(json)]))
    }
}

/// Re-parses `smart_account` for the `get_spending_limit_data` call.
///
/// `classify_rule_policies` consumes the original `ScAddress` by value; this
/// avoids threading a clone through the whole handler body for the single
/// downstream use.
fn smart_account_for_budget(
    smart_account: &str,
) -> Result<stellar_xdr::ScAddress, rmcp::ErrorData> {
    parse_c_strkey_to_smart_account(smart_account).map_err(|e| {
        rmcp::ErrorData::invalid_params(
            format!("invalid smart_account (expected C-strkey): {e}"),
            None,
        )
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Toolset-dispatch helpers
// ─────────────────────────────────────────────────────────────────────────────

impl WalletServer {
    /// Invoke `stellar_rules_list` by value, bypassing the rmcp transport layer.
    ///
    /// Used by the toolset-invocation routing path (`tools/toolsets.rs`).
    ///
    /// # Errors
    ///
    /// Same as `WalletServer::stellar_rules_list`.
    pub(crate) async fn invoke_stellar_rules_list(
        &self,
        args: StellarRulesListArgs,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.stellar_rules_list(Parameters(args)).await
    }

    /// Invoke `stellar_rules_get` by value, bypassing the rmcp transport layer.
    ///
    /// # Errors
    ///
    /// Same as `WalletServer::stellar_rules_get`.
    pub(crate) async fn invoke_stellar_rules_get(
        &self,
        args: StellarRulesGetArgs,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.stellar_rules_get(Parameters(args)).await
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test helpers
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(any(test, feature = "test-helpers"))]
impl WalletServer {
    /// Calls `stellar_rules_list` with the given args, bypassing the rmcp transport.
    ///
    /// # Errors
    ///
    /// Same as `WalletServer::stellar_rules_list`.
    pub async fn call_stellar_rules_list(
        &self,
        args: StellarRulesListArgs,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.stellar_rules_list(Parameters(args)).await
    }

    /// Calls `stellar_rules_get` with the given args, bypassing the rmcp transport.
    ///
    /// # Errors
    ///
    /// Same as `WalletServer::stellar_rules_get`.
    pub async fn call_stellar_rules_get(
        &self,
        args: StellarRulesGetArgs,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        self.stellar_rules_get(Parameters(args)).await
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests: arg schema round-trips + output wire-shape
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]
    use super::*;

    // ── Manager configuration from the server's context ──────────────────────

    const PRIMARY: &str = "https://primary.example";
    const SECONDARY: &str = "https://secondary.example";

    /// A testnet server whose context carries `secondary` as its secondary
    /// endpoint.
    fn server_with_secondary(secondary: Option<&str>) -> WalletServer {
        let profile = stellar_agent_core::profile::Profile::builder_testnet_named(
            "manager-config",
            "s",
            "a",
            "n",
            "a",
        )
        .rpc_url(PRIMARY)
        .with_noop_engine()
        .build();
        let mut server = WalletServer::new(profile).expect("server");
        server.context = NetworkContext::new(
            stellar_agent_core::profile::caip2::Caip2::Testnet,
            PRIMARY.to_owned(),
        )
        .with_secondary(secondary.map(str::to_owned));
        server
    }

    /// The two manager configurations built from `server`'s context.
    fn manager_configs(server: &WalletServer) -> (SignersManagerConfig, ContextRuleManagerConfig) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let writer = Arc::new(Mutex::new(
            AuditWriter::open(path.clone(), None).expect("writer"),
        ));
        let timeout = Duration::from_secs(DEFAULT_TIMEOUT_SECONDS);
        (
            signers_manager_config(
                &server.context,
                writer,
                path,
                "manager-config".to_owned(),
                timeout,
            ),
            context_rule_manager_config(&server.context, timeout),
        )
    }

    #[test]
    fn manager_configs_carry_a_distinct_context_secondary() {
        let server = server_with_secondary(Some(SECONDARY));
        let (signers, rules) = manager_configs(&server);
        assert_eq!(signers.primary_rpc_url, PRIMARY);
        assert_eq!(signers.secondary_rpc_url, SECONDARY);
        assert_eq!(rules.primary_rpc_url, PRIMARY);
        assert_eq!(rules.secondary_rpc_url.as_deref(), Some(SECONDARY));
    }

    #[test]
    fn manager_configs_without_a_secondary_fall_back_to_the_primary() {
        let server = server_with_secondary(None);
        let (signers, rules) = manager_configs(&server);
        assert_eq!(signers.secondary_rpc_url, PRIMARY);
        assert_eq!(rules.secondary_rpc_url, None);
    }

    // ── Arg schema round-trips ────────────────────────────────────────────────

    #[test]
    fn stellar_rules_list_args_deserialise_from_representative_json() {
        let json = serde_json::json!({
            "chain_id": "stellar:testnet",
            "smart_account": "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
        });
        let args: StellarRulesListArgs = serde_json::from_value(json).expect("deserialise");
        assert_eq!(args.chain_id, "stellar:testnet");
        assert_eq!(
            args.smart_account,
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM"
        );
    }

    #[test]
    fn stellar_rules_get_args_deserialise_from_representative_json() {
        let json = serde_json::json!({
            "chain_id": "stellar:testnet",
            "smart_account": "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "rule_id": 3,
        });
        let args: StellarRulesGetArgs = serde_json::from_value(json).expect("deserialise");
        assert_eq!(args.chain_id, "stellar:testnet");
        assert_eq!(args.rule_id, 3);
    }

    #[test]
    fn stellar_rules_get_args_rejects_missing_rule_id() {
        let json = serde_json::json!({
            "chain_id": "stellar:testnet",
            "smart_account": "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
        });
        let result: Result<StellarRulesGetArgs, _> = serde_json::from_value(json);
        assert!(result.is_err(), "rule_id must be required");
    }

    // ── Output wire-shape ─────────────────────────────────────────────────────

    #[test]
    fn stellar_rules_list_result_wire_shape() {
        let result = StellarRulesListResult {
            rules: vec![RuleListEntry {
                rule_id: 0,
                name: "boot-rule".to_owned(),
                context_type_label: "default",
                valid_until: None,
                signer_count: 1,
                policy_count: 0,
                baseline: "v2".to_owned(),
            }],
            as_of_ledger: 12_345,
        };
        let json = serde_json::to_string(&result).expect("serialise");
        for key in [
            "rules",
            "as_of_ledger",
            "rule_id",
            "name",
            "context_type_label",
            "baseline",
        ] {
            assert!(
                json.contains(&format!("\"{key}\"")),
                "JSON must contain '{key}' key; got: {json}"
            );
        }
    }

    #[test]
    fn stellar_rules_get_result_wire_shape_without_spending_limit() {
        let result = StellarRulesGetResult {
            rule_id: 1,
            name: "rule-1".to_owned(),
            context_type_label: "call_contract",
            valid_until: Some(2_000),
            expires_in_ledgers: Some(500),
            signer_count: 1,
            policy_count: 1,
            policies: vec![PolicyEntry {
                address: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".to_owned(),
                identified_kind: "unknown".to_owned(),
            }],
            spending_limit: None,
            as_of_ledger: 1_500,
            baseline: "v2".to_owned(),
        };
        let json = serde_json::to_string(&result).expect("serialise");
        for key in [
            "rule_id",
            "context_type_label",
            "valid_until",
            "expires_in_ledgers",
            "policies",
            "address",
            "identified_kind",
            "as_of_ledger",
            "baseline",
        ] {
            assert!(
                json.contains(&format!("\"{key}\"")),
                "JSON must contain '{key}' key; got: {json}"
            );
        }
        // spending_limit is omitted when None (skip_serializing_if).
        assert!(
            !json.contains("\"spending_limit\""),
            "spending_limit must be omitted when None: {json}"
        );
    }

    #[test]
    fn stellar_rules_get_result_wire_shape_with_spending_limit() {
        let result = StellarRulesGetResult {
            rule_id: 2,
            name: "rule-2".to_owned(),
            context_type_label: "call_contract",
            valid_until: None,
            expires_in_ledgers: None,
            signer_count: 1,
            policy_count: 1,
            policies: vec![PolicyEntry {
                address: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".to_owned(),
                identified_kind: "spending-limit".to_owned(),
            }],
            spending_limit: Some(SpendingLimitBudget {
                spending_limit: "10000000".to_owned(),
                period_ledgers: 17_280,
                in_window_spent: "2000000".to_owned(),
                remaining_budget: "8000000".to_owned(),
                as_of_ledger: 1_500,
            }),
            as_of_ledger: 1_500,
            baseline: "none".to_owned(),
        };
        let json = serde_json::to_string(&result).expect("serialise");
        for key in [
            "spending_limit",
            "period_ledgers",
            "in_window_spent",
            "remaining_budget",
        ] {
            assert!(
                json.contains(&format!("\"{key}\"")),
                "JSON must contain '{key}' key; got: {json}"
            );
        }
    }

    /// Asserts the budget fields are JSON strings, not JSON numbers —
    /// values above `2^53` must survive an `f64`-backed JSON parser
    /// exactly.
    #[test]
    fn spending_limit_budget_amount_fields_serialise_as_json_strings() {
        let budget = SpendingLimitBudget {
            spending_limit: "170141183460469231731687303715884105727".to_owned(),
            period_ledgers: 17_280,
            in_window_spent: "9007199254740993".to_owned(),
            remaining_budget: "0".to_owned(),
            as_of_ledger: 1_500,
        };
        let value = serde_json::to_value(&budget).expect("serialise");
        assert!(
            value["spending_limit"].is_string(),
            "spending_limit must serialise as a JSON string: {value}"
        );
        assert!(
            value["in_window_spent"].is_string(),
            "in_window_spent must serialise as a JSON string: {value}"
        );
        assert!(
            value["remaining_budget"].is_string(),
            "remaining_budget must serialise as a JSON string: {value}"
        );
        assert_eq!(
            value["spending_limit"].as_str().expect("string"),
            "170141183460469231731687303715884105727"
        );
    }

    // ── stellar_rules_get refuses a rule it cannot read in full ───────────────

    /// A rule map for rule `0` with one `Delegated` signer and one signer whose
    /// tag is `Future`, a `Signer` variant the wallet does not know.
    fn rule_with_an_unknown_signer() -> stellar_xdr::ScVal {
        use stellar_xdr::{
            AccountId, ContractId, Hash, PublicKey, ScAddress, ScMap, ScMapEntry, ScString,
            ScSymbol, ScVal, ScVec, Uint256,
        };
        let sym = |s: &str| ScVal::Symbol(ScSymbol::try_from(s).expect("symbol fits"));
        let list = |items: Vec<ScVal>| ScVal::Vec(Some(ScVec(items.try_into().expect("fits"))));
        let delegated = list(vec![
            sym("Delegated"),
            ScVal::Address(ScAddress::Account(AccountId(
                PublicKey::PublicKeyTypeEd25519(Uint256([0x11; 32])),
            ))),
        ]);
        let unknown = list(vec![
            sym("Future"),
            ScVal::Address(ScAddress::Contract(ContractId(Hash([0x22; 32])))),
        ]);
        let entry = |key: &str, val: ScVal| ScMapEntry { key: sym(key), val };
        let entries: Vec<ScMapEntry> = vec![
            entry("context_type", list(vec![sym("Default")])),
            entry("id", ScVal::U32(0)),
            entry(
                "name",
                ScVal::String(ScString(b"rule-0".to_vec().try_into().expect("fits"))),
            ),
            entry("policies", list(vec![])),
            entry("policy_ids", list(vec![])),
            entry("signer_ids", list(vec![ScVal::U32(0), ScVal::U32(1)])),
            entry("signers", list(vec![delegated, unknown])),
            entry("valid_until", ScVal::Void),
        ];
        ScVal::Map(Some(ScMap(entries.try_into().expect("fits"))))
    }

    /// Mock Soroban RPC for `stellar_rules_get`: serves the source account for
    /// `getLedgerEntries` and answers `simulateTransaction` by the invoked
    /// function name (`get_context_rules_count` returns `1`,
    /// `get_context_rule` returns [`rule_with_an_unknown_signer`]).
    struct RuleReadResponder;

    impl wiremock::Respond for RuleReadResponder {
        fn respond(&self, request: &wiremock::Request) -> wiremock::ResponseTemplate {
            use stellar_xdr::{
                HostFunction, Limits, OperationBody, ReadXdr, ScVal, TransactionEnvelope, WriteXdr,
            };
            let body: serde_json::Value =
                serde_json::from_slice(&request.body).expect("JSON-RPC body");
            let id = body["id"].clone();
            let result = match body["method"].as_str().unwrap_or("") {
                "getLedgerEntries" => json!({
                    "entries": [{
                        "key": stellar_agent_test_support::xdr_fixtures::account_ledger_key_xdr(
                            INTEROP_DEPLOYER_G,
                        ),
                        "xdr": stellar_agent_test_support::xdr_fixtures::account_entry_xdr(
                            INTEROP_DEPLOYER_G,
                            100_000_000,
                            0,
                        ),
                        "lastModifiedLedgerSeq": 100
                    }],
                    "latestLedger": 1000
                }),
                "simulateTransaction" => {
                    let envelope = TransactionEnvelope::from_xdr_base64(
                        body["params"]["transaction"].as_str().expect("transaction"),
                        Limits::none(),
                    )
                    .expect("transaction envelope decodes");
                    let TransactionEnvelope::Tx(tx) = envelope else {
                        panic!("expected a v1 transaction envelope");
                    };
                    let OperationBody::InvokeHostFunction(op) = &tx.tx.operations[0].body else {
                        panic!("expected an InvokeHostFunction operation");
                    };
                    let HostFunction::InvokeContract(args) = &op.host_function else {
                        panic!("expected an InvokeContract host function");
                    };
                    let returned = match args.function_name.0.as_slice() {
                        b"get_context_rules_count" => ScVal::U32(1),
                        b"get_context_rule" => rule_with_an_unknown_signer(),
                        other => panic!("unexpected simulated function {other:?}"),
                    };
                    json!({
                        "transactionData": "",
                        "minResourceFee": "0",
                        "results": [{
                            "auth": [],
                            "xdr": returned.to_xdr_base64(Limits::none()).expect("encodes")
                        }],
                        "latestLedger": 1000
                    })
                }
                other => panic!("unexpected JSON-RPC method {other}"),
            };
            wiremock::ResponseTemplate::new(200)
                .set_body_json(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
        }
    }

    /// `stellar_rules_get` refuses a rule holding a signer the wallet cannot
    /// decode with the decoder's `sa.deployment_failed`, and never reports
    /// the rule with an empty policy list.
    #[tokio::test]
    #[serial_test::serial(keyring)]
    async fn stellar_rules_get_refuses_a_rule_with_an_undecodable_signer() {
        use stellar_agent_core::profile::schema::Profile;
        use stellar_agent_test_support::{StellarAgentHomeGuard, keyring_mock};

        let home = tempfile::tempdir().expect("temp home");
        let _home_guard = StellarAgentHomeGuard::new(home.path());
        keyring_mock::install().expect("mock keyring store");

        let rpc = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .respond_with(RuleReadResponder)
            .mount(&rpc)
            .await;

        let mut profile = Profile::builder_testnet("svc", INTEROP_DEPLOYER_G, "n-svc", "n-acct")
            .with_noop_engine()
            .build();
        profile.rpc_url = rpc.uri();
        let server = WalletServer::new(profile).expect("WalletServer::new");

        let result = server
            .call_stellar_rules_get(StellarRulesGetArgs {
                chain_id: "stellar:testnet".to_owned(),
                smart_account: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM"
                    .to_owned(),
                rule_id: 0,
            })
            .await
            .expect("the refusal is a tool-level result");

        let (code, message, _) = crate::tools::common::assert_business_envelope(&result);
        assert_eq!(code, "sa.deployment_failed", "{message}");
        assert!(
            message.contains(
                "get_context_rule: signer at index 1 (id 1) is not a recognised Signer: \
                 unknown signer tag \"Future\""
            ),
            "{message}"
        );
    }
}
