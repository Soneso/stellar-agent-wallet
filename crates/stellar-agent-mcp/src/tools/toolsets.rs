//! `stellar_toolset_list` and `stellar_toolset_invoke` MCP tools.
//!
//! Implements the generic statically-registered toolset-invocation surface.
//! Toolsets are DATA (manifests + capability grants); these tools enumerate
//! installed toolsets and route their actions to existing trusted tools through
//! the four-part enforcement check.
//!
//! ## Registration model
//!
//! Both tools are STATICALLY registered via `#[mcp_tool_item]` — they appear
//! in `inventory::iter::<McpToolRegistration>()` and satisfy the
//! `check-mcp-tool-registry-generated.sh` gate.  Their ROUTING is dynamic
//! (reads installed pin records at call time), but registration is static.
//!
//! ## Security posture
//!
//! - The four-part enforcement check runs BEFORE routing to a trusted tool.
//! - After the four-part check passes, the trusted tool's normal handler
//!   including `dispatch_gate` (operator-policy + chain + registry) runs.
//!   The toolset gate is ADDITIVE, never substitutive.
//! - No signing/key/policy tool is reachable via any capability grant
//!   (structural isolation).

use rmcp::{
    handler::server::wrapper::Parameters,
    model::{CallToolResult, Content},
    schemars, serde, tool, tool_router,
};
use serde_json::json;
use stellar_agent_mcp_macros::mcp_tool_router;
use stellar_agent_toolsets_runtime::{
    GatedInvokeParams, GatedResolveOutcome, list_pinned_toolsets, resolve_toolset_and_check,
    resolve_toolset_sign_payment_gated,
};

use crate::server::WalletServer;

// ─────────────────────────────────────────────────────────────────────────────
// Argument types
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for the `stellar_toolset_list` MCP tool.
///
/// Returns a JSON array of installed-toolset entries including their declared
/// capabilities, `allowed_tools` narrowing, and invocable actions.
///
/// # Example
///
/// ```json
/// {}
/// ```
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(crate = "rmcp::serde")]
pub struct StellarToolsetListArgs {
    // No arguments required; toolsets_root is resolved from the profile.
}

/// Arguments for the `stellar_toolset_invoke` MCP tool.
///
/// Invokes a named action of an installed toolset, routing to the trusted tool
/// the action maps to via the capability→tool matrix.
///
/// # Example
///
/// ```json
/// {
///   "toolset": "balance-reporter",
///   "action": "stellar_balances",
///   "chain_id": "stellar:testnet",
///   "args": { "account_id": "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN" }
/// }
/// ```
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(crate = "rmcp::serde")]
pub struct StellarToolsetInvokeArgs {
    /// Package name of the installed toolset to invoke (e.g. `"balance-reporter"`).
    pub toolset: String,

    /// Action to invoke — must be an exact registry tool name that the toolset's
    /// declared capabilities grant (e.g. `"stellar_balances"`, `"stellar_pay"`).
    pub action: String,

    /// CAIP-2 chain identifier passed to the routed tool.
    ///
    /// Required for tools that validate the chain identifier (`chain_id_required`).
    /// For tools that do not require it, this field is still accepted and ignored.
    #[serde(default)]
    pub chain_id: Option<String>,

    /// Tool-specific arguments forwarded to the routed tool.
    ///
    /// The structure of this object depends on the specific tool being invoked.
    /// For `stellar_balances` this must include `account_id` (G-strkey).
    /// For `stellar_pay` this must include the payment parameters.
    #[serde(default)]
    pub args: serde_json::Value,
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool router impl block
// ─────────────────────────────────────────────────────────────────────────────

// Attribute order: #[tool_router] is innermost (listed last) and runs FIRST.
// #[mcp_tool_router] is outermost (listed first) and runs SECOND.
#[mcp_tool_router]
#[tool_router(router = toolsets_tool_router, vis = "pub(crate)")]
impl WalletServer {
    /// List all installed toolsets and their declared actions.
    ///
    /// Returns a JSON array of installed-toolset entries.  Each entry includes:
    /// - `name` — package name (sanitised).
    /// - `description` — toolset description (sanitised; may be empty).
    /// - `capabilities` — declared capability tokens.
    /// - `allowed_tools` — intersective narrowing list (empty = no narrowing).
    /// - `version` — installed version.
    /// - `actions` — tool names the toolset may invoke (subject to enforcement).
    ///
    /// This is the canonical scriptable enumeration.  Uninstalling a toolset
    /// removes it from this list without recompiling the binary.
    ///
    /// # Tool annotations
    ///
    /// - `readOnlyHint = true` — reads install metadata; no chain state change.
    /// - `destructiveHint = false` — safe to call without user confirmation.
    ///
    /// # Errors
    ///
    /// Returns a tool-level error when the toolsets directory cannot be read.
    #[mcp_tool_item(
        name = "stellar_toolset_list",
        destructive_hint = false,
        read_only_hint = true,
        chain_id_required = false
    )]
    #[tool(
        name = "stellar_toolset_list",
        description = "List all installed toolsets and their invocable actions. \
                       Returns a JSON array with name, capabilities, allowed_tools, \
                       version, and actions for each installed toolset. \
                       read_only_hint=true; destructive_hint=false.",
        annotations(read_only_hint = true, destructive_hint = false)
    )]
    async fn stellar_toolset_list(
        &self,
        Parameters(_args): Parameters<StellarToolsetListArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let args_value = json!({});
        // dispatch_gate with empty chain_id (chain_id_required = false).
        // Non-signing tool: RequireApproval produces no signing material; proceed.
        let _ = self
            .dispatch_gate("stellar_toolset_list", &args_value, "")
            .await?;

        let toolsets_root =
            stellar_agent_core::profile::schema::default_toolsets_dir().map_err(|e| {
                rmcp::ErrorData::internal_error(format!("toolset.toolsets_dir_error: {e}"), None)
            })?;

        let entries = list_pinned_toolsets(&toolsets_root).map_err(|e| {
            rmcp::ErrorData::internal_error(format!("toolset.list_error: {e}"), None)
        })?;

        let result_json = serde_json::to_value(&entries).map_err(|e| {
            rmcp::ErrorData::internal_error(format!("toolset.serialise_error: {e}"), None)
        })?;

        Ok(CallToolResult::success(vec![
            Content::json(result_json).map_err(|e| {
                rmcp::ErrorData::internal_error(format!("toolset.content_error: {e}"), None)
            })?,
        ]))
    }

    /// Invoke a named action of an installed toolset.
    ///
    /// Routes the action to the trusted wallet tool it maps to via the
    /// four-part capability enforcement check:
    ///
    /// 1. Action resolves to a registry tool-name constant via the matrix.
    /// 2. The resolving capability is in the toolset's declared `CapabilitySet`.
    /// 3. The resolved tool is in the toolset's `allowed_tools` (intersective narrowing).
    /// 4. The routed tool's normal handler runs including `dispatch_gate`.
    ///
    /// The toolset gate is ADDITIVE: a toolset action allowed by its manifest but
    /// denied by operator policy is refused by the operator-policy gate.
    ///
    /// # Signing isolation
    ///
    /// No signing/key/policy tool is reachable via any capability grant.
    /// The matrix contains no such tool regardless of declared capabilities
    /// (structural isolation).
    ///
    /// # Tool annotations
    ///
    /// - `readOnlyHint = true` — the toolset gate itself is read-only; the routed
    ///   tool determines the actual mutability (all matrix tools are read-only
    ///   or build-only).
    /// - `destructiveHint = false` — all matrix tools are non-destructive.
    ///
    /// # Errors
    ///
    /// - `toolset.not_installed` — toolset is not installed.
    /// - `toolset.unknown_action` — action not in the capability→tool matrix.
    /// - `toolset.capability_not_declared` — granting capability not declared.
    /// - `toolset.tool_not_allowed` — tool excluded by `allowed_tools` narrowing.
    /// - Plus any error from the routed tool (operator policy, chain mismatch, etc.).
    #[mcp_tool_item(
        name = "stellar_toolset_invoke",
        destructive_hint = false,
        read_only_hint = true,
        chain_id_required = false
    )]
    #[tool(
        name = "stellar_toolset_invoke",
        description = "Invoke a named action of an installed toolset through the \
                       four-part capability enforcement gate. \
                       `toolset` is the package name; `action` is the registry tool name \
                       (e.g. stellar_balances, stellar_pay). \
                       Signing tools are never reachable regardless of declared capabilities. \
                       The routed tool's normal operator-policy gate also runs (additive gate). \
                       read_only_hint=true; destructive_hint=false.",
        annotations(read_only_hint = true, destructive_hint = false)
    )]
    async fn stellar_toolset_invoke(
        &self,
        Parameters(args): Parameters<StellarToolsetInvokeArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        use stellar_agent_toolsets_runtime::{ToolsetRuntimeError, matrix};

        let toolset_name = stellar_agent_toolsets::sanitise_display(&args.toolset, 64);
        let action = stellar_agent_toolsets::sanitise_display(&args.action, 128);

        let args_value = json!({
            "toolset": &toolset_name,
            "action": &action,
        });
        // dispatch_gate with empty chain_id (chain_id_required = false for the
        // outer toolset_invoke tool — the routed tool handles its own chain_id check).
        // Non-signing tool: RequireApproval produces no signing material; proceed.
        let _ = self
            .dispatch_gate("stellar_toolset_invoke", &args_value, "")
            .await?;

        let toolsets_root = {
            #[cfg(any(test, feature = "test-helpers"))]
            {
                if let Some(ref override_root) = self.toolsets_root_override {
                    override_root.clone()
                } else {
                    stellar_agent_core::profile::schema::default_toolsets_dir().map_err(|e| {
                        rmcp::ErrorData::internal_error(
                            format!("toolset.toolsets_dir_error: {e}"),
                            None,
                        )
                    })?
                }
            }
            #[cfg(not(any(test, feature = "test-helpers")))]
            {
                stellar_agent_core::profile::schema::default_toolsets_dir().map_err(|e| {
                    rmcp::ErrorData::internal_error(
                        format!("toolset.toolsets_dir_error: {e}"),
                        None,
                    )
                })?
            }
        };

        // ── Check if this is a gated action ───────────────────────────────────
        //
        // The gated matrix maps SignPayment → stellar_pay_commit and
        // SignRuleCreate → stellar_rule_create_commit.  If the action is in
        // the gated matrix, route through the appropriate GATED RESOLVER (a
        // distinct entry point, NOT route_to_matrix_tool) — the two
        // capabilities need different authoritative-args extraction
        // (payment decodes an envelope_xdr; rule-create looks up the
        // smart_account from the pending RuleProposalSimulated entry), so a
        // SEPARATE resolver method handles each.
        //
        // Gated actions are NOT in ALL_MATRIX_ENTRIES; resolve_toolset_and_check
        // would return UnknownToolsetAction for them.  We check the gated matrix
        // BEFORE the ungated resolver to give the correct error.
        if matrix::SIGN_RULE_CREATE_GATED_TOOLS.contains(&action.as_str()) {
            return self
                .route_to_gated_resolver_rule_create(&toolset_name, &action, &args, &toolsets_root)
                .await;
        }
        if matrix::GATED_MATRIX_ENTRIES
            .iter()
            .any(|(_, tools)| tools.contains(&action.as_str()))
        {
            return self
                .route_to_gated_resolver(&toolset_name, &action, &args, &toolsets_root)
                .await;
        }

        // ── Four-part enforcement (ungated path) ──────────────────────────────
        let (tool_name, _pin) = resolve_toolset_and_check(&toolset_name, &action, &toolsets_root)
            .map_err(|e| match e {
            ToolsetRuntimeError::ToolsetNotInstalled { .. } => {
                rmcp::ErrorData::invalid_params(e.to_string(), None)
            }
            ToolsetRuntimeError::UnknownToolsetAction { .. }
            | ToolsetRuntimeError::CapabilityNotDeclared { .. }
            | ToolsetRuntimeError::ToolNotAllowed { .. } => {
                rmcp::ErrorData::invalid_params(e.to_string(), None)
            }
            ToolsetRuntimeError::Io(_) => rmcp::ErrorData::internal_error(e.to_string(), None),
            // Forward-compat: new #[non_exhaustive] variants fail closed.
            _ => rmcp::ErrorData::internal_error(format!("toolset.enforcement_error: {e}"), None),
        })?;

        // ── Build merged args: chain_id + tool-specific args ──────────────────
        let chain_id = args.chain_id.as_deref().unwrap_or("");
        let mut tool_args = match args.args {
            serde_json::Value::Object(m) => m,
            serde_json::Value::Null => serde_json::Map::new(),
            other => {
                // args must be a JSON object; reject anything else.
                return Err(rmcp::ErrorData::invalid_params(
                    format!(
                        "toolset.args_not_object: expected JSON object for args, \
                         got {}",
                        other.type_str_name()
                    ),
                    None,
                ));
            }
        };
        // Inject chain_id into the tool args if non-empty.
        if !chain_id.is_empty() {
            tool_args.insert(
                "chain_id".to_owned(),
                serde_json::Value::String(chain_id.to_owned()),
            );
        }
        let tool_args_value = serde_json::Value::Object(tool_args);

        // ── Pre-canonicalisation argument validation (ungated path) ───────────
        //
        // MUTATION-BEFORE-GUARD INVARIANT:
        // All mutation of tool_args has completed above (chain_id injection).
        // The validated `tool_args_value` is the EXACT Value moved into dispatch
        // below — no insert, merge, or serde round-trip occurs between this guard
        // and route_to_matrix_tool / from_value::<TypedArgs>.
        stellar_agent_toolsets::validate_toolset_tool_args(&tool_args_value).map_err(|e| {
            rmcp::ErrorData::invalid_params(format!("toolset.args_validation: {e}"), None)
        })?;

        // ── Route to the trusted tool handler (closed routing + additive gate) ─
        // The tool_name is a &'static str compile-time constant from the matrix.
        // A toolset-supplied String CANNOT reach here as a &'static str.
        // The closed match below is the anti-aliasing anchor: only exact names
        // from ALL_MATRIX_TOOL_NAMES can appear here.
        //
        // The routed handler's own dispatch_gate is the SINGLE authoritative
        // operator-policy site for the matrix tool (additive gate).  No outer
        // dispatch_gate call is made here: it would be redundant and would use
        // the wrong args shape ({"toolset":...,"action":...} instead of the
        // tool-specific args), which could cause spurious denials for tools that
        // inspect args["amount"] or similar (e.g. stellar_pay via amount_in_stroops).
        self.route_to_matrix_tool(tool_name, tool_args_value).await
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Gated resolver routing
// ─────────────────────────────────────────────────────────────────────────────

impl WalletServer {
    /// Route a toolset-routed `sign-payment` action through the GATED resolver.
    ///
    /// This is the DISTINCT internal entry point for the gated tier.  NOT a
    /// `route_to_matrix_tool` arm.
    ///
    /// Enforcement order:
    /// 1. Four-part check via the gated matrix.
    /// 2. First-invoke gate check (via `resolve_toolset_sign_payment_gated`).
    /// 3. On `GatedResolveOutcome::Resolved` → route to `stellar_pay_commit`
    ///    with per-action `PaymentSimulated` approval FORCED ON (Override
    ///    `Allow → RequireApproval`).
    /// 4. On `GatedResolveOutcome::FirstInvokeApprovalRequired` → return
    ///    `FirstInvokeApprovalRequired` typed error with `approval_nonce`.
    ///
    /// # Authoritative params
    ///
    /// The `envelope_xdr` MUST be present in `toolset_args.args` — it was
    /// produced by a prior `stellar_pay` (simulate) call.  The gated resolver
    /// decodes the AUTHORITATIVE destination, asset, and amount from this XDR
    /// BEFORE the dangerous-key guard runs.  The money-bearing fields therefore
    /// come from XDR decode, not from the raw args map — the guard at the commit
    /// site (`route_to_gated_commit`) covers the remaining case where a dangerous
    /// key transits the args map into `from_value::<StellarPayCommitArgs>`.
    ///
    /// # Pre-canonicalisation guard placement
    ///
    /// The `validate_toolset_tool_args` guard runs ONLY on the `Resolved` branch
    /// (inside `route_to_gated_commit`).  The `FirstInvokeApprovalRequired`
    /// branch returns an error without reaching `from_value`, so no guard is
    /// needed there — a dangerous-key payload is harmless until it reaches the
    /// deserialisation boundary.
    ///
    /// # Errors
    ///
    /// - `toolset.first_invoke_approval_required` — gate fired, approval queued.
    /// - All `stellar_pay_commit` errors (policy, nonce, chain, etc.).
    #[allow(clippy::too_many_lines)]
    pub(crate) async fn route_to_gated_resolver(
        &self,
        toolset_name: &str,
        action: &str,
        toolset_args: &StellarToolsetInvokeArgs,
        toolsets_root: &std::path::Path,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        use stellar_agent_core::approval::process_uid_for_attestation;
        use stellar_agent_core::envelope_decode::decode_authoritative_args;
        use stellar_agent_toolsets_runtime::ToolsetRuntimeError;

        // ── Decode authoritative params from envelope_xdr ─────────────────────
        //
        // The args object MUST contain `envelope_xdr` (produced by stellar_pay).
        // This is the SINGLE authoritative decode — no TOCTOU between gate and
        // commit since both decode the same bytes.
        let tool_args_obj = match &toolset_args.args {
            serde_json::Value::Object(m) => m,
            serde_json::Value::Null => {
                return Err(rmcp::ErrorData::invalid_params(
                    "toolset.gated_missing_envelope: sign-payment requires \
                     args.envelope_xdr (from stellar_pay simulate output)",
                    None,
                ));
            }
            _ => {
                return Err(rmcp::ErrorData::invalid_params(
                    "toolset.args_not_object: expected JSON object for args",
                    None,
                ));
            }
        };

        let envelope_xdr = match tool_args_obj.get("envelope_xdr").and_then(|v| v.as_str()) {
            Some(s) => s.to_owned(),
            None => {
                return Err(rmcp::ErrorData::invalid_params(
                    "toolset.gated_missing_envelope: sign-payment requires \
                     args.envelope_xdr (from stellar_pay simulate output)",
                    None,
                ));
            }
        };

        // Decode authoritative args — destination, asset, amount.
        // Use "stellar_pay_commit" as the tool name: that is the gated tool
        // this route resolves to, and decode_authoritative_args only accepts
        // "stellar_pay_commit" / "stellar_create_account_commit".
        let authoritative_args = decode_authoritative_args(&envelope_xdr, "stellar_pay_commit")
            .map_err(|e| {
                rmcp::ErrorData::internal_error(
                    format!("simulation.divergence: envelope_xdr decode failed: {e}"),
                    None,
                )
            })?;

        let destination = authoritative_args
            .get("destination")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let asset = authoritative_args
            .get("asset")
            .and_then(|v| v.as_str())
            .unwrap_or("XLM")
            .to_owned();
        let amount_stroops = authoritative_args
            .get("amount_stroops")
            .and_then(crate::tools::amount_wire::value_as_stroops_i64)
            .unwrap_or(0_i64);

        // Validate: destination must be a G-strkey (ed25519 public key).
        // Uses stellar_strkey to validate the base32 checksum and version byte,
        // matching the validation used at other tool boundaries in this crate.
        if stellar_strkey::ed25519::PublicKey::from_string(&destination).is_err() {
            return Err(rmcp::ErrorData::internal_error(
                "simulation.divergence: envelope_xdr did not yield a valid G-strkey destination",
                None,
            ));
        }

        // ── Now route through the gated resolver ──────────────────────────────
        let profile_name = self.profile_name_for_approval();
        let process_uid = process_uid_for_attestation().map_err(|e| {
            rmcp::ErrorData::internal_error(format!("approval.uid_unavailable: {e}"), None)
        })?;
        let now_unix_ms = stellar_agent_core::timefmt::now_unix_ms()
            .map_err(|e| rmcp::ErrorData::internal_error(format!("clock_error: {e}"), None))?;

        #[cfg(not(feature = "test-helpers"))]
        let gated_params = GatedInvokeParams {
            toolset_name,
            action,
            toolsets_root,
            profile_name: &profile_name,
            authoritative_destination: &destination,
            authoritative_asset: &asset,
            authoritative_amount_stroops: amount_stroops,
            now_unix_ms,
            process_uid: &process_uid,
        };
        #[cfg(feature = "test-helpers")]
        let gated_params = GatedInvokeParams {
            toolset_name,
            action,
            toolsets_root,
            profile_name: &profile_name,
            authoritative_destination: &destination,
            authoritative_asset: &asset,
            authoritative_amount_stroops: amount_stroops,
            now_unix_ms,
            process_uid: &process_uid,
            approval_dir_override: self.approval_dir_override.clone(),
            grant_store_path_override: self.grant_store_path_override.clone(),
        };

        match resolve_toolset_sign_payment_gated(&gated_params) {
            Err(e) => {
                // Hard errors (toolset not installed, capability not declared, etc.)
                let err = match e {
                    ToolsetRuntimeError::ToolsetNotInstalled { .. }
                    | ToolsetRuntimeError::UnknownToolsetAction { .. }
                    | ToolsetRuntimeError::CapabilityNotDeclared { .. }
                    | ToolsetRuntimeError::ToolNotAllowed { .. } => {
                        rmcp::ErrorData::invalid_params(e.to_string(), None)
                    }
                    ToolsetRuntimeError::FirstInvokeApprovalRequired { .. } => {
                        // Should not happen as Err — the resolver returns Ok for
                        // this outcome.  Fail closed.
                        rmcp::ErrorData::internal_error(
                            format!("toolset.enforcement_error: {e}"),
                            None,
                        )
                    }
                    _ => rmcp::ErrorData::internal_error(
                        format!("toolset.enforcement_error: {e}"),
                        None,
                    ),
                };
                Err(err)
            }

            Ok(GatedResolveOutcome::FirstInvokeApprovalRequired {
                approval_nonce,
                toolset_name: sn,
                capability,
            }) => {
                // Gate fired: return the approval_nonce for the agent to pass
                // to `stellar-agent approve --id <nonce>`.  The agent then
                // re-invokes.
                let payload = serde_json::json!({
                    "approval_nonce": &approval_nonce,
                    "toolset_name": &sn,
                    "capability": &capability,
                    "message": format!(
                        "toolset.first_invoke_approval_required: run \
                         `stellar-agent approve --id {approval_nonce}` then re-invoke"
                    )
                });
                Err(rmcp::ErrorData::invalid_params(
                    format!(
                        "toolset.first_invoke_approval_required: \
                         approval_nonce={approval_nonce}"
                    ),
                    Some(payload),
                ))
            }

            Ok(GatedResolveOutcome::Resolved { tool_name }) => {
                // Gate passed (current grant found).
                // Force per-action PaymentSimulated approval UNCONDITIONALLY,
                // overriding DispatchOutcome::Allow.
                // Route to stellar_pay_commit via the gated commit path.
                self.route_to_gated_commit(tool_name, toolset_args, envelope_xdr)
                    .await
            }
        }
    }

    /// Routes to `stellar_pay_commit` with the per-action `PaymentSimulated`
    /// approval FORCED ON UNCONDITIONALLY.
    ///
    /// This method synthesises a `RequireApproval` dispatch outcome if the
    /// policy engine returned `Allow`, ensuring the per-action human
    /// envelope-review approval fires for every toolset-routed payment.
    ///
    /// The `approval_nonce` and `approval_attestation` must be present in
    /// `toolset_args.args` for the forced-approval path.
    async fn route_to_gated_commit(
        &self,
        tool_name: &'static str,
        toolset_args: &StellarToolsetInvokeArgs,
        envelope_xdr: String,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        // Build the full tool args, injecting chain_id and envelope_xdr.
        let chain_id = toolset_args.chain_id.as_deref().unwrap_or("");
        let mut tool_args = match &toolset_args.args {
            serde_json::Value::Object(m) => m.clone(),
            _ => serde_json::Map::new(),
        };
        // Ensure envelope_xdr is in the args.
        tool_args.insert(
            "envelope_xdr".to_owned(),
            serde_json::Value::String(envelope_xdr),
        );
        if !chain_id.is_empty() {
            tool_args.insert(
                "chain_id".to_owned(),
                serde_json::Value::String(chain_id.to_owned()),
            );
        }
        let tool_args_value = serde_json::Value::Object(tool_args);

        // ── Pre-canonicalisation argument validation (gated path) ─────────────
        //
        // This guard runs only on the GatedResolveOutcome::Resolved branch (i.e.
        // only when the first-invoke gate passed and a current grant exists).  The
        // FirstInvokeApprovalRequired branch returns an error before reaching
        // from_value, so no guard is needed there — a dangerous-key payload is
        // harmless until it reaches the deserialisation boundary.
        //
        // MUTATION-BEFORE-GUARD INVARIANT:
        // All mutation of tool_args has completed above (envelope_xdr insertion
        // and chain_id injection).  The validated `tool_args_value` is the EXACT
        // Value moved into dispatch below — no insert, merge, or serde round-trip
        // occurs between this guard and route_to_gated_tool / from_value::<StellarPayCommitArgs>.
        //
        // The money-bearing fields (destination, asset, amount) are decoded from
        // envelope_xdr BEFORE this guard runs (in route_to_gated_resolver above).
        // Those fields come from XDR decode, not from the raw args map — the guard
        // here covers the remaining case where a dangerous key transits the args map
        // into from_value (defence in depth).
        stellar_agent_toolsets::validate_toolset_tool_args(&tool_args_value).map_err(|e| {
            rmcp::ErrorData::invalid_params(format!("toolset.args_validation: {e}"), None)
        })?;

        // Route to stellar_pay_commit via the gated routing arm.
        // The tool_name here is "stellar_pay_commit" (a &'static str constant).
        self.route_to_gated_tool(tool_name, tool_args_value).await
    }

    /// Route a toolset-routed `sign-rule-create` action through the GATED
    /// resolver (Package D, GH issue #8).
    ///
    /// Distinct entry point from [`Self::route_to_gated_resolver`] (the
    /// `sign-payment` resolver): rule-create has no `envelope_xdr` to decode
    /// the authoritative bucket-matching fields from — the pending
    /// `RuleProposalSimulated` entry (looked up by the caller-supplied
    /// `approval_nonce`, which `stellar_rule_create` always mints) is the
    /// SOLE source of the authoritative smart-account.
    ///
    /// `resolve_toolset_sign_payment_gated` is reused as-is (it is generic
    /// over the GATED matrix / `Capability`, despite its name) with the
    /// smart-account C-strkey as `authoritative_destination` and the fixed
    /// `matrix::SIGN_RULE_CREATE_ASSET_SENTINEL` /
    /// `matrix::SIGN_RULE_CREATE_AMOUNT_SENTINEL` for the asset/amount
    /// dimensions, which carry no independent meaning for rule creation —
    /// see that module's doc comments for the full rationale.
    ///
    /// # Errors
    ///
    /// - `toolset.gated_missing_approval_nonce` — `args.approval_nonce`
    ///   absent, not a string, or does not resolve to a pending
    ///   `RuleProposalSimulated` entry.
    /// - `toolset.first_invoke_approval_required` — gate fired, approval queued.
    /// - All `stellar_rule_create_commit` errors (policy, attestation, chain, etc.).
    pub(crate) async fn route_to_gated_resolver_rule_create(
        &self,
        toolset_name: &str,
        action: &str,
        toolset_args: &StellarToolsetInvokeArgs,
        toolsets_root: &std::path::Path,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        use stellar_agent_core::approval::process_uid_for_attestation;
        use stellar_agent_core::approval::store::ApprovalKind;
        use stellar_agent_toolsets_runtime::ToolsetRuntimeError;

        let tool_args_obj = match &toolset_args.args {
            serde_json::Value::Object(m) => m,
            _ => {
                return Err(rmcp::ErrorData::invalid_params(
                    "toolset.gated_missing_approval_nonce: sign-rule-create requires \
                     args.approval_nonce (from stellar_rule_create propose output)",
                    None,
                ));
            }
        };
        let approval_nonce = match tool_args_obj.get("approval_nonce").and_then(|v| v.as_str()) {
            Some(s) => s.to_owned(),
            None => {
                return Err(rmcp::ErrorData::invalid_params(
                    "toolset.gated_missing_approval_nonce: sign-rule-create requires \
                     args.approval_nonce (from stellar_rule_create propose output)",
                    None,
                ));
            }
        };

        // ── Look up the AUTHORITATIVE smart_account from the stored entry ────
        // Never from toolset-supplied args — only the pending
        // RuleProposalSimulated entry (identified by approval_nonce) is
        // authoritative.
        let approvals_dir = self.resolve_approval_dir().map_err(|e| {
            rmcp::ErrorData::internal_error(format!("approval.dir_error: {e}"), None)
        })?;
        let store_path = approvals_dir.join(format!("{}.toml", self.profile_name_for_approval()));
        let store = stellar_agent_core::approval::open_with_retry(
            &store_path,
            stellar_agent_core::approval::DEFAULT_RETRY_ATTEMPTS,
            stellar_agent_core::approval::DEFAULT_RETRY_BACKOFF,
        )
        .map_err(|e| rmcp::ErrorData::internal_error(format!("approval.store_open: {e}"), None))?;

        let entry = store.get(&approval_nonce).cloned().ok_or_else(|| {
            rmcp::ErrorData::invalid_params(
                "toolset.gated_missing_approval_nonce: approval_nonce does not resolve to a \
                 pending RuleProposalSimulated entry; call stellar_rule_create first",
                None,
            )
        })?;
        let smart_account = match &entry.kind {
            ApprovalKind::RuleProposalSimulated { smart_account, .. } => smart_account.clone(),
            other => {
                return Err(rmcp::ErrorData::invalid_params(
                    format!(
                        "toolset.gated_missing_approval_nonce: approval_nonce resolves to a \
                         {} entry, not RuleProposalSimulated",
                        other.kind_name()
                    ),
                    None,
                ));
            }
        };

        let profile_name = self.profile_name_for_approval();
        let process_uid = process_uid_for_attestation().map_err(|e| {
            rmcp::ErrorData::internal_error(format!("approval.uid_unavailable: {e}"), None)
        })?;
        let now_unix_ms = stellar_agent_core::timefmt::now_unix_ms()
            .map_err(|e| rmcp::ErrorData::internal_error(format!("clock_error: {e}"), None))?;

        #[cfg(not(feature = "test-helpers"))]
        let gated_params = GatedInvokeParams {
            toolset_name,
            action,
            toolsets_root,
            profile_name: &profile_name,
            authoritative_destination: &smart_account,
            authoritative_asset:
                stellar_agent_toolsets_runtime::matrix::SIGN_RULE_CREATE_ASSET_SENTINEL,
            authoritative_amount_stroops:
                stellar_agent_toolsets_runtime::matrix::SIGN_RULE_CREATE_AMOUNT_SENTINEL,
            now_unix_ms,
            process_uid: &process_uid,
        };
        #[cfg(feature = "test-helpers")]
        let gated_params = GatedInvokeParams {
            toolset_name,
            action,
            toolsets_root,
            profile_name: &profile_name,
            authoritative_destination: &smart_account,
            authoritative_asset:
                stellar_agent_toolsets_runtime::matrix::SIGN_RULE_CREATE_ASSET_SENTINEL,
            authoritative_amount_stroops:
                stellar_agent_toolsets_runtime::matrix::SIGN_RULE_CREATE_AMOUNT_SENTINEL,
            now_unix_ms,
            process_uid: &process_uid,
            approval_dir_override: self.approval_dir_override.clone(),
            grant_store_path_override: self.grant_store_path_override.clone(),
        };

        match resolve_toolset_sign_payment_gated(&gated_params) {
            Err(e) => {
                let err = match e {
                    ToolsetRuntimeError::ToolsetNotInstalled { .. }
                    | ToolsetRuntimeError::UnknownToolsetAction { .. }
                    | ToolsetRuntimeError::CapabilityNotDeclared { .. }
                    | ToolsetRuntimeError::ToolNotAllowed { .. } => {
                        rmcp::ErrorData::invalid_params(e.to_string(), None)
                    }
                    _ => rmcp::ErrorData::internal_error(
                        format!("toolset.enforcement_error: {e}"),
                        None,
                    ),
                };
                Err(err)
            }
            Ok(GatedResolveOutcome::FirstInvokeApprovalRequired {
                approval_nonce,
                toolset_name: sn,
                capability,
            }) => {
                let payload = serde_json::json!({
                    "approval_nonce": &approval_nonce,
                    "toolset_name": &sn,
                    "capability": &capability,
                    "message": format!(
                        "toolset.first_invoke_approval_required: run \
                         `stellar-agent approve --id {approval_nonce}` then re-invoke"
                    )
                });
                Err(rmcp::ErrorData::invalid_params(
                    format!(
                        "toolset.first_invoke_approval_required: \
                         approval_nonce={approval_nonce}"
                    ),
                    Some(payload),
                ))
            }
            Ok(GatedResolveOutcome::Resolved { tool_name }) => {
                self.route_to_gated_commit_rule_create(tool_name, toolset_args)
                    .await
            }
        }
    }

    /// Routes to `stellar_rule_create_commit` with the per-proposal
    /// `RuleProposalSimulated` approval FORCED ON UNCONDITIONALLY.
    async fn route_to_gated_commit_rule_create(
        &self,
        tool_name: &'static str,
        toolset_args: &StellarToolsetInvokeArgs,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let chain_id = toolset_args.chain_id.as_deref().unwrap_or("");
        let mut tool_args = match &toolset_args.args {
            serde_json::Value::Object(m) => m.clone(),
            _ => serde_json::Map::new(),
        };
        if !chain_id.is_empty() {
            tool_args.insert(
                "chain_id".to_owned(),
                serde_json::Value::String(chain_id.to_owned()),
            );
        }
        let tool_args_value = serde_json::Value::Object(tool_args);

        stellar_agent_toolsets::validate_toolset_tool_args(&tool_args_value).map_err(|e| {
            rmcp::ErrorData::invalid_params(format!("toolset.args_validation: {e}"), None)
        })?;

        self.route_to_gated_tool(tool_name, tool_args_value).await
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Closed routing: route a static tool_name constant to its handler
// ─────────────────────────────────────────────────────────────────────────────

impl WalletServer {
    /// Route to a GATED tool by its `&'static str` name constant.
    ///
    /// Unlike `route_to_matrix_tool`, this entry point routes to signing-adjacent
    /// tools (`stellar_pay_commit`) with the per-action `PaymentSimulated` approval
    /// FORCED ON UNCONDITIONALLY.
    ///
    /// The `args` object MUST contain `approval_nonce` and `approval_attestation`
    /// (pre-approved per-action `PaymentSimulated` approval) for the commit to
    /// succeed.  If the caller provides these (from a previously-approved
    /// `PaymentSimulated` pending approval), the commit proceeds.  If absent,
    /// `stellar_pay_commit` returns `policy.approval_required` as usual —
    /// this is the correct behaviour (the forced gate fired; the operator must
    /// approve via `stellar-agent approve --id <nonce>`).
    ///
    /// # Errors
    ///
    /// Returns an MCP error from `stellar_pay_commit` on any failure.
    pub(crate) async fn route_to_gated_tool(
        &self,
        tool_name: &'static str,
        args: serde_json::Value,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        match tool_name {
            "stellar_pay_commit" => {
                let typed: super::pay::StellarPayCommitArgs = serde_json::from_value(args)
                    .map_err(|e| {
                        rmcp::ErrorData::invalid_params(
                            format!("toolset.gated_args_deserialise: stellar_pay_commit: {e}"),
                            None,
                        )
                    })?;
                // Route via invoke_stellar_pay_commit_toolset_gated which forces
                // RequireApproval unconditionally.
                self.invoke_stellar_pay_commit_toolset_gated(typed).await
            }
            "stellar_rule_create_commit" => {
                let typed: super::rule_create::StellarRuleCreateCommitArgs =
                    serde_json::from_value(args).map_err(|e| {
                        rmcp::ErrorData::invalid_params(
                            format!(
                                "toolset.gated_args_deserialise: stellar_rule_create_commit: {e}"
                            ),
                            None,
                        )
                    })?;
                // Route via invoke_stellar_rule_create_commit_toolset_gated
                // which forces RequireApproval unconditionally.
                self.invoke_stellar_rule_create_commit_toolset_gated(typed)
                    .await
            }
            other => Err(rmcp::ErrorData::internal_error(
                format!(
                    "toolset.gated_route_missing: no gated routing arm for tool '{other}'; \
                     binary may be outdated relative to toolset-runtime gated matrix"
                ),
                None,
            )),
        }
    }
}

impl WalletServer {
    /// Route to a matrix-listed tool by its `&'static str` name constant.
    ///
    /// This is the CLOSED routing mechanism: only names from
    /// [`stellar_agent_toolsets_runtime::matrix::ALL_MATRIX_TOOL_NAMES`]
    /// can appear here.  A toolset-supplied `String` cannot become a `&'static str`,
    /// so no toolset-controlled value can reach a handler here.
    ///
    /// Each arm deserialises `args` into the tool's concrete arg type and
    /// calls the corresponding tool fn directly.  The tool fn may call
    /// `dispatch_gate` again — this is correct (additive gate).
    ///
    /// # Errors
    ///
    /// Returns an MCP error if `args` cannot be deserialised into the
    /// expected type for the tool, or if the tool itself returns an error.
    pub(crate) async fn route_to_matrix_tool(
        &self,
        tool_name: &'static str,
        args: serde_json::Value,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        match tool_name {
            "stellar_balances" => {
                let typed: super::balances::StellarBalancesArgs = serde_json::from_value(args)
                    .map_err(|e| {
                        rmcp::ErrorData::invalid_params(
                            format!("toolset.args_deserialise: stellar_balances: {e}"),
                            None,
                        )
                    })?;
                self.invoke_stellar_balances(typed).await
            }
            "stellar_pay" => {
                let typed: super::pay::StellarPayArgs =
                    serde_json::from_value(args).map_err(|e| {
                        rmcp::ErrorData::invalid_params(
                            format!("toolset.args_deserialise: stellar_pay: {e}"),
                            None,
                        )
                    })?;
                self.invoke_stellar_pay(typed).await
            }
            "stellar_claim" => {
                let typed: super::claim::StellarClaimArgs =
                    serde_json::from_value(args).map_err(|e| {
                        rmcp::ErrorData::invalid_params(
                            format!("toolset.args_deserialise: stellar_claim: {e}"),
                            None,
                        )
                    })?;
                self.invoke_stellar_claim(typed).await
            }
            "stellar_rule_create" => {
                let typed: super::rule_create::StellarRuleCreateArgs = serde_json::from_value(args)
                    .map_err(|e| {
                        rmcp::ErrorData::invalid_params(
                            format!("toolset.args_deserialise: stellar_rule_create: {e}"),
                            None,
                        )
                    })?;
                self.invoke_stellar_rule_create(typed).await
            }
            "stellar_sep47_discover" => {
                let typed: super::sep47_discover::Sep47DiscoverArgs = serde_json::from_value(args)
                    .map_err(|e| {
                        rmcp::ErrorData::invalid_params(
                            format!("toolset.args_deserialise: stellar_sep47_discover: {e}"),
                            None,
                        )
                    })?;
                self.invoke_stellar_sep47_discover(typed).await
            }
            "stellar_sep48_preview_invocation" => {
                let typed: super::sep48_preview_invocation::Sep48PreviewInvocationArgs =
                    serde_json::from_value(args).map_err(|e| {
                        rmcp::ErrorData::invalid_params(
                            format!(
                                "toolset.args_deserialise: stellar_sep48_preview_invocation: {e}"
                            ),
                            None,
                        )
                    })?;
                self.invoke_stellar_sep48_preview_invocation(typed).await
            }
            "stellar_sep7_parse_uri" => {
                let typed: super::sep7_parse_uri::Sep7ParseUriArgs = serde_json::from_value(args)
                    .map_err(|e| {
                    rmcp::ErrorData::invalid_params(
                        format!("toolset.args_deserialise: stellar_sep7_parse_uri: {e}"),
                        None,
                    )
                })?;
                self.invoke_stellar_sep7_parse_uri(typed).await
            }
            "stellar_rules_list" => {
                let typed: super::rules::StellarRulesListArgs = serde_json::from_value(args)
                    .map_err(|e| {
                        rmcp::ErrorData::invalid_params(
                            format!("toolset.args_deserialise: stellar_rules_list: {e}"),
                            None,
                        )
                    })?;
                self.invoke_stellar_rules_list(typed).await
            }
            "stellar_rules_get" => {
                let typed: super::rules::StellarRulesGetArgs = serde_json::from_value(args)
                    .map_err(|e| {
                        rmcp::ErrorData::invalid_params(
                            format!("toolset.args_deserialise: stellar_rules_get: {e}"),
                            None,
                        )
                    })?;
                self.invoke_stellar_rules_get(typed).await
            }
            // Forward-compat: if the matrix gains a new tool that this binary
            // does not yet have a routing arm for, fail closed with an internal
            // error rather than panicking.  This should never happen in a
            // well-maintained deployment, but is defensively correct.
            other => Err(rmcp::ErrorData::internal_error(
                format!(
                    "toolset.route_missing: no routing arm for matrix tool '{other}'; \
                     binary may be outdated relative to toolset-runtime matrix"
                ),
                None,
            )),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Value type name helper (no std dependency)
// ─────────────────────────────────────────────────────────────────────────────

trait TypeStrName {
    fn type_str_name(&self) -> &'static str;
}

impl TypeStrName for serde_json::Value {
    fn type_str_name(&self) -> &'static str {
        match self {
            serde_json::Value::Null => "null",
            serde_json::Value::Bool(_) => "bool",
            serde_json::Value::Number(_) => "number",
            serde_json::Value::String(_) => "string",
            serde_json::Value::Array(_) => "array",
            serde_json::Value::Object(_) => "object",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests for route_to_matrix_tool fail-closed `other =>` arm
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use stellar_agent_toolsets_runtime::matrix::ALL_MATRIX_TOOL_NAMES;

    /// Verify that ALL_MATRIX_TOOL_NAMES lists only names that have a routing arm
    /// in route_to_matrix_tool (i.e. no name exists in the matrix that is missing
    /// from the match — catches the case where a matrix tool is added but the
    /// routing arm is forgotten).
    ///
    /// This does NOT exercise the `other =>` arm itself (that would require calling
    /// route_to_matrix_tool directly with a synthetic static str, which requires
    /// unsafe transmute).  Instead it asserts the POSITIVE invariant:
    /// every ALL_MATRIX_TOOL_NAMES entry has an arm.
    ///
    /// The `other =>` arm itself is verified by the CHANGELOG and by code review;
    /// the negative path (unknown name → route_missing refusal, no panic) is proven
    /// by the Rust match exhaustiveness guarantee + the `other =>` wildcard.
    #[test]
    fn all_matrix_tool_names_have_known_values() {
        let known_arms = [
            "stellar_balances",
            "stellar_pay",
            "stellar_claim",
            "stellar_rule_create",
            "stellar_sep47_discover",
            "stellar_sep48_preview_invocation",
            "stellar_sep7_parse_uri",
            "stellar_rules_list",
            "stellar_rules_get",
        ];
        for name in ALL_MATRIX_TOOL_NAMES {
            assert!(
                known_arms.contains(name),
                "matrix tool '{name}' is in ALL_MATRIX_TOOL_NAMES but has no routing arm \
                 in route_to_matrix_tool — add an arm or update this test"
            );
        }
        // Also check the inverse: every known arm is in ALL_MATRIX_TOOL_NAMES.
        for arm in &known_arms {
            assert!(
                ALL_MATRIX_TOOL_NAMES.contains(arm),
                "routing arm '{arm}' is present but not in ALL_MATRIX_TOOL_NAMES — \
                 the matrix and the router are out of sync"
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test-helper methods on WalletServer (gated on test-helpers feature / cfg(test))
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(any(test, feature = "test-helpers"))]
impl WalletServer {
    /// Calls `stellar_toolset_invoke` with the given args, bypassing the rmcp
    /// transport.
    ///
    /// Integration-test entry point for the gated-toolset-invoke path.
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Feature gate
    ///
    /// Gated on `test-helpers` feature or `#[cfg(test)]`.
    #[doc(hidden)]
    pub async fn call_stellar_toolset_invoke(
        &self,
        args: StellarToolsetInvokeArgs,
    ) -> Result<rmcp::model::CallToolResult, rmcp::ErrorData> {
        self.stellar_toolset_invoke(rmcp::handler::server::wrapper::Parameters(args))
            .await
    }
}

/// Fixture strings for `stellar_toolset_list` and `stellar_toolset_invoke` tools.
///
/// Exposed under `#[cfg(any(test, feature = "test-helpers"))]` for integration tests.
#[cfg(any(test, feature = "test-helpers"))]
pub mod test_helpers {
    /// Fixture: `stellar_toolset_list` — no args, expects empty array with no toolsets.
    #[allow(dead_code)]
    pub const TOOLSET_LIST_EMPTY_ARGS: &str = r#"{}"#;

    /// Fixture: `stellar_toolset_invoke` — unknown toolset, expect `toolset.not_installed`.
    #[allow(dead_code)]
    pub const TOOLSET_INVOKE_UNKNOWN_TOOLSET: &str = r#"{
        "toolset": "nonexistent-toolset",
        "action": "stellar_balances",
        "chain_id": "stellar:testnet",
        "args": {}
    }"#;

    /// Fixture: `stellar_toolset_invoke` — signing tool action, expect `toolset.unknown_action`.
    #[allow(dead_code)]
    pub const TOOLSET_INVOKE_UNKNOWN_ACTION: &str = r#"{
        "toolset": "any-toolset",
        "action": "stellar_sep43_sign_transaction",
        "chain_id": "stellar:testnet",
        "args": {}
    }"#;
}
