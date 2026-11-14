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
//! - The toolset's capabilities are read from its install record, which is
//!   authenticated by an HMAC under the installation's toolset pin key in the
//!   platform keyring and carries the `TOOLSET.md` digest both resolver tiers
//!   check. A record that does not verify refuses with
//!   `toolset.pin_unverifiable`.
//! - The four-part enforcement check runs BEFORE routing to a trusted tool.
//! - After the four-part check passes, the trusted tool's normal handler
//!   including `dispatch_gate` (operator-policy + chain + registry) runs.
//!   The toolset gate is ADDITIVE, never substitutive.
//! - No signing/key/policy tool is reachable via an ungated capability grant;
//!   the signing actions (sign-payment, sign-rule-create) route to the signing
//!   commit tools only behind a first-invoke grant and a per-action approval.
//! - `stellar_toolset_invoke` is annotated destructive, so on mainnet the
//!   default policy engine refuses it.
//! - A toolset narrows what this dispatcher routes. It does not restrict the
//!   native tools the same server registers, the `toolset` argument is chosen
//!   by the caller, and no session is bound to a toolset; the operator policy
//!   and the approvals bound native and routed calls alike.

use rmcp::{
    handler::server::wrapper::Parameters,
    model::{CallToolResult, Content},
    schemars, serde, tool, tool_router,
};
use serde_json::json;
use stellar_agent_core::profile::schema::KeyringEntryRef;
use stellar_agent_mcp_macros::mcp_tool_router;
use stellar_agent_toolsets_runtime::{
    GatedInvokeParams, GatedResolveOutcome, PinKey, list_pinned_toolsets,
    resolve_toolset_and_check, resolve_toolset_sign_payment_gated,
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

/// Resolves payment effects for an outer gate without mainnet context.
/// Commit effects come from the envelope; preparation uses routed arguments.
fn toolset_payment_value(
    action: &str,
    args: &serde_json::Value,
    chain: Option<&str>,
    has_mainnet_context: bool,
) -> Option<stellar_agent_core::policy::v1::ValueClass> {
    use stellar_agent_core::envelope_decode::decode_authoritative_args;
    use stellar_agent_core::policy::v1::value::derive_value_class;
    if has_mainnet_context {
        return None;
    }
    let object = args.as_object()?;
    match action {
        "stellar_pay_commit" => object
            .get("envelope_xdr")
            .and_then(serde_json::Value::as_str)
            .and_then(|envelope| decode_authoritative_args(envelope, "stellar_pay_commit").ok())
            .map(|authoritative| derive_value_class("stellar_pay_commit", &authoritative)),
        "stellar_pay" => {
            let mut merged = object.clone();
            if let Some(chain) = chain.filter(|chain| !chain.is_empty()) {
                merged.insert("chain_id".into(), chain.into());
            }
            let fields: GatedPaymentFields = serde_json::from_value(args.clone()).ok()?;
            let (_, amount) = super::pay::parse_asset_and_amount(
                &fields.asset,
                fields.amount,
                fields.amount_in_stroops,
            )
            .ok()?;
            merged.insert(
                "amount_stroops".into(),
                amount.as_stroops().to_string().into(),
            );
            Some(derive_value_class(
                "stellar_pay",
                &serde_json::Value::Object(merged),
            ))
        }
        _ => None,
    }
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
    /// removes it from this list without recompiling the binary.  A toolset
    /// whose install record does not verify under the installation's pin key
    /// is left out; without a pin key the list is empty.
    ///
    /// # Tool annotations
    ///
    /// - `readOnlyHint = true` — reads install metadata; no chain state change.
    /// - `destructiveHint = false` — safe to call without user confirmation.
    ///
    /// # Errors
    ///
    /// Returns a tool-level error when the toolsets directory cannot be read,
    /// or when the pin key cannot be read for a reason other than its absence.
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
        if let Err(e) = self
            .dispatch_gate("stellar_toolset_list", &args_value, "")
            .await
        {
            return e.into_result();
        }

        let toolsets_root =
            stellar_agent_core::profile::schema::default_toolsets_dir().map_err(|e| {
                rmcp::ErrorData::internal_error(format!("toolset.toolsets_dir_error: {e}"), None)
            })?;

        let pin_key = self.toolset_pin_key()?;
        let entries = list_pinned_toolsets(&toolsets_root, pin_key.as_ref()).map_err(|e| {
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
    /// 2. The resolving capability is in the toolset's declared `CapabilitySet`,
    ///    read from its authenticated install record.
    /// 3. The resolved tool is in the toolset's `allowed_tools` (intersective narrowing).
    /// 4. The routed tool's normal handler runs including `dispatch_gate`.
    ///
    /// The toolset gate is ADDITIVE: a toolset action allowed by its manifest but
    /// denied by operator policy is refused by the operator-policy gate.  A
    /// toolset adds these gates to the routed calls; it does not restrict the
    /// native tools this server also exposes, and the caller chooses the
    /// `toolset` argument.
    ///
    /// # Signing isolation
    ///
    /// No signing/key/policy tool is reachable via an ungated capability grant:
    /// the ungated matrix contains no such tool regardless of declared
    /// capabilities.  The signing actions (sign-payment, sign-rule-create)
    /// route to `stellar_pay_commit` and `stellar_rule_create_commit` only
    /// through the gated resolver, behind a first-invoke grant and a
    /// per-action approval.
    ///
    /// # Tool annotations
    ///
    /// - `readOnlyHint = false`: the signing actions route to commit tools
    ///   that sign and submit.
    /// - `destructiveHint = true`: the dispatcher reaches destructive tools,
    ///   so on mainnet the default policy engine refuses it and the mainnet
    ///   read-only tool set does not list it.
    ///
    /// # Errors
    ///
    /// - `profile.halted` or `profile.halt_unreadable`: the action names a tool
    ///   that is not read-only and the profile is halted, answered before any
    ///   other step.
    /// - `network.mainnet_write_forbidden`: a signing action (sign-payment or
    ///   rule-create) on a mainnet profile, answered as a business envelope
    ///   before any gate, approval, key access, or RPC request.
    /// - `policy.engine_required` and the other dispatch-gate refusals: a non-signing
    ///   action on a mainnet profile, refused by the dispatcher's policy gate.
    /// - `toolset.pin_unverifiable`: the install record does not verify under
    ///   the installation's pin key, or no pin key exists.
    /// - `toolset.not_installed`: toolset is not installed.
    /// - `toolset.unknown_action`: action not in the capability→tool matrix.
    /// - `toolset.capability_not_declared`: granting capability not declared.
    /// - `toolset.tool_not_allowed`: tool excluded by `allowed_tools` narrowing.
    /// - Plus any error from the routed tool (operator policy, chain mismatch, etc.).
    #[mcp_tool_item(
        name = "stellar_toolset_invoke",
        destructive_hint = true,
        read_only_hint = false,
        chain_id_required = false
    )]
    #[tool(
        name = "stellar_toolset_invoke",
        description = "Invoke a named action of an installed toolset. `toolset` names the \
                       package; `action` must be granted by the toolset's declared \
                       capabilities, read from its authenticated install record. Signing \
                       actions (sign-payment, sign-rule-create) route to the signing commit \
                       tools behind a first-invoke grant and a per-action approval. A toolset \
                       adds these gates; it does not restrict the native tools this server \
                       also exposes.",
        annotations(read_only_hint = false, destructive_hint = true)
    )]
    async fn stellar_toolset_invoke(
        &self,
        Parameters(args): Parameters<StellarToolsetInvokeArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        use stellar_agent_toolsets_runtime::{ToolsetRuntimeError, matrix};

        let toolset_name = stellar_agent_toolsets::sanitise_display(&args.toolset, 64);
        let action = stellar_agent_toolsets::sanitise_display(&args.action, 128);

        // Halt check for the routed tool, repeated from the server's entry
        // check: the action names the tool whose handler runs in this
        // process, and that tool's descriptor decides, before any gate,
        // store, keyring, or network access of the call.
        if let Some(refusal) = self.halt_refusal_for_tool(&action) {
            return Ok(refusal);
        }

        // Signing actions refuse here; other actions reach the dispatcher's
        // policy gate, which refuses them on mainnet.
        let is_signing_action = matrix::GATED_MATRIX_ENTRIES
            .iter()
            .any(|(_, tools)| tools.contains(&action.as_str()));
        if is_signing_action && self.context.chain_id.is_mainnet() {
            return Ok(crate::tools::common::mainnet_write_forbidden_result());
        }

        let args_value = json!({
            "toolset": &toolset_name,
            "action": &action,
        });
        // Payment effects come from the envelope or the routed arguments.
        // The routed gate enforces approval and reads live account state.
        let payment_value = toolset_payment_value(
            &action,
            &args.args,
            args.chain_id.as_deref(),
            self.mainnet_context.is_some(),
        );
        let outer = match payment_value {
            Some(value) => {
                self.dispatch_gate_provisional("stellar_toolset_invoke", &args_value, "", value)
                    .await
            }
            None => {
                self.dispatch_gate("stellar_toolset_invoke", &args_value, "")
                    .await
            }
        };
        if let Err(e) = outer {
            return e.into_result();
        }

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
        if is_signing_action {
            return self
                .route_to_gated_resolver(&toolset_name, &action, &args, &toolsets_root)
                .await;
        }

        // ── Four-part enforcement (ungated path) ──────────────────────────────
        let pin_key = self.toolset_pin_key()?;
        let (tool_name, _pin) =
            resolve_toolset_and_check(&toolset_name, &action, &toolsets_root, pin_key.as_ref())
                .map_err(|e| match e {
                    ToolsetRuntimeError::ToolsetNotInstalled
                    | ToolsetRuntimeError::PinUnverifiable { .. } => {
                        rmcp::ErrorData::invalid_params(e.to_string(), None)
                    }
                    ToolsetRuntimeError::UnknownToolsetAction
                    | ToolsetRuntimeError::CapabilityNotDeclared { .. }
                    | ToolsetRuntimeError::ToolNotAllowed { .. } => {
                        rmcp::ErrorData::invalid_params(e.to_string(), None)
                    }
                    ToolsetRuntimeError::Io(_) => {
                        rmcp::ErrorData::internal_error(e.to_string(), None)
                    }
                    // Forward-compat: new #[non_exhaustive] variants fail closed.
                    _ => rmcp::ErrorData::internal_error(
                        format!("toolset.enforcement_error: {e}"),
                        None,
                    ),
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
        // The routed handler evaluates its tool-specific arguments and live
        // account views. Its strict decision and approval govern submission.
        self.route_to_matrix_tool(tool_name, tool_args_value).await
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Gated resolver routing
// ─────────────────────────────────────────────────────────────────────────────

/// Payment fields shared by preparation and sign-payment routes.
/// Both routes use the payment parser before deriving or signing an amount.
#[derive(serde::Deserialize)]
#[serde(crate = "rmcp::serde")]
struct GatedPaymentFields {
    asset: String,
    #[serde(default)]
    amount: Option<String>,
    #[serde(default)]
    amount_in_stroops: Option<String>,
}

impl WalletServer {
    /// Reads the installation's toolset pin key for one toolset call.
    ///
    /// Read per call, so a key minted by an install after this server started
    /// is used at once.  `Ok(None)` when no toolset was ever installed: every
    /// resolver then reports an installed toolset as unverifiable.  A keyring
    /// failure other than the key's absence is an internal error carrying the
    /// keyring code, so a locked keyring never reads as an absent key.
    fn toolset_pin_key(&self) -> Result<Option<PinKey>, rmcp::ErrorData> {
        #[cfg(any(test, feature = "test-helpers"))]
        if let Some(key) = &self.toolset_pin_key_override {
            return Ok(Some(key.clone()));
        }
        stellar_agent_network::keyring::read_secret_32(&KeyringEntryRef::toolset_pin_key())
            .map(|key| key.map(PinKey::from_bytes))
            .map_err(|e| {
                rmcp::ErrorData::internal_error(
                    format!("{}: the toolset pin key cannot be read: {e}", e.code()),
                    Some(json!({ "code": e.code() })),
                )
            })
    }

    /// Loads the profile's attestation key and the binding its toolset grants
    /// are attested under, for the gated resolver's verified grant lookup.
    ///
    /// The binding is the profile and chain pair every approval surface
    /// attests a first-invoke grant under, so a grant recorded by `approve`
    /// verifies here and a grant attested for another profile or chain does
    /// not.
    ///
    /// # Errors
    ///
    /// Returns the uniform `policy.approval_required` result of
    /// [`crate::tools::common::load_attestation_key`] when the key is absent,
    /// unreadable or refused; without the key no grant is honored.
    fn load_gated_attestation_key<'a>(
        &'a self,
        profile_name: &'a str,
    ) -> Result<
        (
            zeroize::Zeroizing<[u8; 32]>,
            stellar_agent_core::approval::AttestationBinding<'a>,
        ),
        CallToolResult,
    > {
        let key = crate::tools::common::load_attestation_key(&self.profile)?;
        let binding = stellar_agent_core::approval::AttestationBinding::new(
            profile_name,
            self.context.chain_id.caip2_str(),
        );
        Ok((key, binding))
    }

    /// Route a toolset-routed `sign-payment` action through the GATED resolver.
    ///
    /// This is the DISTINCT internal entry point for the gated tier.  NOT a
    /// `route_to_matrix_tool` arm.
    ///
    /// Enforcement order:
    /// 1. `args.envelope_xdr` is present; an args object without it refuses
    ///    with `toolset.gated_missing_envelope`.
    /// 2. The caller's `asset`, `amount`, and `amount_in_stroops` are validated
    ///    through [`super::pay::parse_asset_and_amount`], so an invalid input
    ///    refuses before the envelope decode and before any gate creates an
    ///    approval.
    /// 3. Four-part check via the gated matrix.
    /// 4. First-invoke gate check (via `resolve_toolset_sign_payment_gated`).
    /// 5. On `GatedResolveOutcome::Resolved` → route to `stellar_pay_commit`
    ///    with per-action `PaymentSimulated` approval FORCED ON (Override
    ///    `Allow → RequireApproval`).
    /// 6. On `GatedResolveOutcome::FirstInvokeApprovalRequired` → return
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
    /// deserialisation boundary.  The asset and amount validation that precedes
    /// both branches deserializes a map holding only the `asset`, `amount`, and
    /// `amount_in_stroops` entries, never the caller's full args map.
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

        // ── Validate the caller's asset and amount ────────────────────────────
        //
        // Both gate outcomes below can persist an approval (the first-invoke
        // entry here, the per-action entry on the commit route), so the asset
        // and amount refuse before the envelope decode and before either gate
        // runs. Only the three payment fields are copied out of the args map;
        // the dangerous-key guard still runs on the full map before it is
        // deserialized on the commit route.
        let payment_fields: serde_json::Map<String, serde_json::Value> =
            ["asset", "amount", "amount_in_stroops"]
                .into_iter()
                .filter_map(|key| {
                    tool_args_obj
                        .get(key)
                        .map(|value| (key.to_owned(), value.clone()))
                })
                .collect();
        let payment_fields: GatedPaymentFields =
            serde_json::from_value(serde_json::Value::Object(payment_fields)).map_err(|e| {
                rmcp::ErrorData::invalid_params(
                    format!(
                        "toolset.gated_args_deserialise: stellar_pay_commit: {}",
                        describe_args_error(&e)
                    ),
                    None,
                )
            })?;
        super::pay::parse_asset_and_amount(
            &payment_fields.asset,
            payment_fields.amount,
            payment_fields.amount_in_stroops,
        )?;

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

        // Validate: the destination is a G or M classic account. The parser
        // checks the base32 checksum and version byte. An M destination keeps
        // its full string: a G grant covers it, and an M grant covers only its
        // exact key and ID.
        if stellar_agent_core::payment_accounts::PaymentAccount::parse(&destination).is_err() {
            return Err(rmcp::ErrorData::internal_error(
                "simulation.divergence: envelope_xdr did not yield a valid G-strkey or M-strkey \
                 destination",
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

        let (attestation_key, attestation_binding) =
            match self.load_gated_attestation_key(&profile_name) {
                Ok(loaded) => loaded,
                Err(result) => return Ok(result),
            };
        let pin_key = self.toolset_pin_key()?;

        #[cfg(not(feature = "test-helpers"))]
        let gated_params = GatedInvokeParams {
            toolset_name,
            action,
            toolsets_root,
            profile_name: &profile_name,
            attestation_key: &attestation_key,
            attestation_binding: &attestation_binding,
            authoritative_destination: &destination,
            authoritative_asset: &asset,
            authoritative_amount_stroops: amount_stroops,
            now_unix_ms,
            process_uid: &process_uid,
            pin_key: pin_key.as_ref(),
        };
        #[cfg(feature = "test-helpers")]
        let gated_params = GatedInvokeParams {
            toolset_name,
            action,
            toolsets_root,
            profile_name: &profile_name,
            attestation_key: &attestation_key,
            attestation_binding: &attestation_binding,
            authoritative_destination: &destination,
            authoritative_asset: &asset,
            authoritative_amount_stroops: amount_stroops,
            now_unix_ms,
            process_uid: &process_uid,
            pin_key: pin_key.as_ref(),
            approval_dir_override: self.approval_dir_override.clone(),
            grant_store_path_override: self.grant_store_path_override.clone(),
        };

        match resolve_toolset_sign_payment_gated(&gated_params) {
            Err(e) => {
                // Hard errors (toolset not installed, capability not declared, etc.)
                let err = match e {
                    ToolsetRuntimeError::ToolsetNotInstalled
                    | ToolsetRuntimeError::PinUnverifiable { .. }
                    | ToolsetRuntimeError::UnknownToolsetAction
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
                    ToolsetRuntimeError::BindingMismatch
                    | ToolsetRuntimeError::GrantStoreError { .. } => {
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
                // to `stellar-agent approve --id <nonce> --profile <name>`.  The agent then
                // re-invokes.
                let payload = serde_json::json!({
                    "approval_nonce": &approval_nonce,
                    "toolset_name": &sn,
                    "capability": &capability,
                    "message": format!(
                        "toolset.first_invoke_approval_required: run \
                         `{}` then re-invoke", stellar_agent_core::approval::approve_hint(&approval_nonce, &profile_name)
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
    /// the authoritative bucket-matching fields from. The pending
    /// `RuleProposalSimulated` entry (looked up by the caller-supplied
    /// `approval_nonce`, which `stellar_rule_create` always mints) is the
    /// SOLE source of the authoritative smart-account.
    ///
    /// `resolve_toolset_sign_payment_gated` is reused as-is (it is generic
    /// over the GATED matrix / `Capability`, despite its name) with the
    /// smart-account C-strkey as `authoritative_destination` and the fixed
    /// `matrix::SIGN_RULE_CREATE_ASSET_SENTINEL` /
    /// `matrix::SIGN_RULE_CREATE_AMOUNT_SENTINEL` for the asset/amount
    /// dimensions, which carry no independent meaning for rule creation.
    /// See that module's doc comments for the full rationale.
    ///
    /// # Errors
    ///
    /// - `toolset.gated_missing_approval_nonce`: `args.approval_nonce`
    ///   absent, not a string, or does not resolve to a pending
    ///   `RuleProposalSimulated` entry.
    /// - `policy.approval_consumed` (a business result): `args.approval_nonce`
    ///   resolves to an unexpired rule-proposal approval a commit already
    ///   spent.
    /// - `toolset.first_invoke_approval_required`: gate fired, approval queued.
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
        // The store holds its writer lock while this handle lives. The handle closes
        // at the end of this block, before the gated resolver or the commit opens the same store.
        // The commit rereads the entry under its own lock and verifies its digest and attestation.
        let entry = {
            let store = stellar_agent_core::approval::open_with_retry(
                &store_path,
                stellar_agent_core::approval::DEFAULT_RETRY_ATTEMPTS,
                stellar_agent_core::approval::DEFAULT_RETRY_BACKOFF,
            )
            .map_err(|e| {
                rmcp::ErrorData::internal_error(format!("approval.store_open: {e}"), None)
            })?;
            store.get(&approval_nonce).cloned()
        }
        .ok_or_else(|| {
            rmcp::ErrorData::invalid_params(
                "toolset.gated_missing_approval_nonce: approval_nonce does not resolve to a \
                 pending RuleProposalSimulated entry; call stellar_rule_create first",
                None,
            )
        })?;
        let now_unix_ms = stellar_agent_core::timefmt::now_unix_ms()
            .map_err(|e| rmcp::ErrorData::internal_error(format!("clock_error: {e}"), None))?;
        let smart_account = match &entry.kind {
            ApprovalKind::RuleProposalSimulated { smart_account, .. } => smart_account.clone(),
            // The commit spends a rule-proposal approval before its install
            // starts. A retry through the toolset is named as spent, as the
            // commit names it, rather than as a nonce of the wrong kind.
            ApprovalKind::Consumed {
                original_kind_name, ..
            } if original_kind_name == "RuleProposalSimulated"
                && !entry.is_expired(now_unix_ms) =>
            {
                return Ok(crate::tools::common::rule_proposal_consumed_error());
            }
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

        let (attestation_key, attestation_binding) =
            match self.load_gated_attestation_key(&profile_name) {
                Ok(loaded) => loaded,
                Err(result) => return Ok(result),
            };
        let pin_key = self.toolset_pin_key()?;

        #[cfg(not(feature = "test-helpers"))]
        let gated_params = GatedInvokeParams {
            toolset_name,
            action,
            toolsets_root,
            profile_name: &profile_name,
            attestation_key: &attestation_key,
            attestation_binding: &attestation_binding,
            authoritative_destination: &smart_account,
            authoritative_asset:
                stellar_agent_toolsets_runtime::matrix::SIGN_RULE_CREATE_ASSET_SENTINEL,
            authoritative_amount_stroops:
                stellar_agent_toolsets_runtime::matrix::SIGN_RULE_CREATE_AMOUNT_SENTINEL,
            now_unix_ms,
            process_uid: &process_uid,
            pin_key: pin_key.as_ref(),
        };
        #[cfg(feature = "test-helpers")]
        let gated_params = GatedInvokeParams {
            toolset_name,
            action,
            toolsets_root,
            profile_name: &profile_name,
            attestation_key: &attestation_key,
            attestation_binding: &attestation_binding,
            authoritative_destination: &smart_account,
            authoritative_asset:
                stellar_agent_toolsets_runtime::matrix::SIGN_RULE_CREATE_ASSET_SENTINEL,
            authoritative_amount_stroops:
                stellar_agent_toolsets_runtime::matrix::SIGN_RULE_CREATE_AMOUNT_SENTINEL,
            now_unix_ms,
            process_uid: &process_uid,
            pin_key: pin_key.as_ref(),
            approval_dir_override: self.approval_dir_override.clone(),
            grant_store_path_override: self.grant_store_path_override.clone(),
        };

        match resolve_toolset_sign_payment_gated(&gated_params) {
            Err(e) => {
                let err = match e {
                    ToolsetRuntimeError::ToolsetNotInstalled
                    | ToolsetRuntimeError::PinUnverifiable { .. }
                    | ToolsetRuntimeError::UnknownToolsetAction
                    | ToolsetRuntimeError::CapabilityNotDeclared { .. }
                    | ToolsetRuntimeError::ToolNotAllowed { .. } => {
                        rmcp::ErrorData::invalid_params(e.to_string(), None)
                    }
                    ToolsetRuntimeError::BindingMismatch
                    | ToolsetRuntimeError::GrantStoreError { .. } => {
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
                let payload = serde_json::json!({
                    "approval_nonce": &approval_nonce,
                    "toolset_name": &sn,
                    "capability": &capability,
                    "message": format!(
                        "toolset.first_invoke_approval_required: run \
                         `{}` then re-invoke", stellar_agent_core::approval::approve_hint(&approval_nonce, &profile_name)
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
    /// approve via `stellar-agent approve --id <nonce> --profile <name>`).
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
                            format!(
                                "toolset.gated_args_deserialise: stellar_pay_commit: {}",
                                describe_args_error(&e)
                            ),
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
                                "toolset.gated_args_deserialise: stellar_rule_create_commit: {}",
                                describe_args_error(&e)
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

/// Describes why tool arguments did not deserialise, by the error class only.
///
/// A `serde_json` data error quotes the offending value (an unknown variant,
/// an invalid string), and the arguments come from the caller, so the
/// description names the class and never the value. A deserialisation from a
/// `serde_json::Value` carries no source position, so none is reported.
fn describe_args_error(error: &serde_json::Error) -> &'static str {
    use serde_json::error::Category;
    match error.classify() {
        Category::Syntax | Category::Eof => "the arguments are not valid JSON",
        Category::Data => {
            "the arguments have a missing field or a field of the wrong type or value"
        }
        Category::Io => "the arguments could not be read",
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
                            format!(
                                "toolset.args_deserialise: stellar_balances: {}",
                                describe_args_error(&e)
                            ),
                            None,
                        )
                    })?;
                self.invoke_stellar_balances(typed).await
            }
            "stellar_pay" => {
                let typed: super::pay::StellarPayArgs =
                    serde_json::from_value(args).map_err(|e| {
                        rmcp::ErrorData::invalid_params(
                            format!(
                                "toolset.args_deserialise: stellar_pay: {}",
                                describe_args_error(&e)
                            ),
                            None,
                        )
                    })?;
                self.invoke_stellar_pay(typed).await
            }
            "stellar_claim" => {
                let typed: super::claim::StellarClaimArgs =
                    serde_json::from_value(args).map_err(|e| {
                        rmcp::ErrorData::invalid_params(
                            format!(
                                "toolset.args_deserialise: stellar_claim: {}",
                                describe_args_error(&e)
                            ),
                            None,
                        )
                    })?;
                self.invoke_stellar_claim(typed).await
            }
            "stellar_rule_create" => {
                let typed: super::rule_create::StellarRuleCreateArgs = serde_json::from_value(args)
                    .map_err(|e| {
                        rmcp::ErrorData::invalid_params(
                            format!(
                                "toolset.args_deserialise: stellar_rule_create: {}",
                                describe_args_error(&e)
                            ),
                            None,
                        )
                    })?;
                self.invoke_stellar_rule_create(typed).await
            }
            "stellar_sep47_discover" => {
                let typed: super::sep47_discover::Sep47DiscoverArgs = serde_json::from_value(args)
                    .map_err(|e| {
                        rmcp::ErrorData::invalid_params(
                            format!(
                                "toolset.args_deserialise: stellar_sep47_discover: {}",
                                describe_args_error(&e)
                            ),
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
                                "toolset.args_deserialise: stellar_sep48_preview_invocation: {}",
                                describe_args_error(&e)
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
                        format!(
                            "toolset.args_deserialise: stellar_sep7_parse_uri: {}",
                            describe_args_error(&e)
                        ),
                        None,
                    )
                })?;
                self.invoke_stellar_sep7_parse_uri(typed).await
            }
            "stellar_rules_list" => {
                let typed: super::rules::StellarRulesListArgs = serde_json::from_value(args)
                    .map_err(|e| {
                        rmcp::ErrorData::invalid_params(
                            format!(
                                "toolset.args_deserialise: stellar_rules_list: {}",
                                describe_args_error(&e)
                            ),
                            None,
                        )
                    })?;
                self.invoke_stellar_rules_list(typed).await
            }
            "stellar_rules_get" => {
                let typed: super::rules::StellarRulesGetArgs = serde_json::from_value(args)
                    .map_err(|e| {
                        rmcp::ErrorData::invalid_params(
                            format!(
                                "toolset.args_deserialise: stellar_rules_get: {}",
                                describe_args_error(&e)
                            ),
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
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only fixture construction and assertions"
    )]

    use stellar_agent_core::profile::Profile;
    use stellar_agent_toolsets_runtime::PinKey;
    use stellar_agent_toolsets_runtime::matrix::ALL_MATRIX_TOOL_NAMES;

    use super::StellarToolsetInvokeArgs;
    use crate::server::WalletServer;

    #[test]
    fn mainnet_context_keeps_raw_outer_gate() {
        let args = serde_json::json!({
            "destination": "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
            "asset": "native", "amount_in_stroops": "10",
        });
        assert!(
            super::toolset_payment_value("stellar_pay", &args, Some("stellar:mainnet"), true)
                .is_none()
        );
        let value =
            super::toolset_payment_value("stellar_pay", &args, Some("stellar:testnet"), false);
        assert!(
            matches!(value, Some(stellar_agent_core::policy::v1::ValueClass::Value(ref effects)) if effects.legs()[0].amount == Some(10))
        );
        for args in [serde_json::Value::Null, serde_json::json!([])] {
            assert!(super::toolset_payment_value("stellar_pay", &args, None, false).is_none());
        }
        assert!(super::toolset_payment_value("stellar_balances", &args, None, false).is_none());
        assert!(super::toolset_payment_value("stellar_pay_commit", &args, None, false).is_none());
    }

    /// Router metadata carries the annotations clients receive in `tools/list`.
    #[test]
    fn toolset_invoke_router_annotations_are_destructive() {
        let tool = WalletServer::toolsets_tool_router()
            .list_all()
            .into_iter()
            .find(|tool| tool.name == "stellar_toolset_invoke")
            .unwrap();
        let annotations = tool.annotations.unwrap();
        assert_eq!(annotations.destructive_hint, Some(true));
        assert_eq!(annotations.read_only_hint, Some(false));
    }

    fn pin_key(byte: u8) -> PinKey {
        PinKey::from_bytes(zeroize::Zeroizing::new([byte; 32]))
    }

    fn balances_invoke(toolset: &str) -> StellarToolsetInvokeArgs {
        StellarToolsetInvokeArgs {
            toolset: toolset.to_owned(),
            action: "stellar_balances".to_owned(),
            chain_id: None,
            args: serde_json::json!({
                "account_id": "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN"
            }),
        }
    }

    /// A record written under another key, and a record of the earlier
    /// untagged format, both refuse with `toolset.pin_unverifiable` before
    /// any routing.
    #[tokio::test]
    #[serial_test::serial(keyring)]
    #[serial_test::serial]
    async fn toolset_invoke_refuses_an_unverifiable_pin() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let toolsets = tempfile::TempDir::new().unwrap();
        stellar_agent_toolsets_install::write_toolset_for_test(
            toolsets.path(),
            "balance-reporter",
            &["read-balance"],
            &[],
            "2026-06-02T00:00:00Z",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &pin_key(0x5a),
        )
        .unwrap();
        let profile = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
            .with_noop_engine()
            .build();
        let mut server = WalletServer::new(profile).unwrap();
        server.set_toolsets_root_for_test(toolsets.path().to_path_buf());
        server.set_toolset_pin_key_for_test(pin_key(0x5b));

        let err = server
            .call_stellar_toolset_invoke(balances_invoke("balance-reporter"))
            .await
            .expect_err("a record under another key must refuse");
        assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
        assert!(
            err.message.contains("toolset.pin_unverifiable"),
            "{}",
            err.message
        );

        std::fs::write(
            toolsets
                .path()
                .join("balance-reporter")
                .join(".stellar-agent-toolset-pin.json"),
            r#"{"package":"balance-reporter","version":"1.0.0","shasum":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","publisher":"GABC","installed_at":"2026-06-02T00:00:00Z","capabilities":["read-balance"],"allowed_tools":[]}"#,
        )
        .unwrap();
        server.set_toolset_pin_key_for_test(pin_key(0x5a));
        let err = server
            .call_stellar_toolset_invoke(balances_invoke("balance-reporter"))
            .await
            .expect_err("an untagged record must refuse");
        assert!(
            err.message.contains("toolset.pin_unverifiable"),
            "{}",
            err.message
        );
    }

    /// On a mainnet profile without an operator policy, the dispatcher is
    /// refused by its own policy gate for a read-only action, before the
    /// resolver reads any record: the toolset here is not installed, and the
    /// refusal is the policy code, not `toolset.not_installed`.
    #[tokio::test]
    #[serial_test::serial(keyring)]
    #[serial_test::serial]
    async fn toolset_invoke_is_refused_on_mainnet_under_the_default_engine() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let toolsets = tempfile::TempDir::new().unwrap();
        let profile = Profile::builder_mainnet(
            "https://rpc.example.invalid",
            "svc",
            "acct",
            "n-svc",
            "n-acct",
        )
        .with_noop_engine()
        .build();
        let mut server = WalletServer::new(profile).unwrap();
        server.set_toolsets_root_for_test(toolsets.path().to_path_buf());
        server.set_toolset_pin_key_for_test(pin_key(0x5a));

        let result = server
            .call_stellar_toolset_invoke(balances_invoke("balance-reporter"))
            .await
            .expect("the policy refusal is a business envelope");
        let (code, _message, _text) = crate::tools::common::assert_business_envelope(&result);
        assert_eq!(code, "policy.engine_required");
    }

    /// Routed arguments that do not deserialise into the tool's argument type
    /// are refused by the tool and the error class, and the refusal repeats
    /// none of the argument values the deserialiser quotes.
    #[tokio::test]
    #[serial_test::serial(keyring)]
    #[serial_test::serial]
    async fn toolset_args_marker_is_not_echoed() {
        let home = tempfile::tempdir().expect("home");
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let capture = stellar_agent_test_support::log_capture::CaptureWriter::new();
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_max_level(tracing::Level::TRACE)
            .with_writer(capture.clone())
            .finish();
        let _inert = stellar_agent_test_support::log_capture::inert_dispatcher();
        let _subscriber = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();

        use stellar_agent_test_support::rejected_value::{
            CREDENTIAL_MARKER, assert_no_marker, assert_no_marker_in_text,
        };

        let toolsets = tempfile::TempDir::new().unwrap();
        stellar_agent_toolsets_install::write_toolset_for_test(
            toolsets.path(),
            "balance-reporter",
            &[
                "read-balance",
                "propose-transaction",
                "suggest-destination",
                "read-rules",
                "sign-payment",
            ],
            &[],
            "2026-06-02T00:00:00Z",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &pin_key(0x5a),
        )
        .unwrap();
        let profile = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
            .with_noop_engine()
            .build();
        let mut server = WalletServer::new(profile).unwrap();
        server.set_toolsets_root_for_test(toolsets.path().to_path_buf());
        server.set_toolset_pin_key_for_test(pin_key(0x5a));

        for action in ALL_MATRIX_TOOL_NAMES {
            let mut invoke = balances_invoke("balance-reporter");
            invoke.chain_id = Some("stellar:testnet".to_owned());
            invoke.action = (*action).to_owned();
            invoke.args =
                serde_json::json!({"chain_id": "stellar:testnet", "account_id": CREDENTIAL_MARKER});
            // A string in a required numeric field or a missing required field
            // reaches each arm's independent deserializer.
            invoke.args["assets"] = serde_json::json!(CREDENTIAL_MARKER);
            invoke.args["limit"] = serde_json::json!(CREDENTIAL_MARKER);
            invoke.args["transaction_xdr"] = serde_json::json!([CREDENTIAL_MARKER]);
            let err = server
                .call_stellar_toolset_invoke(invoke)
                .await
                .expect_err("arguments are refused");
            assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
            assert_eq!(
                err.message,
                format!(
                    "toolset.args_deserialise: {action}: the arguments have a missing field or a field of the wrong type or value"
                )
            );
            assert_no_marker(&err, CREDENTIAL_MARKER);
        }
        let mut invoke = balances_invoke("balance-reporter");
        invoke.action = "stellar_pay_commit".to_owned();
        invoke.chain_id = Some("stellar:testnet".to_owned());
        invoke.args = serde_json::json!({"envelope_xdr": "unused", "asset": "native", "amount_in_stroops": [CREDENTIAL_MARKER]});
        let err = server
            .call_stellar_toolset_invoke(invoke)
            .await
            .unwrap_err();
        assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
        assert_eq!(
            err.message,
            "toolset.gated_args_deserialise: stellar_pay_commit: the arguments have a missing field or a field of the wrong type or value"
        );
        assert_no_marker(&err, CREDENTIAL_MARKER);
        assert_no_marker_in_text(&capture.captured_str(), "CREDMARKER7");
    }

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
    #[tokio::test]
    #[serial_test::serial(keyring)]
    #[serial_test::serial]
    async fn toolset_name_and_action_marker_is_not_echoed() {
        let home = tempfile::tempdir().expect("home");
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let capture = stellar_agent_test_support::log_capture::CaptureWriter::new();
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_max_level(tracing::Level::TRACE)
            .with_writer(capture.clone())
            .finish();
        let _inert = stellar_agent_test_support::log_capture::inert_dispatcher();
        let _subscriber = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();

        use stellar_agent_test_support::rejected_value::{
            CREDENTIAL_MARKER, assert_no_marker_in_text,
        };
        let toolsets = tempfile::tempdir().unwrap();
        stellar_agent_toolsets_install::write_toolset_for_test(
            toolsets.path(),
            "balance-reporter",
            &["read-balance"],
            &[],
            "2026-06-02T00:00:00Z",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &pin_key(0x5a),
        )
        .unwrap();
        let profile = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
            .with_noop_engine()
            .build();
        let mut server = WalletServer::new(profile).unwrap();
        server.set_toolsets_root_for_test(toolsets.path().to_path_buf());
        server.set_toolset_pin_key_for_test(pin_key(0x5a));
        for (name, action, expected) in [
            (
                CREDENTIAL_MARKER,
                "stellar_balances",
                "toolset.not_installed: the requested toolset is not installed",
            ),
            (
                "missing",
                "stellar_balances",
                "toolset.not_installed: the requested toolset is not installed",
            ),
            (
                "balance-reporter",
                CREDENTIAL_MARKER,
                "toolset.unknown_action: the requested action is not in the capability-to-tool matrix",
            ),
        ] {
            let mut invoke = balances_invoke(name);
            invoke.action = action.to_owned();
            let error = server
                .call_stellar_toolset_invoke(invoke)
                .await
                .unwrap_err();
            assert_eq!(error.code, rmcp::model::ErrorCode::INVALID_PARAMS);
            assert_eq!(error.message, expected);
            stellar_agent_test_support::rejected_value::assert_no_marker(&error, CREDENTIAL_MARKER);
            assert_no_marker_in_text(&format!("{error:?}"), CREDENTIAL_MARKER);
        }
        stellar_agent_test_support::rejected_value::assert_no_marker_in_text(
            &capture.captured_str(),
            "CREDMARKER7",
        );
    }
    #[cfg(feature = "test-helpers")]
    #[tokio::test]
    #[serial_test::serial(keyring)]
    #[serial_test::serial]
    async fn gated_toolset_args_marker_is_not_echoed() {
        let home = tempfile::tempdir().expect("home");
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
        let capture = stellar_agent_test_support::log_capture::CaptureWriter::new();
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_max_level(tracing::Level::TRACE)
            .with_writer(capture.clone())
            .finish();
        let _inert = stellar_agent_test_support::log_capture::inert_dispatcher();
        let _subscriber = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();

        use base64::Engine as _;
        use stellar_agent_core::approval::{
            AttestationBinding, ContextRuleProposalSnapshot, PendingApproval, PendingApprovalStore,
            RuleProposalContextType, RuleProposalSigner, TOOLSET_GRANT_DEFAULT_TTL_MS,
            ToolsetGrantStore, build_attested_grant, process_uid_for_attestation,
        };
        use stellar_agent_test_support::rejected_value::{CREDENTIAL_MARKER, assert_no_marker};
        use stellar_xdr::{
            Asset, Limits, Memo, MuxedAccount, Operation, OperationBody, PaymentOp, Preconditions,
            SequenceNumber, Transaction, TransactionEnvelope, TransactionExt,
            TransactionV1Envelope, Uint256, VecM, WriteXdr,
        };
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let root = tempfile::tempdir().unwrap();
        let approval_dir = root.path().join("approvals");
        std::fs::create_dir(&approval_dir).unwrap();
        let grant_path = root.path().join("grants.toml");
        let profile = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
            .with_noop_engine()
            .build();
        let key = [0x42; 32];
        keyring_core::Entry::new(
            &profile.attestation_key_id.service,
            &profile.attestation_key_id.account,
        )
        .unwrap()
        .set_password(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key))
        .unwrap();
        let mut server = WalletServer::new(profile).unwrap();
        server.set_toolsets_root_for_test(root.path().to_path_buf());
        server.set_toolset_pin_key_for_test(pin_key(0x5a));
        server.set_approval_dir_for_test(approval_dir.clone());
        server.set_grant_store_path_for_test(grant_path.clone());
        stellar_agent_toolsets_install::write_toolset_for_test(
            root.path(),
            "marker-tools",
            &["sign-payment", "sign-rule-create"],
            &[],
            "2026-06-02T00:00:00Z",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &pin_key(0x5a),
        )
        .unwrap();
        let dest = stellar_strkey::ed25519::PublicKey([7; 32])
            .to_string()
            .to_string();
        let contract = stellar_strkey::Contract([8; 32]).to_string().to_string();
        let now = stellar_agent_core::timefmt::now_unix_ms().unwrap();
        for (capability, destination, asset, amount) in [
            ("sign-payment", dest.as_str(), "XLM", 1_000_000),
            (
                "sign-rule-create",
                contract.as_str(),
                stellar_agent_toolsets_runtime::matrix::SIGN_RULE_CREATE_ASSET_SENTINEL,
                stellar_agent_toolsets_runtime::matrix::SIGN_RULE_CREATE_AMOUNT_SENTINEL,
            ),
        ] {
            let grant = build_attested_grant(
                "marker-tools".to_owned(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
                "1.0.0".to_owned(),
                "0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
                capability.to_owned(),
                destination.to_owned(),
                asset.to_owned(),
                0,
                amount,
                process_uid_for_attestation().unwrap(),
                now,
                TOOLSET_GRANT_DEFAULT_TTL_MS,
                &key,
                &AttestationBinding::new("acct", "stellar:testnet"),
            )
            .unwrap();
            ToolsetGrantStore::open(grant_path.clone(), now)
                .unwrap()
                .insert(grant)
                .unwrap();
        }
        let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx: Transaction {
                source_account: MuxedAccount::Ed25519(Uint256([7; 32])),
                fee: 100,
                seq_num: SequenceNumber(1),
                cond: Preconditions::None,
                memo: Memo::None,
                operations: vec![Operation {
                    source_account: None,
                    body: OperationBody::Payment(PaymentOp {
                        destination: MuxedAccount::Ed25519(Uint256([7; 32])),
                        asset: Asset::Native,
                        amount: 1_000_000,
                    }),
                }]
                .try_into()
                .unwrap(),
                ext: TransactionExt::V0,
            },
            signatures: VecM::default(),
        })
        .to_xdr_base64(Limits::none())
        .unwrap();
        let entry = PendingApproval::new_rule_proposal_pending(
            contract,
            stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE.to_owned(),
            "stellar:testnet".to_owned(),
            ContextRuleProposalSnapshot::new(
                RuleProposalContextType::Default,
                "daily".to_owned(),
                None,
                vec![RuleProposalSigner::delegated(dest.clone(), true)],
                vec![],
                vec![0],
                false,
                false,
            ),
            "rule".to_owned(),
            process_uid_for_attestation().unwrap(),
            60_000,
        )
        .unwrap();
        let nonce = entry.approval_nonce.clone();
        PendingApprovalStore::open(approval_dir.join("acct.toml"))
            .unwrap()
            .insert(entry, now)
            .unwrap();
        for (action, args) in [
            (
                "stellar_pay_commit",
                serde_json::json!({"source": dest, "destination": dest, "asset": "native",
                "amount": "0.1 XLM", "envelope_xdr": envelope, "nonce": "unused", "expires_at_unix_ms": CREDENTIAL_MARKER}),
            ),
            (
                "stellar_rule_create_commit",
                serde_json::json!({"approval_nonce": nonce, "approval_attestation": [CREDENTIAL_MARKER]}),
            ),
        ] {
            let err = server
                .call_stellar_toolset_invoke(StellarToolsetInvokeArgs {
                    toolset: "marker-tools".to_owned(),
                    action: action.to_owned(),
                    chain_id: Some("stellar:testnet".to_owned()),
                    args,
                })
                .await
                .unwrap_err();
            assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
            assert_eq!(
                err.message,
                format!(
                    "toolset.gated_args_deserialise: {action}: the arguments have a missing field or a field of the wrong type or value"
                )
            );
            assert_no_marker(&err, CREDENTIAL_MARKER);
        }
        stellar_agent_test_support::rejected_value::assert_no_marker_in_text(
            &capture.captured_str(),
            "CREDMARKER7",
        );
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
