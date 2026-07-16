//! Testnet-only sponsored MPP charge tools.

use rmcp::{
    handler::server::wrapper::Parameters,
    model::{CallToolResult, Content},
    schemars, serde, tool, tool_router,
};
use serde_json::json;
use sha2::{Digest as _, Sha256};
use stellar_agent_core::{
    approval::{store::PendingApprovalStore, user_id::process_uid_for_attestation},
    audit_log::{AuditEntry, PolicyDecision, ValueLegRecord},
    policy::v1::ValueClass,
    profile::caip2::TESTNET_PASSPHRASE,
};
use stellar_agent_mcp_macros::mcp_tool_router;
use stellar_agent_mpp::{
    ApprovalDisposition, ChallengeInput, MppAuthorizationStore, MppError, MppErrorCode,
    ReceiptInput, StellarReconciliationRpc, StellarSponsoredRpc, authorization_status,
    commit_authorization, mpp_value_effects, parse_receipt, persist_prepared_authorization,
    prepare_sponsored, reconcile_transaction, select_and_validate, verify_pending_approval,
};
use stellar_agent_network::keyring::lazy_signer_from_keyring;
use stellar_agent_nonce::Nonce;

use crate::{
    server::WalletServer,
    tools::{
        common::{
            DEFAULT_NONCE_TTL_MS, DispatchOutcome, business_error_result,
            commit_envelope_and_verify_nonce, load_attestation_key,
        },
        value_audit::emit_value_audit_row_strict,
    },
};

#[derive(Debug, serde::Deserialize, serde::Serialize, schemars::JsonSchema)]
#[serde(crate = "rmcp::serde", deny_unknown_fields)]
pub struct MppPrepareArgs {
    /// Active profile name; must match the server profile.
    pub profile: String,
    /// Tagged HTTP or native MCP challenge and exact request context.
    pub challenge: ChallengeInput,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(crate = "rmcp::serde", deny_unknown_fields)]
pub struct MppCommitArgs {
    /// Opaque identifier returned by prepare.
    pub authorization_id: String,
    /// Base64url process-bound commit nonce returned by prepare.
    pub nonce: String,
    /// Nonce expiry returned by prepare, in Unix milliseconds.
    pub expires_at_unix_ms: u64,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(crate = "rmcp::serde", deny_unknown_fields)]
pub struct MppReceiptArgs {
    /// Opaque authorization identifier.
    pub authorization_id: String,
    /// Tagged HTTP or MCP receipt value.
    pub receipt: ReceiptInput,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(crate = "rmcp::serde", deny_unknown_fields)]
pub struct MppReconcileArgs {
    /// Opaque authorization identifier.
    pub authorization_id: String,
    /// Strict lowercase 64-hex transaction hash.
    pub transaction_hash: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(crate = "rmcp::serde", deny_unknown_fields)]
pub struct MppStatusArgs {
    /// Opaque authorization identifier.
    pub authorization_id: String,
}

#[mcp_tool_router]
#[tool_router(router = mpp_tool_router, vis = "pub(crate)")]
impl WalletServer {
    /// Prepares and durably records a testnet sponsored MPP charge.
    #[mcp_tool_item(
        name = "stellar_mpp_charge_prepare",
        destructive_hint = false,
        read_only_hint = false,
        chain_id_required = false,
        value_kind = "moves_value"
    )]
    #[tool(
        name = "stellar_mpp_charge_prepare",
        description = "Validate an HTTP or MCP Payment challenge, simulate a sponsored Stellar testnet charge, evaluate policy, and durably return an authorization preview plus commit nonce. Never signs or returns a credential.",
        annotations(read_only_hint = false, destructive_hint = false)
    )]
    pub async fn stellar_mpp_charge_prepare(
        &self,
        Parameters(args): Parameters<MppPrepareArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if let Err(result) = self.mpp_preflight_profile(&args.profile) {
            return Ok(result);
        }
        let now_ms = stellar_agent_core::timefmt::now_unix_ms()
            .map_err(|_| rmcp::ErrorData::internal_error("clock unavailable", None))?;
        let now_unix = i64::try_from(now_ms / 1_000).unwrap_or(i64::MAX);
        let selected = match select_and_validate(&args.challenge, now_unix) {
            Ok(selected) => selected,
            Err(error) => return Ok(mpp_error_result(&error)),
        };
        let payer = self.profile.mcp_signer_default.account.as_str();
        let rpc = match StellarSponsoredRpc::new(&self.profile.rpc_url) {
            Ok(rpc) => rpc,
            Err(error) => return Ok(mpp_error_result(&error)),
        };
        let prepared = match prepare_sponsored(
            selected,
            payer,
            &self.profile.network_passphrase,
            &rpc,
        )
        .await
        {
            Ok(prepared) => prepared,
            Err(error) => return Ok(mpp_error_result(&error)),
        };
        let effects = mpp_value_effects(prepared.selected());
        let args_value = serde_json::to_value(&args)
            .map_err(|_| rmcp::ErrorData::invalid_params("invalid MPP arguments", None))?;
        let disposition = match self
            .dispatch_gate_with_value(
                "stellar_mpp_charge_prepare",
                &args_value,
                "stellar:testnet",
                ValueClass::Value(effects),
                None,
                None,
            )
            .await
        {
            Ok(DispatchOutcome::Allow(_)) => ApprovalDisposition::Allow,
            Ok(DispatchOutcome::RequireApproval(_)) => ApprovalDisposition::RequireApproval,
            Err(error) => return error.into_result(),
        };

        // Successful simulation precedes lazy MPP key creation.
        let state = match MppAuthorizationStore::from_profile_keyring(&args.profile, true) {
            Ok(state) => state,
            Err(error) => return Ok(mpp_error_result(&error)),
        };
        let mut approvals = if disposition == ApprovalDisposition::RequireApproval {
            let path = match self.resolve_approval_dir() {
                Ok(dir) => dir.join(format!("{}.toml", args.profile)),
                Err(_) => return Ok(mpp_state_error()),
            };
            match PendingApprovalStore::open(path) {
                Ok(store) => Some(store),
                Err(_) => return Ok(mpp_state_error()),
            }
        } else {
            None
        };
        let process_uid = match process_uid_for_attestation() {
            Ok(uid) => uid,
            Err(_) => return Ok(mpp_state_error()),
        };
        let preview = match persist_prepared_authorization(
            &args.profile,
            &self.profile.network_passphrase,
            &prepared,
            disposition,
            &process_uid,
            now_unix,
            &state,
            approvals.as_mut(),
        ) {
            Ok(preview) => preview,
            Err(error) => return Ok(mpp_error_result(&error)),
        };
        let challenge_expiry_ms = u64::try_from(preview.expires_at_unix)
            .unwrap_or(0)
            .saturating_mul(1_000);
        let nonce_expiry = now_ms
            .saturating_add(DEFAULT_NONCE_TTL_MS)
            .min(challenge_expiry_ms);
        let nonce = match self.nonce_mint.mint(
            self.tool_catalogue.as_ref(),
            preview.authorization_id.as_bytes(),
            now_ms,
            nonce_expiry,
            "stellar_mpp_charge_commit",
            "stellar:testnet",
        ) {
            Ok(nonce) => nonce,
            Err(_) => return Ok(mpp_state_error()),
        };
        Ok(success(json!({
            "authorization": preview,
            "nonce": nonce.to_base64(),
            "nonce_expires_at_unix_ms": nonce_expiry,
        })))
    }

    /// Commits one stored authorization and returns its one-shot credential.
    #[mcp_tool_item(
        name = "stellar_mpp_charge_commit",
        destructive_hint = true,
        read_only_hint = false,
        chain_id_required = false,
        value_kind = "moves_value"
    )]
    #[tool(
        name = "stellar_mpp_charge_commit",
        description = "Commit a previously prepared sponsored MPP charge using only its authorization ID and process-bound nonce. Reloads exact terms, verifies approval, re-evaluates policy, signs, re-simulates, audits, and returns one credential.",
        annotations(read_only_hint = false, destructive_hint = true)
    )]
    pub async fn stellar_mpp_charge_commit(
        &self,
        Parameters(args): Parameters<MppCommitArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if let Err(result) = self.mpp_preflight_profile(&self.profile_name_for_approval()) {
            return Ok(result);
        }
        let nonce = match Nonce::from_base64(&args.nonce) {
            Ok(nonce) => nonce,
            Err(_) => {
                return Ok(business_error_result(
                    "nonce.invalid",
                    "invalid commit nonce",
                ));
            }
        };
        let now_ms = stellar_agent_core::timefmt::now_unix_ms()
            .map_err(|_| rmcp::ErrorData::internal_error("clock unavailable", None))?;
        if let Err(error) = commit_envelope_and_verify_nonce(
            &self.nonce_mint,
            &self.replay_window,
            &nonce,
            &args.authorization_id,
            args.expires_at_unix_ms,
            "stellar:testnet",
            "stellar_mpp_charge_commit",
            now_ms,
        )
        .await
        {
            return error.into_result();
        }
        let profile_name = self.profile_name_for_approval();
        let state = match MppAuthorizationStore::from_profile_keyring(&profile_name, false) {
            Ok(state) => state,
            Err(error) => return Ok(mpp_error_result(&error)),
        };
        let record = match state.load(&args.authorization_id) {
            Ok(record) => record,
            Err(error) => return Ok(mpp_error_result(&error)),
        };
        let prepared = match record.prepared_charge() {
            Ok(prepared) => prepared,
            Err(error) => return Ok(mpp_error_result(&error)),
        };
        let effects = mpp_value_effects(prepared.selected());
        let gate_args = json!({"authorization_id": args.authorization_id});
        let disposition = match self
            .dispatch_gate_with_value(
                "stellar_mpp_charge_commit",
                &gate_args,
                "stellar:testnet",
                ValueClass::Value(effects.clone()),
                None,
                None,
            )
            .await
        {
            Ok(DispatchOutcome::Allow(_)) => ApprovalDisposition::Allow,
            Ok(DispatchOutcome::RequireApproval(_)) => ApprovalDisposition::RequireApproval,
            Err(error) => return error.into_result(),
        };
        if disposition == ApprovalDisposition::RequireApproval && record.approval_nonce().is_none()
        {
            return Ok(mpp_approval_error());
        }
        let mut approval_store = None;
        let mut approval_key = None;
        if record.approval_nonce().is_some() {
            let path = match self.resolve_approval_dir() {
                Ok(dir) => dir.join(format!("{profile_name}.toml")),
                Err(_) => return Ok(mpp_state_error()),
            };
            approval_store = match PendingApprovalStore::open(path) {
                Ok(store) => Some(store),
                Err(_) => return Ok(mpp_approval_error()),
            };
            approval_key = match load_attestation_key(&self.profile) {
                Ok(key) => Some(key),
                Err(result) => return Ok(result),
            };
        }
        if let Err(error) = verify_pending_approval(
            &state,
            approval_store.as_ref(),
            approval_key.as_ref(),
            &args.authorization_id,
            i64::try_from(now_ms / 1_000).unwrap_or(i64::MAX),
        ) {
            return Ok(mpp_error_result(&error));
        }
        let signer = match lazy_signer_from_keyring(
            &self.profile.mcp_signer_default,
            &self.profile.mcp_signer_default.account,
        ) {
            Ok(signer) => signer,
            Err(_) => return Ok(mpp_signing_error()),
        };
        let rpc = match StellarSponsoredRpc::new(&self.profile.rpc_url) {
            Ok(rpc) => rpc,
            Err(error) => return Ok(mpp_error_result(&error)),
        };
        let descriptor = match self.tool_registry.get("stellar_mpp_charge_commit") {
            Some(descriptor) => descriptor.clone(),
            None => return Ok(mpp_state_error()),
        };
        let profile = self.profile.clone();
        let engine = self.policy_engine.clone();
        let accounting_profile_name = profile_name.clone();
        let audit_profile = self.profile.clone();
        let audit_profile_name = profile_name.clone();
        let withheld_audit_profile = self.profile.clone();
        let withheld_audit_profile_name = profile_name.clone();
        let credential = commit_authorization(
            &state,
            approval_store.as_ref(),
            approval_key.as_ref(),
            &args.authorization_id,
            i64::try_from(now_ms / 1_000).unwrap_or(i64::MAX),
            &self.profile.network_passphrase,
            &signer,
            &rpc,
            move |_record, _prepared, exact_effects| {
                stellar_agent_network::policy_state::record_authorized_window_state(
                    engine.as_ref(),
                    &descriptor,
                    &profile,
                    &accounting_profile_name,
                    &ValueClass::Value(exact_effects.clone()),
                )
                .map_err(|_| state_error())
            },
            move |authorized| {
                let legs = authorized
                    .value_effects
                    .legs()
                    .iter()
                    .map(ValueLegRecord::from)
                    .collect();
                let id_hash = hex::encode(Sha256::digest(
                    authorized.record.authorization_id().as_bytes(),
                ));
                let entry = AuditEntry::new_mpp_charge_authorized(
                    "stellar_mpp_charge_commit",
                    "stellar:testnet",
                    id_hash,
                    hex::encode(authorized.record.fingerprint()),
                    legs,
                    stellar_agent_core::observability::RedactedStrkey::from_full(authorized.payer),
                    authorized.record.approval_nonce().is_some(),
                    PolicyDecision::Allow,
                    uuid::Uuid::new_v4().to_string(),
                );
                emit_value_audit_row_strict(&audit_profile, &audit_profile_name, entry)
                    .map_err(|()| state_error())
            },
            move |withheld| {
                let entry = AuditEntry::new_mpp_authorization_withheld(
                    hex::encode(Sha256::digest(
                        withheld.record.authorization_id().as_bytes(),
                    )),
                    hex::encode(withheld.record.fingerprint()),
                    withheld.failure_stage,
                    withheld.key_access_began,
                    withheld.policy_budget_consumed,
                    uuid::Uuid::new_v4().to_string(),
                );
                let _ = emit_value_audit_row_strict(
                    &withheld_audit_profile,
                    &withheld_audit_profile_name,
                    entry,
                );
            },
        )
        .await;
        match credential {
            Ok(credential) => Ok(success(json!({
                "authorization_id": args.authorization_id,
                "credential": credential,
            }))),
            Err(error) => Ok(mpp_error_result(&error)),
        }
    }

    /// Records a trusted-host receipt without claiming ledger settlement.
    #[mcp_tool_item(
        name = "stellar_mpp_record_receipt",
        destructive_hint = false,
        read_only_hint = false,
        chain_id_required = false
    )]
    #[tool(
        name = "stellar_mpp_record_receipt",
        description = "Validate and durably record a trusted-host MPP receipt. This records host observation only and does not claim ledger settlement.",
        annotations(read_only_hint = false, destructive_hint = false)
    )]
    pub async fn stellar_mpp_record_receipt(
        &self,
        Parameters(args): Parameters<MppReceiptArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if let Err(result) = self.mpp_preflight_profile(&self.profile_name_for_approval()) {
            return Ok(result);
        }
        let receipt = match parse_receipt(&args.receipt) {
            Ok(receipt) => receipt,
            Err(error) => return Ok(mpp_error_result(&error)),
        };
        let profile_name = self.profile_name_for_approval();
        let state = match MppAuthorizationStore::from_profile_keyring(&profile_name, false) {
            Ok(state) => state,
            Err(error) => return Ok(mpp_error_result(&error)),
        };
        let now = stellar_agent_core::timefmt::now_unix_ms()
            .map(|ms| i64::try_from(ms / 1_000).unwrap_or(i64::MAX))
            .map_err(|_| rmcp::ErrorData::internal_error("clock unavailable", None))?;
        let record = match state.record_receipt(&args.authorization_id, &receipt, now) {
            Ok(record) => record,
            Err(error) => return Ok(mpp_error_result(&error)),
        };
        let source = match args.receipt {
            ReceiptInput::Http { .. } => "http",
            ReceiptInput::Mcp { .. } => "mcp",
        };
        let entry = AuditEntry::new_mpp_receipt_observed(
            hex::encode(Sha256::digest(args.authorization_id.as_bytes())),
            hex::encode(receipt.digest()),
            redact_reference(receipt.reference()),
            source,
            receipt.status(),
            uuid::Uuid::new_v4().to_string(),
        );
        if emit_value_audit_row_strict(&self.profile, &profile_name, entry).is_err() {
            return Ok(mpp_state_error());
        }
        Ok(success(json!({
            "authorization_id": record.authorization_id(),
            "status": record.status(),
            "receipt_observed": true,
            "ledger_settlement": "unknown",
        })))
    }

    /// Reconciles a final transaction against the exact prepared charge.
    #[mcp_tool_item(
        name = "stellar_mpp_reconcile_transaction",
        destructive_hint = false,
        read_only_hint = false,
        chain_id_required = false
    )]
    #[tool(
        name = "stellar_mpp_reconcile_transaction",
        description = "Fetch a final Stellar testnet transaction, verify direct or fee-bump envelope semantics against a stored MPP authorization, and record settled or failed ledger outcome.",
        annotations(read_only_hint = false, destructive_hint = false)
    )]
    pub async fn stellar_mpp_reconcile_transaction(
        &self,
        Parameters(args): Parameters<MppReconcileArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if let Err(result) = self.mpp_preflight_profile(&self.profile_name_for_approval()) {
            return Ok(result);
        }
        let profile_name = self.profile_name_for_approval();
        let state = match MppAuthorizationStore::from_profile_keyring(&profile_name, false) {
            Ok(state) => state,
            Err(error) => return Ok(mpp_error_result(&error)),
        };
        let rpc = match StellarReconciliationRpc::new(&self.profile.rpc_url) {
            Ok(rpc) => rpc,
            Err(error) => return Ok(mpp_error_result(&error)),
        };
        let now = stellar_agent_core::timefmt::now_unix_ms()
            .map(|ms| i64::try_from(ms / 1_000).unwrap_or(i64::MAX))
            .map_err(|_| rmcp::ErrorData::internal_error("clock unavailable", None))?;
        let result = match reconcile_transaction(
            &state,
            &args.authorization_id,
            &args.transaction_hash,
            now,
            &rpc,
        )
        .await
        {
            Ok(result) => result,
            Err(error) => return Ok(mpp_error_result(&error)),
        };
        let entry = AuditEntry::new_mpp_settlement_reconciled(
            hex::encode(Sha256::digest(args.authorization_id.as_bytes())),
            result.transaction_reference_redacted.clone(),
            result.ledger,
            result.outcome.clone(),
            uuid::Uuid::new_v4().to_string(),
        );
        if emit_value_audit_row_strict(&self.profile, &profile_name, entry).is_err() {
            return Ok(mpp_state_error());
        }
        Ok(success(result))
    }

    /// Returns redacted authorization status.
    #[mcp_tool_item(
        name = "stellar_mpp_authorization_status",
        destructive_hint = false,
        read_only_hint = true,
        chain_id_required = false
    )]
    #[tool(
        name = "stellar_mpp_authorization_status",
        description = "Return redacted MPP authorization, approval, policy-accounting, host-observation, and independent ledger-outcome status. Never returns challenge, receipt, XDR, reference, or credential values.",
        annotations(read_only_hint = true, destructive_hint = false)
    )]
    pub async fn stellar_mpp_authorization_status(
        &self,
        Parameters(args): Parameters<MppStatusArgs>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if let Err(result) = self.mpp_preflight_profile(&self.profile_name_for_approval()) {
            return Ok(result);
        }
        let profile_name = self.profile_name_for_approval();
        let state = match MppAuthorizationStore::from_profile_keyring(&profile_name, false) {
            Ok(state) => state,
            Err(error) => return Ok(mpp_error_result(&error)),
        };
        let now_unix = stellar_agent_core::timefmt::now_unix_ms()
            .map(|now| i64::try_from(now / 1_000).unwrap_or(i64::MAX))
            .map_err(|_| rmcp::ErrorData::internal_error("clock unavailable", None))?;
        match authorization_status(&state, &args.authorization_id, now_unix) {
            Ok(status) => Ok(success(status)),
            Err(error) => Ok(mpp_error_result(&error)),
        }
    }

    fn mpp_preflight_profile(&self, requested_profile: &str) -> Result<(), CallToolResult> {
        if self.profile.network_passphrase != TESTNET_PASSPHRASE {
            return Err(mpp_error_result(&MppError::new(
                MppErrorCode::NetworkForbidden,
                "MPP charge is enabled only on Stellar testnet",
            )));
        }
        if requested_profile != self.profile_name_for_approval() {
            return Err(mpp_error_result(&MppError::new(
                MppErrorCode::ChallengeMismatch,
                "MPP profile does not match the active wallet profile",
            )));
        }
        Ok(())
    }
}

fn success(value: impl serde::Serialize) -> CallToolResult {
    let envelope = stellar_agent_core::envelope::Envelope::ok(value);
    CallToolResult::success(vec![Content::text(
        envelope
            .to_json_pretty()
            .unwrap_or_else(|_| "{}".to_owned()),
    )])
}

fn mpp_error_result(error: &MppError) -> CallToolResult {
    business_error_result(error.code(), error.message())
}

fn mpp_state_error() -> CallToolResult {
    mpp_error_result(&state_error())
}

fn mpp_approval_error() -> CallToolResult {
    mpp_error_result(&MppError::new(
        MppErrorCode::ApprovalInvalid,
        "MPP approval is missing, invalid, or expired",
    ))
}

fn mpp_signing_error() -> CallToolResult {
    mpp_error_result(&MppError::new(
        MppErrorCode::SigningFailed,
        "sponsored authorization signing failed",
    ))
}

fn state_error() -> MppError {
    MppError::new(
        MppErrorCode::StateUnavailable,
        "MPP authorization state is unavailable",
    )
}

fn redact_reference(value: &str) -> String {
    format!("{}...{}", &value[..8], &value[value.len() - 8..])
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        reason = "test fixtures use expect for concise setup"
    )]

    use stellar_agent_core::{policy::ToolValueKind, profile::schema::Profile};

    use super::*;

    const MPP_TOOLS: [&str; 5] = [
        "stellar_mpp_charge_prepare",
        "stellar_mpp_charge_commit",
        "stellar_mpp_record_receipt",
        "stellar_mpp_reconcile_transaction",
        "stellar_mpp_authorization_status",
    ];

    #[test]
    fn registry_and_router_expose_closed_mpp_surface() {
        let server = WalletServer::new(
            Profile::builder_testnet("svc", "acct", "nonce-svc", "nonce-acct")
                .with_noop_engine()
                .build(),
        )
        .expect("server");
        let router = WalletServer::router_tool_names();
        for name in MPP_TOOLS {
            assert!(
                router.iter().any(|candidate| candidate == name),
                "missing {name}"
            );
            assert!(
                server.tool_registry_descriptor(name).is_some(),
                "unregistered {name}"
            );
        }
        let prepare = server
            .tool_registry_descriptor("stellar_mpp_charge_prepare")
            .expect("prepare descriptor");
        assert!(!prepare.destructive_hint);
        assert_eq!(prepare.value_kind, ToolValueKind::MovesValue);
        let commit = server
            .tool_registry_descriptor("stellar_mpp_charge_commit")
            .expect("commit descriptor");
        assert!(commit.destructive_hint);
        assert_eq!(commit.value_kind, ToolValueKind::MovesValue);
        let status = server
            .tool_registry_descriptor("stellar_mpp_authorization_status")
            .expect("status descriptor");
        assert!(status.read_only_hint);
        assert!(!status.destructive_hint);
        assert!(
            stellar_agent_toolsets_runtime::matrix::ALL_MATRIX_TOOL_NAMES
                .iter()
                .all(|name| !name.starts_with("stellar_mpp_"))
        );
    }

    #[test]
    fn toolset_routing_cannot_resolve_any_mpp_tool() {
        use stellar_agent_toolsets_runtime::matrix::{GATED_MATRIX_ENTRIES, resolve_action};

        for name in MPP_TOOLS {
            // The ungated resolver refuses the action outright.
            assert!(
                resolve_action(name).is_err(),
                "{name} must be unresolvable through the ungated toolset matrix"
            );
            // No gated capability grants it either.
            assert!(
                GATED_MATRIX_ENTRIES
                    .iter()
                    .all(|(_capability, tools)| !tools.contains(&name)),
                "{name} must be absent from every gated toolset grant"
            );
        }
    }

    #[test]
    fn schemas_are_strict_and_commit_has_no_replacement_terms() {
        let tools = WalletServer::all_registered_tools();
        for name in MPP_TOOLS {
            let tool = tools
                .iter()
                .find(|tool| tool.name.as_ref() == name)
                .expect("tool schema");
            let schema = serde_json::to_value(&tool.input_schema).expect("schema JSON");
            assert_eq!(
                schema["additionalProperties"], false,
                "{name} must be closed"
            );
        }
        let commit = tools
            .iter()
            .find(|tool| tool.name.as_ref() == "stellar_mpp_charge_commit")
            .expect("commit");
        let schema = serde_json::to_value(&commit.input_schema).expect("schema JSON");
        let properties = schema["properties"].as_object().expect("properties");
        assert_eq!(properties.len(), 3);
        assert!(properties.contains_key("authorization_id"));
        assert!(properties.contains_key("nonce"));
        assert!(properties.contains_key("expires_at_unix_ms"));
    }

    #[tokio::test]
    async fn every_mpp_tool_refuses_mainnet_before_state_or_keyring_access() {
        let server = WalletServer::new(
            Profile::builder_mainnet("svc", "acct", "nonce-svc", "nonce-acct")
                .with_noop_engine()
                .build(),
        )
        .expect("server");
        let context = stellar_agent_mpp::McpRequestContext::from_params(
            "merchant",
            stellar_agent_mpp::McpOperationKind::Tool,
            "charge",
            None,
        )
        .expect("context");
        let results = [
            server
                .stellar_mpp_charge_prepare(Parameters(MppPrepareArgs {
                    profile: server.profile_name_for_approval(),
                    challenge: ChallengeInput::Mcp {
                        challenges: Vec::new(),
                        selected_challenge_id: None,
                        context,
                    },
                }))
                .await
                .expect("business error"),
            server
                .stellar_mpp_charge_commit(Parameters(MppCommitArgs {
                    authorization_id: "mpp_00000000000000000000000000000000".to_owned(),
                    nonce: "invalid".to_owned(),
                    expires_at_unix_ms: 0,
                }))
                .await
                .expect("business error"),
            server
                .stellar_mpp_record_receipt(Parameters(MppReceiptArgs {
                    authorization_id: "mpp_00000000000000000000000000000000".to_owned(),
                    receipt: ReceiptInput::Mcp {
                        receipt: serde_json::Value::Null,
                    },
                }))
                .await
                .expect("business error"),
            server
                .stellar_mpp_reconcile_transaction(Parameters(MppReconcileArgs {
                    authorization_id: "mpp_00000000000000000000000000000000".to_owned(),
                    transaction_hash: "invalid".to_owned(),
                }))
                .await
                .expect("business error"),
            server
                .stellar_mpp_authorization_status(Parameters(MppStatusArgs {
                    authorization_id: "mpp_00000000000000000000000000000000".to_owned(),
                }))
                .await
                .expect("business error"),
        ];
        for result in results {
            let (code, message, _text) = crate::tools::common::assert_business_envelope(&result);
            assert_eq!(code, "mpp.network_forbidden");
            assert!(!message.contains("keyring") && !message.contains("state"));
        }
    }
}
