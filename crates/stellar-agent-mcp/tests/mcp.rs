//! Offline integration tests for the MCP server.

#[path = "common/mod.rs"]
#[allow(
    clippy::expect_used,
    reason = "shared test helpers; a failed expectation panics the calling test"
)]
mod common;

#[path = "mcp/approval_attestation_indistinguishability.rs"]
mod approval_attestation_indistinguishability;
#[path = "mcp/approval_cap_integration.rs"]
mod approval_cap_integration;
#[path = "mcp/approval_consumed_integration.rs"]
mod approval_consumed_integration;
#[path = "mcp/approval_spine_integration.rs"]
mod approval_spine_integration;
#[path = "mcp/approve_hint_source_scan.rs"]
mod approve_hint_source_scan;
#[path = "mcp/audit_binding_integration.rs"]
mod audit_binding_integration;
#[path = "mcp/balances_integration.rs"]
mod balances_integration;
#[path = "mcp/claim_integration.rs"]
mod claim_integration;
#[path = "mcp/commit_record_integration.rs"]
mod commit_record_integration;
#[path = "mcp/create_account_commit_args_redrive_integration.rs"]
mod create_account_commit_args_redrive_integration;
#[path = "mcp/create_account_integration.rs"]
mod create_account_integration;
#[path = "mcp/defi_record_integration.rs"]
mod defi_record_integration;
#[path = "mcp/fee_stats_integration.rs"]
mod fee_stats_integration;
#[path = "mcp/friendbot_integration.rs"]
mod friendbot_integration;
#[path = "mcp/integration.rs"]
mod integration;
#[path = "mcp/mpp_audit_anchor_integration.rs"]
mod mpp_audit_anchor_integration;
#[path = "mcp/pay_commit_args_redrive_integration.rs"]
mod pay_commit_args_redrive_integration;
#[path = "mcp/pay_integration.rs"]
mod pay_integration;
#[path = "mcp/policy_advisory_discipline.rs"]
mod policy_advisory_discipline;
#[path = "mcp/policy_v1_integration.rs"]
mod policy_v1_integration;
#[path = "mcp/preflight_integration.rs"]
mod preflight_integration;
#[path = "mcp/profile_selection_integration.rs"]
mod profile_selection_integration;
#[path = "mcp/registry_walk.rs"]
mod registry_walk;
#[path = "mcp/resource_no_secrets.rs"]
mod resource_no_secrets;
#[path = "mcp/sep48_sep47_envelope_shape.rs"]
mod sep48_sep47_envelope_shape;
#[path = "mcp/toolset_args_validation_integration.rs"]
mod toolset_args_validation_integration;
#[path = "mcp/toolset_sign_payment_gated_integration.rs"]
mod toolset_sign_payment_gated_integration;
#[path = "mcp/toolsets_matrix_invariants.rs"]
mod toolsets_matrix_invariants;
#[path = "mcp/trustline_integration.rs"]
mod trustline_integration;
#[path = "mcp/x402_audit_gate_integration.rs"]
mod x402_audit_gate_integration;
