//! Offline integration tests for the Stellar agent CLI.

#[path = "cli/advisory_no_network_deps.rs"]
mod advisory_no_network_deps;
#[path = "cli/approval_attestation_binding.rs"]
mod approval_attestation_binding;
#[path = "cli/audit_binding_cli.rs"]
mod audit_binding_cli;
#[path = "cli/audit_path_discipline.rs"]
mod audit_path_discipline;
#[path = "cli/audit_verify_codes.rs"]
mod audit_verify_codes;
#[path = "cli/consent_drain_source_order.rs"]
mod consent_drain_source_order;
#[path = "cli/fresh_v1_ceremony.rs"]
mod fresh_v1_ceremony;
#[path = "cli/keyring_classification_discipline.rs"]
mod keyring_classification_discipline;
#[path = "cli/mpp_first_run_vs_unavailable_state.rs"]
mod mpp_first_run_vs_unavailable_state;
#[path = "cli/output_failure_exit_code.rs"]
mod output_failure_exit_code;
#[path = "cli/owner_key_sweep_cli.rs"]
mod owner_key_sweep_cli;
#[path = "cli/pool_init_lifecycle.rs"]
mod pool_init_lifecycle;
#[path = "cli/profile_env_var_resolution.rs"]
mod profile_env_var_resolution;
#[path = "cli/profile_flag_discipline.rs"]
mod profile_flag_discipline;
#[path = "cli/profile_init_name_refusals.rs"]
mod profile_init_name_refusals;
#[path = "cli/profile_migrate_refusal_codes.rs"]
mod profile_migrate_refusal_codes;
#[path = "cli/profile_name_path_traversal_refused.rs"]
mod profile_name_path_traversal_refused;
#[path = "cli/profile_name_reconciliation.rs"]
mod profile_name_reconciliation;
#[path = "cli/profile_provenance_refusal.rs"]
mod profile_provenance_refusal;
#[path = "cli/profile_reconciliation_discipline.rs"]
mod profile_reconciliation_discipline;
#[path = "cli/profile_show_load_failure_codes.rs"]
mod profile_show_load_failure_codes;
#[path = "cli/profile_show_profile_flag_equivalence.rs"]
mod profile_show_profile_flag_equivalence;
#[path = "cli/reconcile_pass_discipline.rs"]
mod reconcile_pass_discipline;
#[path = "cli/staged_submit_probe_ordering.rs"]
mod staged_submit_probe_ordering;
#[path = "cli/tx_receipt_clear_integration.rs"]
mod tx_receipt_clear_integration;
#[path = "cli/usage_error_envelope.rs"]
mod usage_error_envelope;
