//! Offline integration tests for smart accounts.
//!
//! The proxy-isolation test `list_rules_no_indexer_call_mock` keeps its own
//! target; see its module doc.

#[path = "smart-account-fixtures/adversarial/combined_rpc_responder.rs"]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "shared test helpers assert fixture invariants"
)]
mod combined_rpc_responder;

#[path = "smart-account-fixtures/adversarial/rpc_mock_helpers.rs"]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "shared test helpers assert fixture invariants"
)]
mod rpc_mock_helpers;

#[path = "smart_account/adversarial_fixtures.rs"]
mod adversarial_fixtures;
#[path = "smart_account/audit_log_missing_mock.rs"]
mod audit_log_missing_mock;
#[path = "smart_account/auth_digest_parity.rs"]
mod auth_digest_parity;
#[path = "smart_account/credentials_e2e.rs"]
mod credentials_e2e;
#[path = "smart_account/horizon_bound_parity_test.rs"]
mod horizon_bound_parity_test;
#[path = "smart_account/list_active_context_rules_mock.rs"]
mod list_active_context_rules_mock;
#[path = "smart_account/multicall_auth_rule_count_mock.rs"]
mod multicall_auth_rule_count_mock;
#[path = "smart_account/oz_caps_parity_test.rs"]
mod oz_caps_parity_test;
#[path = "smart_account/oz_panic_discriminant_mapping_mock.rs"]
mod oz_panic_discriminant_mapping_mock;
#[path = "smart_account/simulate_install_rule_mock.rs"]
mod simulate_install_rule_mock;
#[path = "smart_account/submission_records_mock.rs"]
mod submission_records_mock;
#[path = "smart_account/submit_signed_invoke_sequence_floor_mock.rs"]
mod submit_signed_invoke_sequence_floor_mock;
#[path = "smart_account/upper_bound_max_scan_id_parity_test.rs"]
mod upper_bound_max_scan_id_parity_test;
#[path = "smart_account/verify_rule_wasm_pins_paths.rs"]
mod verify_rule_wasm_pins_paths;
#[path = "smart_account/wallet_install_arg_parity.rs"]
mod wallet_install_arg_parity;
#[path = "smart_account/wasm_pinning_adversarial_fixtures.rs"]
mod wasm_pinning_adversarial_fixtures;
