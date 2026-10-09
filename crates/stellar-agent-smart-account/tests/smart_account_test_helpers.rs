//! Offline integration tests that require test helpers.

#[path = "smart_account_test_helpers/audit_log_emission.rs"]
mod audit_log_emission;
#[path = "smart_account_test_helpers/deploy_c_via_cli_returns_strkey_and_seed.rs"]
mod deploy_c_via_cli_returns_strkey_and_seed;
#[path = "smart_account_test_helpers/deploy_smart_account_collective_budget_mock.rs"]
mod deploy_smart_account_collective_budget_mock;
#[path = "smart_account_test_helpers/deterministic_address_derivation.rs"]
mod deterministic_address_derivation;
#[path = "smart_account_test_helpers/execute_path_drift_check_mock.rs"]
mod execute_path_drift_check_mock;
#[path = "smart_account_test_helpers/recover_strkey_from_seed_and_deployer.rs"]
mod recover_strkey_from_seed_and_deployer;
