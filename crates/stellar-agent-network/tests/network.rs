//! Offline integration tests for the network crate.

#[path = "network/account_client_coverage.rs"]
mod account_client_coverage;
#[path = "network/accounts_create_integration.rs"]
mod accounts_create_integration;
#[path = "network/balances_integration.rs"]
mod balances_integration;
#[path = "network/balances_live.rs"]
mod balances_live;
#[path = "network/connection_counter_control.rs"]
mod connection_counter_control;
#[path = "network/fee_bump_coverage.rs"]
mod fee_bump_coverage;
#[path = "network/fee_bump_idempotent_integration.rs"]
mod fee_bump_idempotent_integration;
#[path = "network/fee_bump_retry_coverage.rs"]
mod fee_bump_retry_coverage;
#[path = "network/fee_bump_retry_unit.rs"]
mod fee_bump_retry_unit;
#[path = "network/fee_stats_integration.rs"]
mod fee_stats_integration;
#[path = "network/fees_unit_integration.rs"]
mod fees_unit_integration;
#[path = "network/fetch_data_entry_regression.rs"]
mod fetch_data_entry_regression;
#[path = "network/friendbot_integration.rs"]
mod friendbot_integration;
#[path = "network/headless_keyring_dispatch.rs"]
mod headless_keyring_dispatch;
#[path = "network/idempotent_submit_block_b_integration.rs"]
mod idempotent_submit_block_b_integration;
#[path = "network/idempotent_submit_integration.rs"]
mod idempotent_submit_integration;
#[path = "network/idempotent_submit_receipt_reconcile.rs"]
mod idempotent_submit_receipt_reconcile;
#[path = "network/keyring_extended_integration.rs"]
mod keyring_extended_integration;
#[path = "network/keyring_integration.rs"]
mod keyring_integration;
#[path = "network/pay_integration.rs"]
mod pay_integration;
#[path = "network/pay_live.rs"]
mod pay_live;
#[path = "network/redaction_audit.rs"]
mod redaction_audit;
#[path = "network/retry_backoff_integration.rs"]
mod retry_backoff_integration;
#[path = "network/sep29_cross_rpc_integration.rs"]
mod sep29_cross_rpc_integration;
#[path = "network/sign_with_ledger_no_keyring_lookup.rs"]
mod sign_with_ledger_no_keyring_lookup;
#[path = "network/submission_record_integration.rs"]
mod submission_record_integration;
#[path = "network/submission_recorder_discipline.rs"]
mod submission_recorder_discipline;
#[path = "network/submit_binding_integration.rs"]
mod submit_binding_integration;
#[path = "network/submit_integration.rs"]
mod submit_integration;
#[path = "network/submit_result_mapping.rs"]
mod submit_result_mapping;
#[path = "network/transaction_status_reads.rs"]
mod transaction_status_reads;
#[path = "network/window_admission.rs"]
mod window_admission;
#[path = "network/window_reconcile.rs"]
mod window_reconcile;
