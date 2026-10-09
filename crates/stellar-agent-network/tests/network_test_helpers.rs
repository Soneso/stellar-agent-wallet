//! Offline integration tests requiring the network test helpers.

#[path = "network_test_helpers/builder_cache_account_topup.rs"]
mod builder_cache_account_topup;
#[path = "network_test_helpers/builder_cache_account_topup2.rs"]
mod builder_cache_account_topup2;
#[path = "network_test_helpers/builder_cache_account_topup3.rs"]
mod builder_cache_account_topup3;
#[path = "network_test_helpers/cache_coverage.rs"]
mod cache_coverage;
#[path = "network_test_helpers/counterparty_cache_integration.rs"]
mod counterparty_cache_integration;
#[path = "network_test_helpers/counterparty_concurrent_first_fetch.rs"]
mod counterparty_concurrent_first_fetch;
#[path = "network_test_helpers/counterparty_fetch_extended_integration.rs"]
mod counterparty_fetch_extended_integration;
#[path = "network_test_helpers/counterparty_fetch_integration.rs"]
mod counterparty_fetch_integration;
