//! Integration tests for the core crate.

#[path = "core/audit_log_alpha9_signer_set_fixture.rs"]
mod audit_log_alpha9_signer_set_fixture;
#[path = "core/envelope_decode_authoritative_args.rs"]
mod envelope_decode_authoritative_args;
#[path = "core/panic_hook_message_bound.rs"]
mod panic_hook_message_bound;
#[path = "core/policy_descriptor_equivalence.rs"]
mod policy_descriptor_equivalence;
#[path = "core/policy_fixtures_adversarial.rs"]
mod policy_fixtures_adversarial;
#[path = "core/profile_horizon_bound_test.rs"]
mod profile_horizon_bound_test;
#[path = "core/profile_scan_id_bound_test.rs"]
mod profile_scan_id_bound_test;
#[path = "core/subscriber_install_path.rs"]
mod subscriber_install_path;
