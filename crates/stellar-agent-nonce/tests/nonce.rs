//! Integration tests for the nonce crate.

#[path = "nonce/boot_nonce_invalidates_pre_restart.rs"]
mod boot_nonce_invalidates_pre_restart;
#[path = "nonce/chain_mismatch.rs"]
mod chain_mismatch;
#[path = "nonce/constant_time_compare.rs"]
mod constant_time_compare;
#[path = "nonce/envelope_mismatch.rs"]
mod envelope_mismatch;
#[path = "nonce/expired_rejected.rs"]
mod expired_rejected;
#[path = "nonce/helpers.rs"]
mod helpers;
#[path = "nonce/key_rotation_first_run.rs"]
mod key_rotation_first_run;
#[path = "nonce/key_rotation_invalidates.rs"]
mod key_rotation_invalidates;
#[path = "nonce/key_too_short.rs"]
mod key_too_short;
#[path = "nonce/load_key_error_paths.rs"]
mod load_key_error_paths;
#[path = "nonce/load_key_panic_unwinds_through_zeroizing_scope.rs"]
mod load_key_panic_unwinds_through_zeroizing_scope;
#[path = "nonce/mint_verify_round_trip.rs"]
mod mint_verify_round_trip;
#[path = "nonce/osrng_key_generation.rs"]
mod osrng_key_generation;
#[path = "nonce/owner_key_refusal.rs"]
mod owner_key_refusal;
#[path = "nonce/replay_rejected.rs"]
mod replay_rejected;
#[path = "nonce/replay_window_eviction.rs"]
mod replay_window_eviction;
#[path = "nonce/tool_mismatch.rs"]
mod tool_mismatch;
#[path = "nonce/ttl_enforcement.rs"]
mod ttl_enforcement;
#[path = "nonce/unregistered_tool_rejected.rs"]
mod unregistered_tool_rejected;
#[path = "nonce/verify_hmac_only.rs"]
mod verify_hmac_only;
