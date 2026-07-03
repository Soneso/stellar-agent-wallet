//! Adversarial fixture tests for the signer-set and threshold lifecycle.
//!
//! Tests the refusal-path, divergence-detection, and audit-log integrity invariants
//! of [`stellar_agent_smart_account::managers::signers::SignersManager`] under
//! adversarial inputs — without a live testnet.
//!
//! # Coverage map
//!
//! | Fixture | Coverage |
//! |---------|----------|
//! | [`threshold_brick`] | `ThresholdUnreachable` on 1-of-1 remove |
//! | [`fresh_wallet_missing_baseline`] | `SignerSetMissingBaseline` with empty audit log |
//! | [`audit_log_tampering_detection`] | `AuditLogIntegrityError` on tampered JSONL |
//! | [`audit_log_baseline_reconstruction`] | Most-recent row dictates reconstruction |
//! | [`audit_log_wholesale_replacement`] | HMAC sidecar mismatch on swapped log |
//! | [`signer_set_divergence_out_of_band`] | `SignerSetDiverged` (both RPCs agree; stale baseline) |
//! | [`rpc_divergence_before`] | `NetworkRpcDivergence` before `SignerSetDiverged` |
//! | [`threshold_policy_not_installed`] | `ThresholdPolicyNotInstalled` on empty policies |
//! | [`threshold_policy_identification_zero_match`] | `ThresholdPolicyIdentificationFailed` |
//! | [`threshold_policy_identification_multi_match`] | `ThresholdPolicyIdentificationFailed` |
//! | [`signer_set_divergence_rpc_suppression`] | `NetworkRpcDivergence` (primary stale) |
//! | [`threshold_policy_identification_rpc_divergence`] | `NetworkRpcDivergence` on hash mismatch |
//! | [`prop_audit_log_baseline_reconstruction`] | Property test: most-recent row dictates state |
//! | [`verifier_identification_rpc_divergence`] | `NetworkRpcDivergence` on verifier hash mismatch |
//! | [`contract_mutability_admin_key_present`] | `MutabilityStatus::Mutable` when Admin key present |
//! | [`contract_mutability_non_address_admin_value`] | fail-closed Mutable on non-address Admin value |
//! | [`contract_mutability_non_map_instance_storage`] | fail-closed Mutable on non-map instance storage |
//! | [`divergence_failure_self_audit_writer`] | write-path divergence failures emit via `self.audit_writer` |
//! | [`wasm_hash_canonicalisation_parity`] | WASM hash canonicalisation regression-lock: byte-identical no-drift + idempotence + first8 formatter determinism |
//! | [`rule_id_downgrade`] | Rule-ID downgrade regression-lock: 5 divergence sub-codes + wire-code mapping + comparator ordering |
//! | [`multicall_inner_invocation_count_cap_51_inner`] | Amplification-defence via `evaluate_bundle` (51-inner deny + 49/50 boundary) |
//! | [`multicall_bundle_aggregate_cap`] | Split-and-scatter via `evaluate_bundle` (sum-over-cap deny + boundary) |
//! | [`multicall_upper_bound_assertion`] | Multicall trust-anchor ceiling: const-context invariant runtime witness |
//! | [`cross_rpc_consumer_audit`] | Cross-RPC primitive consumer enumeration + source-grep regression-lock |
//! | [`timelock_salt_collision`] (`test-helpers`) | Timelock salt-derivation collision resistance: dual-component source-lock + uniqueness under distinct request\_ids + timestamps; tests 3/4/5 call `derive_schedule_salt` directly |
//! | [`verifier_migration_dry_run`] | Verifier-migration planner dry-run mock fixtures |
//! | [`verifier_migration_submit`] | Verifier-migration submit mock fixtures |
//! | [`concurrent_signing_race`] | Per-rule async mutex serialisation (TOCTOU mitigation): A1 mutex serialisation, A2 FrozenChainStateTuple ordering, A3 expected\_audit\_row\_hash post-first-call binding, A4 SignerSetDiverged on audit-log update |
//!
//! # Test organisation
//!
//! Each test group is its own sub-module. The submodule files live in
//! `tests/smart-account-fixtures/adversarial/`; this file
//! includes them via the `#[path]` attribute so Cargo discovers them through a
//! single `tests/adversarial_fixtures.rs` entry point.
//!
//! # Implements
//!
//! Adversarial regression gates for the atomic signer-threshold update invariant.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; adversarial fixtures assert invariants via panic-on-failure"
)]

// ── Shared RPC mock helpers (used by wiremock-dependent fixtures) ─────────────

#[path = "smart-account-fixtures/adversarial/rpc_mock_helpers.rs"]
mod rpc_mock_helpers;

#[path = "smart-account-fixtures/adversarial/combined_rpc_responder.rs"]
mod combined_rpc_responder;

// ── Sub-modules (one per adversarial fixture) ─────────────────────────────────

#[path = "smart-account-fixtures/adversarial/audit_log_baseline_reconstruction.rs"]
mod audit_log_baseline_reconstruction;

#[path = "smart-account-fixtures/adversarial/audit_log_tampering_detection.rs"]
mod audit_log_tampering_detection;

#[path = "smart-account-fixtures/adversarial/audit_log_wholesale_replacement.rs"]
mod audit_log_wholesale_replacement;

#[path = "smart-account-fixtures/adversarial/fresh_wallet_missing_baseline.rs"]
mod fresh_wallet_missing_baseline;

#[path = "smart-account-fixtures/adversarial/threshold_brick.rs"]
mod threshold_brick;

#[path = "smart-account-fixtures/adversarial/signer_set_divergence_out_of_band.rs"]
mod signer_set_divergence_out_of_band;

#[path = "smart-account-fixtures/adversarial/rpc_divergence_before.rs"]
mod rpc_divergence_before;

#[path = "smart-account-fixtures/adversarial/threshold_policy_not_installed.rs"]
mod threshold_policy_not_installed;

#[path = "smart-account-fixtures/adversarial/threshold_policy_identification_zero_match.rs"]
mod threshold_policy_identification_zero_match;

#[path = "smart-account-fixtures/adversarial/threshold_policy_identification_multi_match.rs"]
mod threshold_policy_identification_multi_match;

#[path = "smart-account-fixtures/adversarial/signer_set_divergence_rpc_suppression.rs"]
mod signer_set_divergence_rpc_suppression;

#[path = "smart-account-fixtures/adversarial/threshold_policy_identification_rpc_divergence.rs"]
mod threshold_policy_identification_rpc_divergence;

#[path = "smart-account-fixtures/adversarial/prop_audit_log_baseline_reconstruction.rs"]
mod prop_audit_log_baseline_reconstruction;

#[path = "smart-account-fixtures/adversarial/verifier_identification_rpc_divergence.rs"]
mod verifier_identification_rpc_divergence;

#[path = "smart-account-fixtures/adversarial/contract_mutability_admin_key_present.rs"]
mod contract_mutability_admin_key_present;

#[path = "smart-account-fixtures/adversarial/contract_mutability_non_address_admin_value.rs"]
mod contract_mutability_non_address_admin_value;

#[path = "smart-account-fixtures/adversarial/contract_mutability_non_map_instance_storage.rs"]
mod contract_mutability_non_map_instance_storage;

#[path = "smart-account-fixtures/adversarial/divergence_failure_self_audit_writer.rs"]
mod divergence_failure_self_audit_writer;

#[cfg(feature = "test-helpers")]
#[path = "smart-account-fixtures/adversarial/wasm_hash_canonicalisation_parity.rs"]
mod wasm_hash_canonicalisation_parity;

#[cfg(feature = "test-helpers")]
#[path = "smart-account-fixtures/adversarial/rule_id_downgrade.rs"]
mod rule_id_downgrade;

#[path = "smart-account-fixtures/adversarial/multicall_inner_invocation_count_cap_51_inner.rs"]
mod multicall_inner_invocation_count_cap_51_inner;

#[path = "smart-account-fixtures/adversarial/multicall_bundle_aggregate_cap.rs"]
mod multicall_bundle_aggregate_cap;

#[path = "smart-account-fixtures/adversarial/multicall_upper_bound_assertion.rs"]
mod multicall_upper_bound_assertion;

#[path = "smart-account-fixtures/adversarial/cross_rpc_consumer_audit.rs"]
mod cross_rpc_consumer_audit;

// Tests 3/4/5 call `derive_schedule_salt` which is only visible when the
// `test-helpers` feature is active (re-exported in lib.rs under that gate).
// Tests 1/2 (source-grep) do not require the feature but live in the same
// file; gating the whole module here is the simplest consistent approach.
#[cfg(feature = "test-helpers")]
#[path = "smart-account-fixtures/adversarial/timelock_salt_collision.rs"]
mod timelock_salt_collision;

#[cfg(feature = "test-helpers")]
#[path = "smart-account-fixtures/adversarial/verifier_migration_dry_run.rs"]
mod verifier_migration_dry_run;

#[cfg(feature = "test-helpers")]
#[path = "smart-account-fixtures/adversarial/verifier_migration_submit.rs"]
mod verifier_migration_submit;

#[path = "smart-account-fixtures/adversarial/concurrent_signing_race.rs"]
mod concurrent_signing_race;
