//! Adversarial fixture tests for wasm-hash pinning.
//!
//! Tests the refusal-path, drift-detection, and override-audit invariants of
//! `pin_referenced_contracts` and the drift-detection signing-time helpers
//! under adversarial inputs — without a live testnet.
//!
//! # Coverage map
//!
//! | Fixture | Wire code / assertion |
//! |---------|-----------------------|
//! | [`verifier_mutable_admin_key_rejection`] | `sa.verifier_mutable` |
//! | [`policy_mutable_owner_key_rejection`] | `sa.policy_mutable` |
//! | [`verifier_wasm_drift_detection`] | `sa.verifier_hash_drift` + audit row |
//! | [`policy_wasm_drift_detection`] | `sa.policy_hash_drift` + audit row |
//! | [`verifier_drift_rpc_suppression`] | `network.rpc_divergence` (before drift) |
//! | [`drift_check_infra_failure_routes_to_unavailable`] | `failure:drift_check_unavailable` |
//! | [`pinned_hash_audit_log_tampering`] | `sa.audit_log` before pin extraction |
//! | [`verifier_wasm_not_in_allowlist`] | `sa.verifier_wasm_not_in_allowlist` |
//! | [`accept_mutable_verifier_override_audit_row`] | `SaMutableContractOverride` row emitted |
//!
//! # Test organisation
//!
//! Each test group is its own sub-module file under
//! `tests/smart-account-fixtures/adversarial/`.  This file includes them via
//! the `#[path]` attribute so Cargo discovers them through a single
//! `tests/wasm_pinning_adversarial_fixtures.rs` entry point.
//!
//! The drift-detection fixtures (`verifier_wasm_drift_detection`,
//! `policy_wasm_drift_detection`, `verifier_drift_rpc_suppression`) use
//! `pub(crate)` helpers exposed under `--features test-helpers` via
//! `managers::verifiers::test_helpers`.  They require:
//!
//! ```text
//! cargo test --features test-helpers --test wasm_pinning_adversarial_fixtures
//! ```
//!
//! The remaining fixtures run under default `cargo test`.
//!
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; adversarial fixtures assert invariants via panic-on-failure"
)]

// ── Shared RPC mock helpers ───────────────────────────────────────────────────

#[path = "smart-account-fixtures/adversarial/rpc_mock_helpers.rs"]
mod rpc_mock_helpers;

#[path = "smart-account-fixtures/adversarial/combined_rpc_responder.rs"]
mod combined_rpc_responder;

// ── Fixture sub-modules ───────────────────────────────────────────────────────

#[path = "smart-account-fixtures/adversarial/verifier_mutable_admin_key_rejection.rs"]
mod verifier_mutable_admin_key_rejection;

#[path = "smart-account-fixtures/adversarial/policy_mutable_owner_key_rejection.rs"]
mod policy_mutable_owner_key_rejection;

#[path = "smart-account-fixtures/adversarial/verifier_wasm_drift_detection.rs"]
mod verifier_wasm_drift_detection;

#[path = "smart-account-fixtures/adversarial/policy_wasm_drift_detection.rs"]
mod policy_wasm_drift_detection;

#[path = "smart-account-fixtures/adversarial/verifier_drift_rpc_suppression.rs"]
mod verifier_drift_rpc_suppression;

#[path = "smart-account-fixtures/adversarial/drift_check_infra_failure_routes_to_unavailable.rs"]
mod drift_check_infra_failure_routes_to_unavailable;

#[path = "smart-account-fixtures/adversarial/pinned_hash_audit_log_tampering.rs"]
mod pinned_hash_audit_log_tampering;

#[path = "smart-account-fixtures/adversarial/verifier_wasm_not_in_allowlist.rs"]
mod verifier_wasm_not_in_allowlist;

#[path = "smart-account-fixtures/adversarial/accept_mutable_verifier_override_audit_row.rs"]
mod accept_mutable_verifier_override_audit_row;

#[test]
fn warn_if_test_helpers_feature_disabled() {
    #[cfg(not(feature = "test-helpers"))]
    eprintln!(
        "NOTE: drift-detection fixtures require --features test-helpers. Run: \
         cargo test --features test-helpers --test wasm_pinning_adversarial_fixtures"
    );
}
