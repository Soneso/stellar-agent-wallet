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
//! | [`contract_instance_unsupported_rejection`] | `sa.contract_instance_unsupported` |
//! | [`verifier_wasm_drift_detection`] | `sa.verifier_hash_drift` + audit row |
//! | [`policy_wasm_drift_detection`] | `sa.policy_hash_drift` + audit row |
//! | [`verifier_drift_rpc_suppression`] | `network.rpc_divergence` (before drift) |
//! | [`drift_check_infra_failure_routes_to_unavailable`] | `failure:drift_check_unavailable` |
//! | [`pinned_hash_audit_log_tampering`] | `sa.audit_log` before pin extraction |
//! | [`verifier_wasm_not_in_allowlist`] | `sa.verifier_wasm_not_in_allowlist` |
//! | [`accept_mutable_verifier_override_audit_row`] | pending mutable override, no row written while pinning |
//! | [`external_ref_install_pinning`] | external reference: `sa.verifier_mutable` / `sa.policy_mutable`, pending overrides, `ExecutableRefPin`, `executable changed during install` |
//! | [`external_ref_drift_detection`] | external reference drift by kind, reference and hash |
//! | [`passkey_signing_malformed_pin_record`] | malformed pin record: `failure:drift_check_unavailable` with the integrity source |
//! | [`passkey_signing_check_order`] | missing baseline before a drifted verifier; `baseline_read` elapse wrapped as `failure:signer_set_diverged` |
//!
//! # Test organisation
//!
//! Each test group is its own sub-module file under
//! `tests/smart-account-fixtures/adversarial/`.  This file includes them via
//! the `#[path]` attribute so Cargo discovers them through a single
//! `tests/smart_account/wasm_pinning_adversarial_fixtures.rs` entry point.
//!
//! The drift-detection fixtures (`verifier_wasm_drift_detection`,
//! `policy_wasm_drift_detection`, `verifier_drift_rpc_suppression`,
//! `external_ref_drift_detection`) use
//! `pub(crate)` helpers exposed under `--features test-helpers` via
//! `managers::verifiers::test_helpers`.  They require:
//!
//! ```text
//! cargo test --features test-helpers --test smart_account wasm_pinning_adversarial_fixtures
//! ```
//!
//! The remaining fixtures run under default `cargo test`.
//!
//! A fixture that opens its audit writer through `tmp_audit_writer` also
//! holds its own marked `STELLAR_AGENT_HOME`, so it passes alone in a fresh
//! process. It runs under `#[serial]`, which the home guard requires.
//!
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; adversarial fixtures assert invariants via panic-on-failure"
)]

// ── Shared RPC mock helpers ───────────────────────────────────────────────────

/// The shared RPC mock helpers, with `tmp_audit_writer` resolving to
/// `isolated_audit_writer`: every fixture that opens its audit writer also
/// holds its own marked `STELLAR_AGENT_HOME` and runs under `#[serial]`.
mod rpc_mock_helpers {
    pub(super) use crate::rpc_mock_helpers::isolated_audit_writer as tmp_audit_writer;
    pub(super) use crate::rpc_mock_helpers::*;
}

/// A fixture outside the `#[serial]` lock is refused before it sets
/// `STELLAR_AGENT_HOME`.
#[test]
#[serial_test::parallel]
#[should_panic(expected = "an isolated wallet home requires the #[serial] lock")]
fn an_audit_writer_outside_the_serial_lock_is_refused() {
    let _audit = rpc_mock_helpers::tmp_audit_writer();
}

use crate::combined_rpc_responder;

// ── Fixture sub-modules ───────────────────────────────────────────────────────

#[path = "../smart-account-fixtures/adversarial/verifier_mutable_admin_key_rejection.rs"]
mod verifier_mutable_admin_key_rejection;

#[path = "../smart-account-fixtures/adversarial/policy_mutable_owner_key_rejection.rs"]
mod policy_mutable_owner_key_rejection;

#[path = "../smart-account-fixtures/adversarial/contract_instance_unsupported_rejection.rs"]
mod contract_instance_unsupported_rejection;

#[path = "../smart-account-fixtures/adversarial/verifier_wasm_drift_detection.rs"]
mod verifier_wasm_drift_detection;

#[path = "../smart-account-fixtures/adversarial/policy_wasm_drift_detection.rs"]
mod policy_wasm_drift_detection;

#[path = "../smart-account-fixtures/adversarial/verifier_drift_rpc_suppression.rs"]
mod verifier_drift_rpc_suppression;

#[path = "../smart-account-fixtures/adversarial/drift_check_infra_failure_routes_to_unavailable.rs"]
mod drift_check_infra_failure_routes_to_unavailable;

#[path = "../smart-account-fixtures/adversarial/pinned_hash_audit_log_tampering.rs"]
mod pinned_hash_audit_log_tampering;

#[path = "../smart-account-fixtures/adversarial/verifier_wasm_not_in_allowlist.rs"]
mod verifier_wasm_not_in_allowlist;

#[path = "../smart-account-fixtures/adversarial/accept_mutable_verifier_override_audit_row.rs"]
mod accept_mutable_verifier_override_audit_row;

#[path = "../smart-account-fixtures/adversarial/external_ref_install_pinning.rs"]
mod external_ref_install_pinning;

#[path = "../smart-account-fixtures/adversarial/external_ref_drift_detection.rs"]
mod external_ref_drift_detection;

#[path = "../smart-account-fixtures/adversarial/passkey_signing_malformed_pin_record.rs"]
mod passkey_signing_malformed_pin_record;

#[path = "../smart-account-fixtures/adversarial/passkey_signing_check_order.rs"]
mod passkey_signing_check_order;

#[test]
fn warn_if_test_helpers_feature_disabled() {
    #[cfg(not(feature = "test-helpers"))]
    eprintln!(
        "NOTE: drift-detection fixtures require --features test-helpers. Run: \
         cargo test --features test-helpers --test smart_account wasm_pinning_adversarial_fixtures"
    );
}

#[path = "../smart-account-fixtures/adversarial/passkey_signing_revoked_verifier.rs"]
mod passkey_signing_revoked_verifier;
