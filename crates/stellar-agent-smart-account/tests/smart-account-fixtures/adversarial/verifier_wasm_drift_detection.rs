//! Adversarial fixture: `verifier_wasm_drift_detection`.
//!
//! Scenario: a rule was installed with a verifier whose wasm hash was pinned
//! at install time.  At signing time the mock RPC returns a different wasm
//! hash for that verifier (simulating an on-chain WASM upgrade).
//! `verify_pinned_verifier_against_chain` MUST return
//! `SaError::VerifierHashDrift` with `wire_code = "sa.verifier_hash_drift"`.
//!
//! # Design
//!
//! 1. Write a `SaContextRuleCreatedV2` audit entry whose
//!    `pinned_verifier_wasm_hashes` is `[[0x01; 32]]` (a sentinel that will
//!    not match the mock RPC's response).
//! 2. Mount a mock RPC that returns a contract instance with wasm hash
//!    `VERIFIER_ALLOWLIST[0].wasm_hash`, different from the pinned sentinel.
//! 3. Call `verify_pinned_verifier_against_chain` (exposed via
//!    `managers::verifiers::test_helpers` under `--features test-helpers`).
//! 4. Assert `SaError::VerifierHashDrift` is returned AND a `SaVerifierHashDrift`
//!    audit row is emitted with matching `request_id`.
//!
//! # Implements
//!
//! Verifier-pinning drift detection: on-chain WASM hash change at sign time must be caught,
//! including a hash that shares the pinned hash's first eight bytes.

#![cfg(feature = "test-helpers")]

use std::collections::HashMap;
use std::sync::Arc;

use stellar_agent_core::audit_log::entry::AuditEntry;
use stellar_agent_core::audit_log::schema::{EventKind, WasmHashPin};
use stellar_agent_core::audit_log::test_helpers::verified_audit_entries;
use stellar_agent_smart_account::VERIFIER_ALLOWLIST;
use stellar_agent_smart_account::error::SaError;
use stellar_agent_smart_account::managers::signers::ObservedExecutable;
use stellar_agent_smart_account::managers::verifiers::test_helpers;
use stellar_xdr::{ContractId, Hash, ScAddress};
use uuid::Uuid;
use wiremock::{
    Mock, MockServer,
    matchers::{method, path},
};

use super::combined_rpc_responder::JsonRpcResultResponder;
use super::rpc_mock_helpers::{
    ZERO_CONTRACT_REDACTED, build_ledger_entries_contract_instance, manager_one_url,
    tmp_audit_writer,
};

// ── Address helpers ───────────────────────────────────────────────────────────

/// Verifier contract address (`[0x20; 32]`).
fn verifier_addr() -> ScAddress {
    ScAddress::Contract(ContractId(Hash([0x20u8; 32])))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// When the pinned verifier wasm hash in the audit log does not match the live
/// on-chain hash returned by the mock RPC, `verify_pinned_verifier_against_chain`
/// returns `SaError::VerifierHashDrift` and emits a `SaVerifierHashDrift` audit row.
#[tokio::test]
async fn verifier_wasm_hash_drift_detected_and_audit_row_emitted() {
    let verifier = verifier_addr();

    // ── Step 1: Set up a mock RPC that serves VERIFIER_ALLOWLIST[0].wasm_hash ──
    let live_wasm_hash = VERIFIER_ALLOWLIST[0].wasm_hash;
    let ledger_entries = build_ledger_entries_contract_instance(&verifier, live_wasm_hash);

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(JsonRpcResultResponder(ledger_entries))
        .mount(&server)
        .await;

    let (audit_writer, audit_log_path, _dir) = tmp_audit_writer();
    let manager = manager_one_url(&server.uri(), Arc::clone(&audit_writer), audit_log_path);

    // ── Step 2: Write a fake SaContextRuleCreatedV2 row with a DIFFERENT pinned hash
    let fake_pinned = WasmHashPin::new([0x01; 32]);
    let rule_id: u32 = 1;
    let request_id = Uuid::new_v4().to_string();

    let fake_entry = AuditEntry::new_sa_context_rule_created_v2(
        ZERO_CONTRACT_REDACTED,
        rule_id,
        "default",
        1,
        0,
        None,
        "stellar:testnet",
        &request_id,
        vec![fake_pinned],
        vec![],
        false,
        false,
        vec![],
        vec![],
    );
    {
        let mut writer = audit_writer.lock().expect("audit writer poisoned");
        writer
            .write_entry(fake_entry)
            .expect("write_entry must succeed");
    }

    // ── Step 3: Call verify_pinned_verifier_against_chain ────────────────────
    let mut cache: HashMap<Vec<u8>, ObservedExecutable> = HashMap::new();

    let result = test_helpers::verify_pinned_verifier_against_chain(
        &manager,
        verifier.clone(),
        rule_id,
        ZERO_CONTRACT_REDACTED,
        &request_id,
        &mut cache,
    )
    .await;

    // ── Step 4: Assertions ────────────────────────────────────────────────────
    assert!(
        matches!(result, Err(SaError::VerifierHashDrift { .. })),
        "wasm-hash drift must return SaError::VerifierHashDrift; got: {result:?}"
    );
    assert_eq!(
        result.unwrap_err().wire_code(),
        "sa.verifier_hash_drift",
        "wire_code must be 'sa.verifier_hash_drift'"
    );

    // The SaVerifierHashDrift audit row must be emitted.
    let entries = verified_audit_entries(&audit_writer);
    let drift_row = entries.iter().find(|e| {
        matches!(
            &e.event_kind,
            EventKind::SaVerifierHashDrift { rule_id: rid, .. } if *rid == rule_id
        )
    });
    assert!(
        drift_row.is_some(),
        "SaVerifierHashDrift audit row must be emitted after drift detection"
    );

    // Verify the drift row carries the same request_id.
    let drift_entry = drift_row.unwrap();
    assert_eq!(
        drift_entry.request_id, request_id,
        "SaVerifierHashDrift row must carry the same request_id as the verify call"
    );
}

#[tokio::test]
async fn a_pinned_revoked_verifier_refuses_after_the_pin_matches() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(JsonRpcResultResponder(
            build_ledger_entries_contract_instance(&verifier_addr(), [0xee; 32]),
        ))
        .mount(&server)
        .await;
    let (audit, path, _dir) = tmp_audit_writer();
    let manager = manager_one_url(&server.uri(), Arc::clone(&audit), path);
    audit
        .lock()
        .unwrap()
        .write_entry(AuditEntry::new_sa_context_rule_created_v2(
            ZERO_CONTRACT_REDACTED,
            1,
            "default",
            1,
            0,
            None,
            "stellar:testnet",
            "revoked-pin",
            vec![WasmHashPin::new([0xee; 32])],
            vec![],
            false,
            false,
            vec![],
            vec![],
        ))
        .unwrap();
    let error = test_helpers::verify_pinned_verifier_against_chain(
        &manager,
        verifier_addr(),
        1,
        ZERO_CONTRACT_REDACTED,
        "revoked-pin",
        &mut HashMap::new(),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(
            error,
            SaError::VerifierWasmRevoked {
                rule_id: Some(1),
                ..
            }
        ),
        "{error:?}"
    );
    assert!(
        !verified_audit_entries(&audit)
            .iter()
            .any(|entry| matches!(entry.event_kind, EventKind::SaVerifierHashDrift { .. }))
    );
}

/// The pinned hash of the pin-width tests and a hash sharing its first eight
/// bytes that differs in every later byte.
fn pinned_and_twin() -> ([u8; 32], [u8; 32]) {
    let pinned = [0x42u8; 32];
    let mut twin = pinned;
    twin[8..].fill(0x43);
    (pinned, twin)
}

/// Serves `live` as the verifier's Wasm hash and pins `pinned` for rule 1
/// with the given override flags; returns the check's outcome and the audit
/// log's rows.
async fn check_against(
    pinned: [u8; 32],
    live: [u8; 32],
    overrides: bool,
) -> (
    Result<(), SaError>,
    Vec<stellar_agent_core::audit_log::entry::AuditEntry>,
) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(JsonRpcResultResponder(
            build_ledger_entries_contract_instance(&verifier_addr(), live),
        ))
        .mount(&server)
        .await;
    let (audit, path, _dir) = tmp_audit_writer();
    let manager = manager_one_url(&server.uri(), Arc::clone(&audit), path);
    audit
        .lock()
        .unwrap()
        .write_entry(AuditEntry::new_sa_context_rule_created_v2(
            ZERO_CONTRACT_REDACTED,
            1,
            "default",
            1,
            0,
            None,
            "stellar:testnet",
            "twin-pin",
            vec![WasmHashPin::new(pinned)],
            vec![],
            overrides,
            overrides,
            vec![],
            vec![],
        ))
        .unwrap();
    let outcome = test_helpers::verify_pinned_verifier_against_chain(
        &manager,
        verifier_addr(),
        1,
        ZERO_CONTRACT_REDACTED,
        "twin-pin",
        &mut HashMap::new(),
    )
    .await;
    (outcome, verified_audit_entries(&audit))
}

/// A live verifier whose hash shares the pinned hash's first eight bytes
/// and is in no allowlist refuses as drift, with and without both admission
/// overrides on the pin record, naming both full hashes and writing the
/// drift row. The exact pinned hash passes.
#[tokio::test]
async fn an_unlisted_equal_prefix_twin_refuses_as_drift_under_both_overrides() {
    let (pinned, twin) = pinned_and_twin();
    for overrides in [false, true] {
        let (outcome, rows) = check_against(pinned, twin, overrides).await;
        match outcome {
            Err(SaError::VerifierHashDrift {
                pinned_hash,
                observed_hash,
                ..
            }) => {
                assert_eq!(
                    pinned_hash,
                    WasmHashPin::new(pinned),
                    "overrides={overrides}"
                );
                assert_eq!(
                    observed_hash,
                    Some(WasmHashPin::new(twin)),
                    "overrides={overrides}"
                );
            }
            other => panic!("overrides={overrides}: expected VerifierHashDrift, got {other:?}"),
        }
        assert!(
            rows.iter()
                .any(|entry| matches!(entry.event_kind, EventKind::SaVerifierHashDrift { .. })),
            "overrides={overrides}: the drift row is written"
        );

        let (outcome, _) = check_against(pinned, pinned, overrides).await;
        assert!(outcome.is_ok(), "overrides={overrides}: {outcome:?}");
    }
}

/// A live twin of a pinned revoked verifier refuses as drift: the status of
/// the revoked hash is never assigned to a hash that only shares its prefix,
/// and the pin comparison refuses first.
#[tokio::test]
async fn a_twin_of_a_pinned_revoked_verifier_refuses_as_drift() {
    let revoked = [0xeeu8; 32];
    let mut twin = revoked;
    twin[8..].fill(0x43);
    let (outcome, _) = check_against(revoked, twin, false).await;
    assert!(
        matches!(outcome, Err(SaError::VerifierHashDrift { .. })),
        "{outcome:?}"
    );
}
