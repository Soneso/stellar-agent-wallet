//! Adversarial fixture: `wasm_hash_canonicalisation_parity`.
//!
//! Regression-locks the no-covert-canonicalisation invariant: at install time
//! the wallet pins the verifier wasm-hash; the FIRST subsequent re-fetch (for
//! drift check or migration planning) MUST byte-match the pinned value with no
//! covert canonicalisation step. A bug that off-by-ones the hash format but
//! matches itself on re-fetch would silently pass the
//! `verifier_wasm_drift_detection` fixture because the drift check would compare
//! "normalised" against "normalised" and find them identical.
//!
//! # What this fixture proves
//!
//! 1. **No-drift contract under byte-identical re-fetch.** If the mock RPC
//!    returns exactly the bytes that were pinned at install, the drift check
//!    must succeed (no `SaError::VerifierHashDrift`). This is the positive
//!    counterpart of `verifier_wasm_drift_detection.rs` and verifies the same
//!    code path produces the correct verdict in BOTH directions.
//! 2. **Idempotence of the re-fetch path.** Calling
//!    `verify_pinned_verifier_against_chain` twice with identical mock state
//!    must produce identical verdicts (both `Ok(_)`). A non-idempotent
//!    canonicalisation (e.g., a "normalisation" that re-keys on each call)
//!    would break this.
//! 3. **Bytes-in == bytes-out at the on-chain fetch boundary.** The
//!    `fetch_observed_executable` path returns the `[u8; 32]` inside
//!    `ObservedExecutable::Wasm`: no
//!    string-encoding, no XDR re-wrapping, no normalisation. The fixture's
//!    full-hash audit row and matching mock-served hash exercise this
//!    end-to-end with no intermediate transformation.
//!
//! # Why this is materially different from `verifier_wasm_drift_detection`
//!
//! `verifier_wasm_drift_detection` exercises the DRIFT-DETECTED path: pinned
//! sentinel `0101…` vs mock-served `67800690…`. That fixture passes if the
//! pipeline ALWAYS returns drift; it would also pass under a hypothetical
//! canonicalisation bug that maps every input to a constant sentinel.
//!
//! `wasm_hash_canonicalisation_parity` (this fixture) exercises the
//! NO-DRIFT path: pinned `67800690…` vs mock-served `67800690…`. It would
//! fail under that same canonicalisation bug because the pipeline would
//! report drift when in fact bytes are identical. The two fixtures together
//! lock both directions of the contract.
//!
//! # Canonicalisation pipeline absence (negative regression-lock)
//!
//! The wallet's wasm-hash pipeline has NO canonicalisation step: bytes flow as
//! `[u8; 32]` from `stellar_agent_network::fetch_contract_wasm_hash` (called inside
//! `fetch_observed_executable` at
//! `crates/stellar-agent-smart-account/src/managers/signers.rs`)
//! through to the comparison with the pin, which compares all 32 bytes.
//! The audit row stores `pinned_verifier_wasm_hashes: Vec<WasmHashPin>`,
//! whose wire form is 64 lowercase hex characters and whose parser refuses
//! every other form. There is no normalisation function the pipeline could
//! quietly invoke. This fixture regression-locks that property by asserting
//! byte-identical pinned-vs-observed produces no drift.
//!
//! # Scope: wire-form round trip
//!
//! The only string-shaping step is the pin's wire form. The round-trip test
//! (`wasm_hash_pin_wire_form_is_deterministic_and_round_trips`) asserts that
//! step is deterministic, lowercase, 64 characters long and parses back to
//! the same 32 bytes.
//!
//! # Scope: deploy-time path coverage
//!
//! This fixture exercises the re-fetch half end-to-end via
//! `verify_pinned_verifier_against_chain` (which internally invokes
//! `fetch_observed_executable`). The deploy-time half is modelled by writing
//! the `SaContextRuleCreatedV2` audit row directly with the full pinned
//! hash, bypassing the install-path code. This is a deliberate isolation
//! discipline: the install-path's happy direction is covered by
//! `verifier_wasm_not_in_allowlist.rs` (refusal path) plus the install-path
//! testnet acceptance suite.
//!
//! # Implements
//!
//! Verifier wasm-hash pinning: no-drift and idempotence contracts for the
//! re-fetch path; regression-lock against covert hash canonicalisation.

#![cfg(feature = "test-helpers")]

use std::collections::HashMap;
use std::sync::Arc;

use stellar_agent_core::audit_log::entry::AuditEntry;
use stellar_agent_core::audit_log::schema::{EventKind, WasmHashPin};
use stellar_agent_core::audit_log::test_helpers::verified_audit_entries;
use stellar_agent_smart_account::VERIFIER_ALLOWLIST;
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

// ── Test: byte-identical no-drift contract + idempotence ──────────────────────

/// When the mock RPC returns the same wasm-hash bytes that were pinned at
/// install time, `verify_pinned_verifier_against_chain` MUST succeed (no
/// drift), AND a second call against the same mock state MUST produce the
/// same verdict (idempotence).
///
/// Together with `verifier_wasm_drift_detection.rs` (drift-detected path),
/// this locks both directions of the verifier-wasm drift contract and
/// regression-locks against a hypothetical canonicalisation bug that
/// off-by-ones the hash format identically on both sides.
#[tokio::test]
async fn wasm_hash_canonicalisation_parity_byte_identical_no_drift_and_idempotent() {
    let verifier = verifier_addr();
    let pinned_hash = VERIFIER_ALLOWLIST[0].wasm_hash;

    // ── Step 1: Set up mock RPC returning the SAME bytes as the pinned hash ──
    let ledger_entries = build_ledger_entries_contract_instance(&verifier, pinned_hash);
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(JsonRpcResultResponder(ledger_entries))
        .mount(&server)
        .await;

    let (audit_writer, audit_log_path, _dir) = tmp_audit_writer();
    let manager = manager_one_url(&server.uri(), Arc::clone(&audit_writer), audit_log_path);

    // ── Step 2: Write SaContextRuleCreatedV2 pinning the mock-served hash ────
    let rule_id: u32 = 1;
    let request_id = Uuid::new_v4().to_string();

    let pin_entry = AuditEntry::new_sa_context_rule_created_v2(
        ZERO_CONTRACT_REDACTED,
        rule_id,
        "default",
        1,
        0,
        None,
        "stellar:testnet",
        &request_id,
        vec![WasmHashPin::new(pinned_hash)],
        vec![],
        false,
        false,
        vec![],
        vec![],
    );
    {
        let mut writer = audit_writer.lock().expect("audit writer poisoned");
        writer
            .write_entry(pin_entry)
            .expect("write_entry must succeed");
    }

    // ── Step 3: First call — must succeed (no drift) ──────────────────────────
    let mut cache: HashMap<Vec<u8>, ObservedExecutable> = HashMap::new();
    let first_result = test_helpers::verify_pinned_verifier_against_chain(
        &manager,
        verifier.clone(),
        rule_id,
        ZERO_CONTRACT_REDACTED,
        &request_id,
        &mut cache,
    )
    .await;

    assert!(
        first_result.is_ok(),
        "byte-identical pinned-vs-observed must NOT report drift; got: {first_result:?}",
    );

    // ── Step 4: Second call (idempotence) — also must succeed ─────────────────
    let mut cache2: HashMap<Vec<u8>, ObservedExecutable> = HashMap::new();
    let second_result = test_helpers::verify_pinned_verifier_against_chain(
        &manager,
        verifier.clone(),
        rule_id,
        ZERO_CONTRACT_REDACTED,
        &request_id,
        &mut cache2,
    )
    .await;

    assert!(
        second_result.is_ok(),
        "second drift-check against identical mock state must also succeed; \
         non-idempotent canonicalisation would surface here. got: {second_result:?}",
    );

    // ── Step 5: No SaVerifierHashDrift audit row must have been emitted ───────
    let entries = verified_audit_entries(&audit_writer);
    let drift_rows: Vec<_> = entries
        .iter()
        .filter(|e| {
            matches!(
                &e.event_kind,
                EventKind::SaVerifierHashDrift { rule_id: rid, .. } if *rid == rule_id
            )
        })
        .collect();
    assert!(
        drift_rows.is_empty(),
        "no SaVerifierHashDrift row may be emitted on byte-identical re-fetch; \
         got {} row(s)",
        drift_rows.len(),
    );
}

// ── Test: pin wire-form determinism (formatter regression-lock) ───────────────

/// Asserts the pin's wire form, used by the audit row the install writes
/// and the record the drift check reads, is deterministic, 64 lowercase hex
/// characters, and parses back to the same 32 bytes.
///
/// This guards against a refactor that swaps the encoding (for example to
/// uppercase hex or base64) on one side: the reader refuses any other form,
/// so a record written in another form does not read.
#[test]
fn wasm_hash_pin_wire_form_is_deterministic_and_round_trips() {
    let h = VERIFIER_ALLOWLIST[0].wasm_hash;

    let first = WasmHashPin::new(h).to_hex();
    let second = WasmHashPin::new(h).to_hex();

    assert_eq!(
        first, second,
        "the wire form must be deterministic on the same input",
    );
    assert_eq!(first.len(), 64, "the wire form must be 64 ASCII chars");
    assert!(
        first
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()),
        "the wire form must be all lowercase ASCII hex digits; got {first:?}",
    );
    assert_eq!(WasmHashPin::parse(&first).unwrap().as_bytes(), &h);
}

// ── Test: pinned bytes survive end-to-end without transformation ──────────────

/// Constructs an `ObservedSignerSet`-adjacent pipeline: pin a hash via the
/// audit row, then run the drift check. Asserts the cache map populated by
/// the drift-check path carries the EXACT bytes returned by the mock RPC,
/// not a normalised form.
#[tokio::test]
async fn wasm_hash_cache_carries_bytes_unmodified_from_rpc() {
    let verifier = verifier_addr();
    let pinned_hash = VERIFIER_ALLOWLIST[0].wasm_hash;

    let ledger_entries = build_ledger_entries_contract_instance(&verifier, pinned_hash);
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(JsonRpcResultResponder(ledger_entries))
        .mount(&server)
        .await;

    let (audit_writer, audit_log_path, _dir) = tmp_audit_writer();
    let manager = manager_one_url(&server.uri(), Arc::clone(&audit_writer), audit_log_path);

    let rule_id: u32 = 7;
    let request_id = Uuid::new_v4().to_string();

    let pin_entry = AuditEntry::new_sa_context_rule_created_v2(
        ZERO_CONTRACT_REDACTED,
        rule_id,
        "default",
        1,
        0,
        None,
        "stellar:testnet",
        &request_id,
        vec![WasmHashPin::new(pinned_hash)],
        vec![],
        false,
        false,
        vec![],
        vec![],
    );
    {
        let mut writer = audit_writer.lock().expect("audit writer poisoned");
        writer
            .write_entry(pin_entry)
            .expect("write_entry must succeed");
    }

    let mut cache: HashMap<Vec<u8>, ObservedExecutable> = HashMap::new();
    test_helpers::verify_pinned_verifier_against_chain(
        &manager,
        verifier.clone(),
        rule_id,
        ZERO_CONTRACT_REDACTED,
        &request_id,
        &mut cache,
    )
    .await
    .expect("byte-identical pinned-vs-observed must succeed");

    // The cache map populated by the drift-check carries the verifier's
    // observed wasm hash, keyed by the contract address bytes. Assert any
    // value present is byte-identical to the bytes the mock RPC served.
    assert_eq!(
        cache.len(),
        1,
        "drift-check must populate the wasm-hash cache with exactly one entry; \
         empty or multi-entry cache means the bytes-in==bytes-out assertion below \
         is vacuous or ambiguous",
    );
    for observed in cache.values() {
        assert_eq!(
            observed,
            &ObservedExecutable::Wasm(pinned_hash),
            "observed hash in cache must be byte-identical to RPC-served bytes; \
             a canonicalisation step would surface here",
        );
    }
}
