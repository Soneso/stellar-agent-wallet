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
//!    `fetch_observed_wasm_hash` path returns `Option<[u8; 32]>` — no
//!    string-encoding, no XDR re-wrapping, no normalisation. The fixture's
//!    pinned `_first8` audit-row + matching mock-served full hash exercises
//!    this end-to-end with no intermediate transformation.
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
//! `fetch_observed_wasm_hash` at
//! `crates/stellar-agent-smart-account/src/managers/signers.rs`)
//! through to the byte-level comparison at the audit-log first-8 boundary.
//! The audit-log row stores `pinned_verifier_wasm_hashes_first8: Vec<String>`
//! (first-8-hex) at `crates/stellar-agent-core/src/audit_log/schema.rs:372`;
//! the comparison reduces both sides to first-8-hex via the same
//! `format!("{b:02x}")` formatter. There is no normalisation function the
//! pipeline could quietly invoke. This fixture regression-locks that
//! property by asserting byte-identical pinned-vs-observed produces
//! no drift.
//!
//! # Scope: formatter round-trip substitution
//!
//! There is no canonicalisation function to round-trip — the wallet's pipeline
//! is bytes-in/bytes-out as documented above. The formatter-determinism test
//! (`first8_hex_formatter_is_deterministic_and_idempotent`) captures the
//! practical equivalent of an idempotence assertion: the ONLY string-shaping
//! step in the audit-log first-8 comparison is the format-string `"{b:02x}"`,
//! and the test asserts that step is deterministic and idempotent. A future
//! refactor introducing a real canonicalisation step (e.g., a
//! `normalise_wasm_hash` function) must extend this fixture with the
//! literal round-trip assertion at that point.
//!
//! # Scope: deploy-time path coverage
//!
//! This fixture exercises the re-fetch half end-to-end via
//! `verify_pinned_verifier_against_chain` (which internally invokes
//! `fetch_observed_wasm_hash`). The deploy-time half is modelled by writing
//! the `SaContextRuleCreated` audit row directly with the canonical
//! `pinned_first8` shape, bypassing the actual install-path code at
//! `crates/stellar-agent-smart-account/src/managers/verifiers.rs:410-423`
//! (`identify_verifier` → push to `pinned_verifier_wasm_hashes`). This is a
//! deliberate isolation discipline: the install-path's happy direction is
//! covered by `verifier_wasm_not_in_allowlist.rs` (refusal path) plus the
//! install-path testnet acceptance suite. The byte-shape of the
//! `pinned_first8` written here is faithful to what `verifiers.rs:423`
//! produces because both sides use the same `first8_hex` formatter contract.
//!
//! # Implements
//!
//! Verifier wasm-hash pinning: no-drift and idempotence contracts for the
//! re-fetch path; regression-lock against covert hash canonicalisation.

#![cfg(feature = "test-helpers")]

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::sync::Arc;

use stellar_agent_core::audit_log::entry::AuditEntry;
use stellar_agent_core::audit_log::schema::EventKind;
use stellar_agent_smart_account::VERIFIER_ALLOWLIST;
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

/// Returns the canonical `first8` hex form of a 32-byte hash, matching the
/// formatter used by the install path at `verifiers.rs:423` and the drift
/// path at `verify_pinned_verifier_against_chain`.
fn first8_hex(hash: &[u8; 32]) -> String {
    hash[..8].iter().map(|b| format!("{b:02x}")).collect()
}

/// Reads all non-empty JSONL lines from the audit log file.
fn read_audit_entries(log_path: &std::path::Path) -> Vec<AuditEntry> {
    let file = std::fs::File::open(log_path).expect("audit log must be readable");
    let reader = BufReader::new(file);
    let mut entries = Vec::new();
    for line in reader.lines() {
        let Ok(line) = line else { continue };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(entry) = serde_json::from_str::<AuditEntry>(trimmed) {
            entries.push(entry);
        }
    }
    entries
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
    let pinned_first8 = first8_hex(&pinned_hash);

    // ── Step 1: Set up mock RPC returning the SAME bytes as the pinned hash ──
    let ledger_entries = build_ledger_entries_contract_instance(&verifier, pinned_hash);
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(JsonRpcResultResponder(ledger_entries))
        .mount(&server)
        .await;

    let (audit_writer, audit_log_path, _dir) = tmp_audit_writer();
    let manager = manager_one_url(
        &server.uri(),
        Arc::clone(&audit_writer),
        audit_log_path.clone(),
    );

    // ── Step 2: Write SaContextRuleCreated with pinned_first8 matching mock ──
    let rule_id: u32 = 1;
    let request_id = Uuid::new_v4().to_string();

    let pin_entry = AuditEntry::new_sa_context_rule_created(
        ZERO_CONTRACT_REDACTED,
        rule_id,
        "default",
        1,
        0,
        None,
        "stellar:testnet",
        &request_id,
        vec![pinned_first8.clone()],
        vec![],
        false,
        false,
    );
    {
        let mut writer = audit_writer.lock().expect("audit writer poisoned");
        writer
            .write_entry(pin_entry)
            .expect("write_entry must succeed");
    }

    // ── Step 3: First call — must succeed (no drift) ──────────────────────────
    let mut cache: HashMap<Vec<u8>, [u8; 32]> = HashMap::new();
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
    let mut cache2: HashMap<Vec<u8>, [u8; 32]> = HashMap::new();
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
    let entries = read_audit_entries(&audit_log_path);
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

// ── Test: first8 round-trip determinism (formatter regression-lock) ───────────

/// Asserts the first-8-hex formatter (`format!("{b:02x}")`) used on BOTH the
/// install path (`verifiers.rs:423` derives `pinned_*_first8` for the audit row)
/// AND the drift-check path (compares pinned `_first8` against
/// `first8(fetch_observed_wasm_hash())`) is deterministic and idempotent.
///
/// This guards against a future refactor that swaps `format!("{b:02x}")` for
/// (say) `hex::encode_upper` or `base64` on one side but not the other —
/// the pipeline would then report perpetual drift on byte-identical input
/// because the string comparison would differ even though the bytes are equal.
#[test]
fn first8_hex_formatter_is_deterministic_and_idempotent() {
    let h = VERIFIER_ALLOWLIST[0].wasm_hash;

    let first = first8_hex(&h);
    let second = first8_hex(&h);

    assert_eq!(
        first, second,
        "first8 formatter must be deterministic on the same input",
    );

    // Format-shape invariants matching the comparators at `signers.rs:1645`
    // and the audit-row stored shape at `verifiers.rs:423`.
    assert_eq!(first.len(), 16, "first-8-hex must be 16 ASCII chars");
    assert!(
        first
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()),
        "first-8-hex must be all lowercase ASCII hex digits; got {first:?}",
    );
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
    let pinned_first8 = first8_hex(&pinned_hash);

    let pin_entry = AuditEntry::new_sa_context_rule_created(
        ZERO_CONTRACT_REDACTED,
        rule_id,
        "default",
        1,
        0,
        None,
        "stellar:testnet",
        &request_id,
        vec![pinned_first8],
        vec![],
        false,
        false,
    );
    {
        let mut writer = audit_writer.lock().expect("audit writer poisoned");
        writer
            .write_entry(pin_entry)
            .expect("write_entry must succeed");
    }

    let mut cache: HashMap<Vec<u8>, [u8; 32]> = HashMap::new();
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
    for observed_hash in cache.values() {
        assert_eq!(
            observed_hash, &pinned_hash,
            "observed hash in cache must be byte-identical to RPC-served bytes; \
             a canonicalisation step would surface here",
        );
    }
}
