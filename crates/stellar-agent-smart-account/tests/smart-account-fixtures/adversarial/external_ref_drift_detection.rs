//! Adversarial fixture: `external_ref_drift_detection`.
//!
//! Scenario: a rule pins a verifier or policy. At signing time the drift
//! check compares the live executable against the pin by kind, by reference
//! and by hash. With an external-reference pin the live executable must be
//! the pinned reference resolving to the pinned hash; without one, a live
//! external reference is drift whatever it resolves to.
//!
//! Every drift case MUST return `sa.verifier_hash_drift` /
//! `sa.policy_hash_drift` with `observed_executable` describing the live
//! executable, and write the matching drift row.

#![cfg(feature = "test-helpers")]

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::sync::Arc;

use stellar_agent_core::audit_log::entry::AuditEntry;
use stellar_agent_core::audit_log::schema::{EventKind, ExecutableRefPin};
use stellar_agent_smart_account::VERIFIER_ALLOWLIST;
use stellar_agent_smart_account::error::SaError;
use stellar_agent_smart_account::managers::signers::ObservedExecutable;
use stellar_agent_smart_account::managers::verifiers::test_helpers;
use stellar_agent_test_support::{KeyedLedgerEntriesResponder, xdr_fixtures};
use stellar_xdr::{AccountId, ContractId, Hash, PublicKey, ScAddress, ScString, Uint256};
use uuid::Uuid;

use super::rpc_mock_helpers::{
    KNOWN_WASM_HASH, SOURCE_G, ZERO_CONTRACT_REDACTED, account_entry_xdr, account_key_xdr,
    build_context_rule_external_signers_xdr, build_context_rule_scval_xdr, build_simulate_response,
    manager_one_url, signer_set_n_of_n, tmp_audit_writer,
};

// ── Fixture values ────────────────────────────────────────────────────────────

const OWNER: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
const TAG: &[u8] = b"verifier-v1";
const RULE_ID: u32 = 3;

/// Pinned contract address (`[0x71; 32]`).
fn contract_addr() -> ScAddress {
    ScAddress::Contract(ContractId(Hash([0x71u8; 32])))
}

fn contract_strkey() -> String {
    stellar_agent_core::sc_address::scaddress_to_strkey(&contract_addr()).expect("contract strkey")
}

fn owner_scaddress() -> ScAddress {
    ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
        [0u8; 32],
    ))))
}

fn first8(hash: &[u8; 32]) -> String {
    hash[..8].iter().map(|b| format!("{b:02x}")).collect()
}

fn pin_for(tag: &[u8], resolved: [u8; 32]) -> ExecutableRefPin {
    ExecutableRefPin::new(
        &owner_scaddress(),
        &ScString(tag.to_vec().try_into().expect("tag fits")),
        &resolved,
    )
    .expect("pin builds")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Verifier,
    Policy,
}

// ── Live-state responders ─────────────────────────────────────────────────────

fn external_ref_instance(tag: &[u8]) -> serde_json::Value {
    xdr_fixtures::ledger_entry_from_response_json(
        &xdr_fixtures::external_ref_instance_ledger_entries_json(&contract_strkey(), OWNER, tag),
    )
}

fn tag_entry(tag: &[u8], hash: [u8; 32]) -> serde_json::Value {
    xdr_fixtures::ledger_entry_from_response_json(
        &xdr_fixtures::executable_tag_ledger_entries_json(OWNER, tag, hash),
    )
}

fn live_reference(tag: &[u8], resolved: Option<[u8; 32]>) -> KeyedLedgerEntriesResponder {
    let responder = KeyedLedgerEntriesResponder::new().with_entry(external_ref_instance(tag));
    match resolved {
        Some(hash) => responder.with_entry(tag_entry(tag, hash)),
        None => responder,
    }
}

fn live_wasm(hash: [u8; 32]) -> KeyedLedgerEntriesResponder {
    KeyedLedgerEntriesResponder::new().with_entry(xdr_fixtures::ledger_entry_from_response_json(
        &xdr_fixtures::contract_instance_ledger_entries_json(&contract_strkey(), hash),
    ))
}

// ── Harness ───────────────────────────────────────────────────────────────────

fn read_audit_entries(log_path: &std::path::Path) -> Vec<AuditEntry> {
    let file = std::fs::File::open(log_path).expect("audit log must be readable");
    BufReader::new(file)
        .lines()
        .map(|line| line.expect("audit log line must be readable"))
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<AuditEntry>(line.trim()).expect("audit row must parse"))
        .collect()
}

/// Outcome of one drift check: the result, the drift rows written, and the
/// observation left in the per-call cache.
struct CheckOutcome {
    result: Result<(), SaError>,
    drift_rows: Vec<(String, String, Option<String>)>,
    cached: Option<ObservedExecutable>,
}

/// Pins `pinned_first8` (with `pinned_ref` at the same position) for a rule
/// of `kind`, serves `live`, and runs the signing-time drift check.
async fn check(
    kind: Kind,
    pinned_first8: String,
    pinned_ref: Option<ExecutableRefPin>,
    live: KeyedLedgerEntriesResponder,
) -> CheckOutcome {
    let server = live.serve().await;
    let (audit_writer, audit_log_path, _dir) = tmp_audit_writer();
    let manager = manager_one_url(
        &server.uri(),
        Arc::clone(&audit_writer),
        audit_log_path.clone(),
    );
    let request_id = Uuid::new_v4().to_string();
    let (verifier_first8, verifier_refs, policy_first8, policy_refs) = match kind {
        Kind::Verifier => (vec![pinned_first8], vec![pinned_ref], vec![], vec![]),
        Kind::Policy => (vec![], vec![], vec![pinned_first8], vec![pinned_ref]),
    };
    let created = AuditEntry::new_sa_context_rule_created(
        ZERO_CONTRACT_REDACTED,
        RULE_ID,
        "default",
        1,
        u32::from(kind == Kind::Policy),
        None,
        "stellar:testnet",
        &request_id,
        verifier_first8,
        policy_first8,
        true,
        false,
        verifier_refs,
        policy_refs,
    );
    audit_writer
        .lock()
        .expect("audit writer")
        .write_entry(created)
        .expect("created row writes");

    let mut cache: HashMap<Vec<u8>, ObservedExecutable> = HashMap::new();
    let result = match kind {
        Kind::Verifier => {
            test_helpers::verify_pinned_verifier_against_chain(
                &manager,
                contract_addr(),
                RULE_ID,
                ZERO_CONTRACT_REDACTED,
                &request_id,
                &mut cache,
            )
            .await
        }
        Kind::Policy => {
            test_helpers::verify_pinned_policy_against_chain(
                &manager,
                contract_addr(),
                RULE_ID,
                ZERO_CONTRACT_REDACTED,
                &request_id,
                &mut cache,
            )
            .await
        }
    };

    let drift_rows = read_audit_entries(&audit_log_path)
        .into_iter()
        .filter(|e| e.request_id == request_id)
        .filter_map(|e| match e.event_kind {
            EventKind::SaVerifierHashDrift {
                pinned_hash_first8,
                observed_hash_first8,
                observed_executable,
                ..
            } if kind == Kind::Verifier => Some((
                pinned_hash_first8,
                observed_hash_first8,
                observed_executable,
            )),
            EventKind::SaPolicyHashDrift {
                pinned_hash_first8,
                observed_hash_first8,
                observed_executable,
                ..
            } if kind == Kind::Policy => Some((
                pinned_hash_first8,
                observed_hash_first8,
                observed_executable,
            )),
            _ => None,
        })
        .collect();
    CheckOutcome {
        result,
        drift_rows,
        cached: cache.into_values().next(),
    }
}

/// Asserts that `outcome` is drift for `kind` with the given observed
/// first-8 and observed-executable summary, and that exactly one matching
/// drift row was written.
fn assert_drift(
    kind: Kind,
    case: &str,
    outcome: &CheckOutcome,
    pinned_first8: &str,
    observed_first8: &str,
    observed_executable: &str,
) {
    let (pinned, observed, executable, wire_code) = match (&outcome.result, kind) {
        (
            Err(SaError::VerifierHashDrift {
                pinned_hash_first8,
                observed_hash_first8,
                observed_executable,
                ..
            }),
            Kind::Verifier,
        ) => (
            pinned_hash_first8,
            observed_hash_first8,
            observed_executable,
            "sa.verifier_hash_drift",
        ),
        (
            Err(SaError::PolicyHashDrift {
                pinned_hash_first8,
                observed_hash_first8,
                observed_executable,
                ..
            }),
            Kind::Policy,
        ) => (
            pinned_hash_first8,
            observed_hash_first8,
            observed_executable,
            "sa.policy_hash_drift",
        ),
        (other, _) => panic!("{kind:?}, {case}: expected drift; got {other:?}"),
    };
    let error = outcome.result.as_ref().expect_err("drift");
    assert_eq!(error.wire_code(), wire_code, "{kind:?}, {case}");
    assert_eq!(pinned, pinned_first8, "{kind:?}, {case}");
    assert_eq!(observed, observed_first8, "{kind:?}, {case}");
    assert_eq!(
        executable.as_deref(),
        Some(observed_executable),
        "{kind:?}, {case}"
    );
    assert!(
        error.to_string().contains(observed_executable),
        "{kind:?}, {case}: Display names the observed executable: {error}"
    );
    assert_eq!(
        outcome.drift_rows,
        vec![(
            pinned_first8.to_owned(),
            observed_first8.to_owned(),
            Some(observed_executable.to_owned())
        )],
        "{kind:?}, {case}: one drift row with the same fields"
    );
}

fn resolved_hash(kind: Kind) -> [u8; 32] {
    match kind {
        Kind::Verifier => VERIFIER_ALLOWLIST[0].wasm_hash,
        Kind::Policy => KNOWN_WASM_HASH,
    }
}

fn reference_summary(tag: &str, resolved: &str) -> String {
    format!("external reference owner GAAAA...AAWHF tag \"{tag}\" resolved {resolved}")
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Signing proceeds while the owner's tag entry holds the pinned hash, and
/// the cache keeps the observed reference.
#[tokio::test]
async fn pinned_external_ref_matches_while_tag_holds_pinned_hash() {
    for kind in [Kind::Verifier, Kind::Policy] {
        let resolved = resolved_hash(kind);
        let outcome = check(
            kind,
            first8(&resolved),
            Some(pin_for(TAG, resolved)),
            live_reference(TAG, Some(resolved)),
        )
        .await;
        assert!(outcome.result.is_ok(), "{kind:?}: {:?}", outcome.result);
        assert!(outcome.drift_rows.is_empty(), "{kind:?}");
        assert!(
            matches!(
                &outcome.cached,
                Some(ObservedExecutable::ExternalRef(external)) if external.resolved == Some(resolved)
            ),
            "{kind:?}: {:?}",
            outcome.cached
        );
    }
}

/// The owner repointing the tag is drift naming the reference and the new
/// hash.
#[tokio::test]
async fn owner_repointing_the_tag_is_drift() {
    let repointed = [0xe7u8; 32];
    for kind in [Kind::Verifier, Kind::Policy] {
        let resolved = resolved_hash(kind);
        let outcome = check(
            kind,
            first8(&resolved),
            Some(pin_for(TAG, resolved)),
            live_reference(TAG, Some(repointed)),
        )
        .await;
        assert_drift(
            kind,
            "repointed tag",
            &outcome,
            &first8(&resolved),
            &first8(&repointed),
            &reference_summary("verifier-v1", &first8(&repointed)),
        );
    }
}

/// An instance converted to a Wasm executable whose hash equals the pinned
/// resolved hash is drift: the executable kind changed.
#[tokio::test]
async fn reference_converted_to_wasm_with_the_pinned_hash_is_drift() {
    for kind in [Kind::Verifier, Kind::Policy] {
        let resolved = resolved_hash(kind);
        let outcome = check(
            kind,
            first8(&resolved),
            Some(pin_for(TAG, resolved)),
            live_wasm(resolved),
        )
        .await;
        assert_drift(
            kind,
            "converted to wasm",
            &outcome,
            &first8(&resolved),
            &first8(&resolved),
            "wasm",
        );
    }
}

/// An expired tag entry is drift, reported as resolved `unset` with the zero
/// hash.
#[tokio::test]
async fn expired_tag_entry_is_drift() {
    for kind in [Kind::Verifier, Kind::Policy] {
        let resolved = resolved_hash(kind);
        let outcome = check(
            kind,
            first8(&resolved),
            Some(pin_for(TAG, resolved)),
            live_reference(TAG, None),
        )
        .await;
        assert_drift(
            kind,
            "expired tag entry",
            &outcome,
            &first8(&resolved),
            "0000000000000000",
            &reference_summary("verifier-v1", "unset"),
        );
    }
}

/// A different tag on the same owner resolving to the same hash is drift:
/// the reference changed.
#[tokio::test]
async fn different_tag_resolving_to_the_same_hash_is_drift() {
    for kind in [Kind::Verifier, Kind::Policy] {
        let resolved = resolved_hash(kind);
        let outcome = check(
            kind,
            first8(&resolved),
            Some(pin_for(TAG, resolved)),
            live_reference(b"verifier-v2", Some(resolved)),
        )
        .await;
        assert_drift(
            kind,
            "different tag",
            &outcome,
            &first8(&resolved),
            &first8(&resolved),
            &reference_summary("verifier-v2", &first8(&resolved)),
        );
    }
}

/// With a pinned Wasm contract, the instance becoming an external reference
/// that resolves to the pinned Wasm hash is drift.
#[tokio::test]
async fn pinned_wasm_becoming_a_reference_to_the_same_hash_is_drift() {
    for kind in [Kind::Verifier, Kind::Policy] {
        let pinned = resolved_hash(kind);
        // Control: the pinned Wasm executable itself matches.
        let outcome = check(kind, first8(&pinned), None, live_wasm(pinned)).await;
        assert!(outcome.result.is_ok(), "{kind:?}: {:?}", outcome.result);

        let outcome = check(
            kind,
            first8(&pinned),
            None,
            live_reference(TAG, Some(pinned)),
        )
        .await;
        assert_drift(
            kind,
            "wasm became a reference",
            &outcome,
            &first8(&pinned),
            &first8(&pinned),
            &reference_summary("verifier-v1", &first8(&pinned)),
        );
    }
}

/// With a zero pin (an absent contract admitted under the unknown-hash
/// override), an unresolved external reference is drift even though its
/// effective hash reads as the zero hash.
#[tokio::test]
async fn zero_pin_against_an_unresolved_reference_is_drift() {
    let zero = "0000000000000000";
    for kind in [Kind::Verifier, Kind::Policy] {
        // Control: the absent contract itself matches the zero pin.
        let outcome = check(
            kind,
            zero.to_owned(),
            None,
            KeyedLedgerEntriesResponder::new(),
        )
        .await;
        assert!(outcome.result.is_ok(), "{kind:?}: {:?}", outcome.result);

        let outcome = check(kind, zero.to_owned(), None, live_reference(TAG, None)).await;
        assert_drift(
            kind,
            "zero pin, unresolved reference",
            &outcome,
            zero,
            zero,
            &reference_summary("verifier-v1", "unset"),
        );
    }
}

// ── verify_rule_wasm_pins report ──────────────────────────────────────────────

/// Answers `simulateTransaction` with `simulate_result` and every other
/// request through `ledger`.
struct RuleAndLedgerResponder {
    ledger: KeyedLedgerEntriesResponder,
    simulate_result: serde_json::Value,
}

impl wiremock::Respond for RuleAndLedgerResponder {
    fn respond(&self, request: &wiremock::Request) -> wiremock::ResponseTemplate {
        let body: serde_json::Value =
            serde_json::from_slice(&request.body).unwrap_or(serde_json::json!({}));
        if body["method"] != "simulateTransaction" {
            return self.ledger.respond(request);
        }
        wiremock::ResponseTemplate::new(200)
            .set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": body.get("id").cloned().unwrap_or(serde_json::json!(1)),
                "result": self.simulate_result,
            }))
            .insert_header("content-type", "application/json")
    }
}

/// Runs `verify_rule_wasm_pins` for a rule of `kind` that references
/// `contract_addr()` and whose created row pins `pinned_first8` with
/// `pinned_ref`, against `live`.
async fn verify_pins_report(
    kind: Kind,
    pinned_first8: String,
    pinned_ref: Option<ExecutableRefPin>,
    live: KeyedLedgerEntriesResponder,
) -> stellar_agent_smart_account::managers::rules::VerifyPinsResult {
    use stellar_agent_smart_account::managers::rules::{
        ContextRuleManager, ContextRuleManagerConfig,
    };

    let rule_xdr = match kind {
        Kind::Verifier => {
            build_context_rule_external_signers_xdr(RULE_ID, &[0], &contract_addr(), &[0xbb; 32])
        }
        Kind::Policy => {
            build_context_rule_scval_xdr(RULE_ID, &signer_set_n_of_n(0), &[contract_addr()])
        }
    };
    let ledger = live.with_entry(serde_json::json!({
        "key": account_key_xdr(SOURCE_G),
        "xdr": account_entry_xdr(SOURCE_G, 100),
        "lastModifiedLedgerSeq": 100,
    }));
    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .respond_with(RuleAndLedgerResponder {
            ledger,
            simulate_result: build_simulate_response(&rule_xdr),
        })
        .mount(&server)
        .await;

    let (audit_writer, audit_log_path, _dir) = tmp_audit_writer();
    let (verifier_first8, verifier_refs, policy_first8, policy_refs) = match kind {
        Kind::Verifier => (vec![pinned_first8], vec![pinned_ref], vec![], vec![]),
        Kind::Policy => (vec![], vec![], vec![pinned_first8], vec![pinned_ref]),
    };
    audit_writer
        .lock()
        .expect("audit writer")
        .write_entry(AuditEntry::new_sa_context_rule_created(
            ZERO_CONTRACT_REDACTED,
            RULE_ID,
            "default",
            1,
            u32::from(kind == Kind::Policy),
            None,
            "stellar:testnet",
            "req-created",
            verifier_first8,
            policy_first8,
            true,
            false,
            verifier_refs,
            policy_refs,
        ))
        .expect("created row writes");

    let signers_manager = Arc::new(manager_one_url(
        &server.uri(),
        Arc::clone(&audit_writer),
        audit_log_path,
    ));
    let manager = ContextRuleManager::new(
        ContextRuleManagerConfig::new(
            server.uri(),
            "Test SDF Network ; September 2015".to_owned(),
            std::time::Duration::from_secs(5),
            "stellar:testnet".to_owned(),
        )
        .with_signers_manager(signers_manager)
        .with_audit_writer(audit_writer),
    )
    .expect("ContextRuleManager::new");

    manager
        .verify_rule_wasm_pins(
            ScAddress::Contract(ContractId(Hash([0u8; 32]))),
            RULE_ID,
            Some(SOURCE_G),
            "req-verify-pins",
        )
        .await
        .expect("verify_rule_wasm_pins returns a report")
}

/// A rule pinned to an external reference reports the pin and the observed
/// reference summary, aligned with the first-8 lists, for a verifier and for
/// a policy.
#[tokio::test]
async fn verify_pins_reports_the_pinned_and_observed_external_reference() {
    use stellar_agent_smart_account::managers::rules::PinStatus;

    for kind in [Kind::Verifier, Kind::Policy] {
        let resolved = if kind == Kind::Policy {
            KNOWN_WASM_HASH
        } else {
            VERIFIER_ALLOWLIST[0].wasm_hash
        };
        let pin = pin_for(TAG, resolved);
        let report = verify_pins_report(
            kind,
            first8(&resolved),
            Some(pin.clone()),
            live_reference(TAG, Some(resolved)),
        )
        .await;

        let summary = format!(
            "external reference owner GAAAA...AAWHF tag \"verifier-v1\" resolved {}",
            first8(&resolved)
        );
        let (
            status,
            observed_first8,
            observed_executable,
            pinned_refs,
            other_executable,
            other_refs,
        ) = match kind {
            Kind::Verifier => (
                &report.verifier_pin_status,
                &report.observed_verifier_first8,
                &report.observed_verifier_executable,
                &report.pinned_verifier_executable_refs,
                &report.observed_policy_executable,
                &report.pinned_policy_executable_refs,
            ),
            Kind::Policy => (
                &report.policy_pin_status,
                &report.observed_policy_first8,
                &report.observed_policy_executable,
                &report.pinned_policy_executable_refs,
                &report.observed_verifier_executable,
                &report.pinned_verifier_executable_refs,
            ),
        };
        assert_eq!(*status, PinStatus::Match, "{kind:?}");
        assert_eq!(observed_first8, &vec![first8(&resolved)], "{kind:?}");
        assert_eq!(observed_executable, &vec![Some(summary)], "{kind:?}");
        assert_eq!(pinned_refs, &vec![Some(pin)], "{kind:?}");
        assert!(other_executable.is_empty(), "{kind:?}");
        assert!(other_refs.is_empty(), "{kind:?}");
    }
}

/// A reference pin against live Wasm code reports drift, the pin, and `None`
/// for the observed Wasm executable at the drifted position.
#[tokio::test]
async fn verify_pins_reports_live_wasm_against_a_reference_pin_as_none() {
    use stellar_agent_smart_account::managers::rules::PinStatus;

    let resolved = VERIFIER_ALLOWLIST[0].wasm_hash;
    let pin = pin_for(TAG, resolved);
    let report = verify_pins_report(
        Kind::Verifier,
        first8(&resolved),
        Some(pin.clone()),
        live_wasm(resolved),
    )
    .await;

    assert_eq!(report.verifier_pin_status, PinStatus::Drift);
    assert_eq!(report.observed_verifier_first8, vec![first8(&resolved)]);
    assert_eq!(report.observed_verifier_executable, vec![None]);
    assert_eq!(report.pinned_verifier_executable_refs, vec![Some(pin)]);
}
