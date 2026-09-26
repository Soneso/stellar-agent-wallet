//! Adversarial fixture: `external_ref_install_pinning`.
//!
//! Scenario: a verifier or policy contract's executable is a CAP-85 external
//! reference whose owner's tag entry resolves to a hash. The owner can repoint
//! the tag at any time, so the contract is owner-mutable code.
//! `pin_referenced_contracts` MUST:
//!
//! - refuse it without `accept_mutable_verifier` with `sa.verifier_mutable` /
//!   `sa.policy_mutable`, reason `owner-managed external reference`, and a
//!   detail naming the owner and the tag, writing no override row;
//! - admit it with `accept_mutable_verifier`, write a
//!   `SaMutableContractOverride` row naming the owner and the tag, and pin the
//!   resolved hash together with an `ExecutableRefPin` at the same position;
//! - require `accept_unknown_verifier` as well when the resolved hash is
//!   outside the allowlist, writing both override rows;
//! - refuse with `sa.contract_instance_unsupported`, reason
//!   `executable changed during install`, when the mutability probe observes a
//!   different executable than identification.

use std::io::{BufRead, BufReader};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use stellar_agent_core::audit_log::AuditReader;
use stellar_agent_core::audit_log::entry::AuditEntry;
use stellar_agent_core::audit_log::schema::{ContractKind, EventKind, ExecutableRefPin};
use stellar_agent_smart_account::VERIFIER_ALLOWLIST;
use stellar_agent_smart_account::error::{AdminOrOwnerKey, SaError};
use stellar_agent_smart_account::managers::rules::RuleContext;
use stellar_agent_smart_account::managers::rules::{
    ContextRuleDefinition, ContextRulePolicy, ContextRuleSignerInput,
};
use stellar_agent_smart_account::managers::verifiers::{PinResult, pin_referenced_contracts};
use stellar_agent_test_support::{KeyedLedgerEntriesResponder, xdr_fixtures};
use stellar_xdr::{AccountId, ContractId, Hash, PublicKey, ScAddress, ScString, ScVal, Uint256};
use uuid::Uuid;
use wiremock::{Request, Respond, ResponseTemplate};

use super::rpc_mock_helpers::{
    KNOWN_WASM_HASH, SOURCE_G, ZERO_CONTRACT_REDACTED, contract_instance_key_xdr, manager_one_url,
    tmp_audit_writer,
};

// ── Fixture values ────────────────────────────────────────────────────────────

/// Executable owner: the all-zero ed25519 account.
const OWNER: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
const OWNER_REDACTED: &str = "GAAAA...AAWHF";
const TAG: &[u8] = b"verifier-v1";

/// Referenced contract address (`[0x61; 32]`).
fn contract_addr() -> ScAddress {
    ScAddress::Contract(ContractId(Hash([0x61u8; 32])))
}

/// Smart-account address (`[0x62; 32]`).
fn smart_account_addr() -> ScAddress {
    ScAddress::Contract(ContractId(Hash([0x62u8; 32])))
}

fn owner_scaddress() -> ScAddress {
    ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
        [0u8; 32],
    ))))
}

fn contract_strkey() -> String {
    stellar_agent_core::sc_address::scaddress_to_strkey(&contract_addr()).expect("contract strkey")
}

fn first8(hash: &[u8; 32]) -> String {
    hash[..8].iter().map(|b| format!("{b:02x}")).collect()
}

/// The hash the allowlist of `kind` accepts.
fn allowlisted_hash(kind: ContractKind) -> [u8; 32] {
    if kind == ContractKind::Policy {
        KNOWN_WASM_HASH
    } else {
        VERIFIER_ALLOWLIST[0].wasm_hash
    }
}

// ── Responders ────────────────────────────────────────────────────────────────

/// Serves an external-reference instance naming `OWNER` / `tag`, and the
/// owner's tag entry holding `resolved`.
fn external_ref_responder(tag: &[u8], resolved: [u8; 32]) -> KeyedLedgerEntriesResponder {
    KeyedLedgerEntriesResponder::new()
        .with_entry(xdr_fixtures::ledger_entry_from_response_json(
            &xdr_fixtures::external_ref_instance_ledger_entries_json(
                &contract_strkey(),
                OWNER,
                tag,
            ),
        ))
        .with_entry(xdr_fixtures::ledger_entry_from_response_json(
            &xdr_fixtures::executable_tag_ledger_entries_json(OWNER, tag, resolved),
        ))
}

/// Serves `before` for the first `switch_after` requests that ask for the
/// contract-instance key and `after` for every later one, so identification
/// (two instance requests, one per endpoint) and the mutability probe (two
/// more) observe different instances.
struct SwitchingResponder {
    before: KeyedLedgerEntriesResponder,
    after: KeyedLedgerEntriesResponder,
    instance_key: String,
    switch_after: usize,
    instance_requests: AtomicUsize,
}

impl Respond for SwitchingResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let asks_for_instance = serde_json::from_slice::<serde_json::Value>(&request.body)
            .ok()
            .and_then(|body| body["params"]["keys"].as_array().cloned())
            .is_some_and(|keys| keys.iter().any(|k| k.as_str() == Some(&self.instance_key)));
        let served_before = if asks_for_instance {
            self.instance_requests.fetch_add(1, Ordering::SeqCst) < self.switch_after
        } else {
            self.instance_requests.load(Ordering::SeqCst) <= self.switch_after
        };
        if served_before {
            self.before.respond(request)
        } else {
            self.after.respond(request)
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn definition_for(kind: ContractKind) -> ContextRuleDefinition {
    let contract = contract_addr();
    let (signers, policies) = if kind == ContractKind::Policy {
        (
            vec![ContextRuleSignerInput::Delegated {
                address: ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
                    [0x11u8; 32],
                )))),
            }],
            vec![ContextRulePolicy::new(contract, ScVal::Void)],
        )
    } else {
        (
            vec![ContextRuleSignerInput::External {
                verifier: contract,
                pubkey_data: vec![0xbbu8; 32],
            }],
            vec![],
        )
    };
    ContextRuleDefinition::new(
        RuleContext::Default,
        "external-ref-install".to_owned(),
        None,
        signers,
        policies,
    )
}

fn read_audit_entries(log_path: &std::path::Path) -> Vec<AuditEntry> {
    let Ok(file) = std::fs::File::open(log_path) else {
        return Vec::new();
    };
    BufReader::new(file)
        .lines()
        .map(|line| line.expect("audit log line must be readable"))
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<AuditEntry>(line.trim()).expect("audit row must parse"))
        .collect()
}

fn count_rows(entries: &[AuditEntry], pred: impl Fn(&EventKind) -> bool) -> usize {
    entries.iter().filter(|e| pred(&e.event_kind)).count()
}

fn is_mutable_override(kind: &EventKind) -> bool {
    matches!(kind, EventKind::SaMutableContractOverride { .. })
}

fn is_unknown_override(kind: &EventKind) -> bool {
    matches!(kind, EventKind::SaUnknownContractOverride { .. })
}

fn is_rule_created(kind: &EventKind) -> bool {
    matches!(kind, EventKind::SaContextRuleCreated { .. })
}

/// Runs `pin_referenced_contracts` for one contract of `kind` against
/// `responder`, returning the result and the audit rows written.
async fn pin_with<R: Respond + 'static>(
    responder: R,
    kind: ContractKind,
    accept_mutable_verifier: bool,
    accept_unknown_verifier: bool,
) -> (Result<PinResult, SaError>, Vec<AuditEntry>) {
    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .respond_with(responder)
        .mount(&server)
        .await;
    let (audit_writer, audit_log_path, _dir) = tmp_audit_writer();
    let manager = manager_one_url(
        &server.uri(),
        Arc::clone(&audit_writer),
        audit_log_path.clone(),
    );
    let result = pin_referenced_contracts(
        &manager,
        Some(&audit_writer),
        smart_account_addr(),
        ZERO_CONTRACT_REDACTED,
        &definition_for(kind),
        0,
        SOURCE_G,
        accept_mutable_verifier,
        accept_unknown_verifier,
        "stellar:testnet",
        Uuid::new_v4().to_string(),
    )
    .await;
    (result, read_audit_entries(&audit_log_path))
}

fn expected_pin(tag: &[u8], resolved: [u8; 32]) -> ExecutableRefPin {
    ExecutableRefPin::new(
        &owner_scaddress(),
        &ScString(tag.to_vec().try_into().expect("tag fits")),
        &resolved,
    )
    .expect("pin builds")
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Without `accept_mutable_verifier`, an external reference whose resolved
/// hash is allowlisted is refused as mutable with a detail naming the owner
/// and the tag, and no audit row of any pin kind is written.
#[tokio::test]
async fn external_ref_refused_without_accept_mutable_verifier() {
    for kind in [ContractKind::Verifier, ContractKind::Policy] {
        let (result, entries) = pin_with(
            external_ref_responder(TAG, allowlisted_hash(kind)),
            kind,
            false,
            false,
        )
        .await;

        let error = result.expect_err(&format!("{kind}: must refuse"));
        let expected_detail = format!("owner {OWNER_REDACTED}, tag \"verifier-v1\"");
        let (key, detail) = match (&error, kind) {
            (
                SaError::VerifierMutable {
                    admin_or_owner_key,
                    detail,
                    ..
                },
                ContractKind::Verifier,
            )
            | (
                SaError::PolicyMutable {
                    admin_or_owner_key,
                    detail,
                    ..
                },
                ContractKind::Policy,
            ) => (*admin_or_owner_key, detail.clone()),
            _ => panic!("{kind}: expected the mutable refusal; got {error:?}"),
        };
        assert_eq!(key, AdminOrOwnerKey::ExternalRefExecutable, "{kind}");
        assert_eq!(detail.as_deref(), Some(expected_detail.as_str()), "{kind}");
        let message = error.to_string();
        assert!(
            message.contains("owner-managed external reference")
                && message.contains(&expected_detail),
            "{kind}: {message}"
        );

        assert_eq!(count_rows(&entries, is_mutable_override), 0, "{kind}");
        assert_eq!(count_rows(&entries, is_unknown_override), 0, "{kind}");
        assert_eq!(count_rows(&entries, is_rule_created), 0, "{kind}");
    }
}

/// With `accept_mutable_verifier`, the external reference installs: the
/// override row names the owner and the tag, the pin carries the resolved
/// hash and an `ExecutableRefPin` at the same position, and the created row
/// built from the pin records both and reads back through the audit reader.
#[tokio::test]
async fn external_ref_installs_with_accept_mutable_verifier() {
    for kind in [ContractKind::Verifier, ContractKind::Policy] {
        let resolved = allowlisted_hash(kind);
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .respond_with(external_ref_responder(TAG, resolved))
            .mount(&server)
            .await;
        let (audit_writer, audit_log_path, _dir) = tmp_audit_writer();
        let manager = manager_one_url(
            &server.uri(),
            Arc::clone(&audit_writer),
            audit_log_path.clone(),
        );
        let definition = definition_for(kind);
        let request_id = Uuid::new_v4().to_string();

        let pin_result = pin_referenced_contracts(
            &manager,
            Some(&audit_writer),
            smart_account_addr(),
            ZERO_CONTRACT_REDACTED,
            &definition,
            0,
            SOURCE_G,
            true,
            false,
            "stellar:testnet",
            request_id.clone(),
        )
        .await
        .unwrap_or_else(|e| panic!("{kind}: install must succeed with the flag: {e}"));

        assert!(pin_result.mutable_override, "{kind}");
        assert!(!pin_result.unknown_override, "{kind}");
        let pin = expected_pin(TAG, resolved);
        assert_eq!(pin.owner_redacted.as_str(), OWNER_REDACTED);
        assert_eq!(pin.tag, "verifier-v1");
        let (hashes, refs) = if kind == ContractKind::Policy {
            (
                &pin_result.pinned_policy_wasm_hashes,
                &pin_result.pinned_policy_executable_refs,
            )
        } else {
            (
                &pin_result.pinned_verifier_wasm_hashes,
                &pin_result.pinned_verifier_executable_refs,
            )
        };
        assert_eq!(hashes, &vec![(contract_addr(), resolved)], "{kind}");
        assert_eq!(refs, &vec![Some(pin.clone())], "{kind}");

        let entries = read_audit_entries(&audit_log_path);
        assert_eq!(count_rows(&entries, is_unknown_override), 0, "{kind}");
        let overrides: Vec<&AuditEntry> = entries
            .iter()
            .filter(|e| is_mutable_override(&e.event_kind))
            .collect();
        assert_eq!(overrides.len(), 1, "{kind}");
        let EventKind::SaMutableContractOverride {
            contract_kind,
            executable_owner_redacted,
            executable_tag,
            ..
        } = &overrides[0].event_kind
        else {
            unreachable!("filtered on SaMutableContractOverride");
        };
        assert_eq!(*contract_kind, kind);
        assert_eq!(
            executable_owner_redacted.as_ref().map(|o| o.as_str()),
            Some(OWNER_REDACTED),
            "{kind}"
        );
        assert_eq!(executable_tag.as_deref(), Some("verifier-v1"), "{kind}");
        assert_eq!(overrides[0].request_id, request_id, "{kind}");

        // The created row records the resolved first-8 and the pin at the
        // same position, and the reader returns them.
        let created = pin_result.context_rule_created_entry(
            ZERO_CONTRACT_REDACTED,
            4,
            &definition,
            "stellar:testnet",
            &request_id,
        );
        let EventKind::SaContextRuleCreated {
            pinned_verifier_wasm_hashes_first8,
            pinned_policy_wasm_hashes_first8,
            pinned_verifier_executable_refs,
            pinned_policy_executable_refs,
            mutable_override,
            ..
        } = &created.event_kind
        else {
            panic!("{kind}: expected SaContextRuleCreated");
        };
        assert!(*mutable_override, "{kind}");
        let (created_first8, created_refs, other_refs) = if kind == ContractKind::Policy {
            (
                pinned_policy_wasm_hashes_first8,
                pinned_policy_executable_refs,
                pinned_verifier_executable_refs,
            )
        } else {
            (
                pinned_verifier_wasm_hashes_first8,
                pinned_verifier_executable_refs,
                pinned_policy_executable_refs,
            )
        };
        assert_eq!(created_first8, &vec![first8(&resolved)], "{kind}");
        assert_eq!(created_refs, &vec![Some(pin.clone())], "{kind}");
        assert!(other_refs.is_empty(), "{kind}");

        audit_writer
            .lock()
            .expect("audit writer")
            .write_entry(created)
            .expect("created row writes");
        let record = AuditReader::new(Arc::clone(&audit_writer), None)
            .find_latest_context_rule_pinned_hashes(4, ZERO_CONTRACT_REDACTED)
            .expect("reader succeeds")
            .expect("created row found");
        let read_back = if kind == ContractKind::Policy {
            record.policy_executable_ref(0)
        } else {
            record.verifier_executable_ref(0)
        };
        assert_eq!(read_back, Some(&pin), "{kind}");
    }
}

/// A resolved hash outside the allowlist needs both flags: each flag alone
/// refuses, and both together install and write both override rows.
#[tokio::test]
async fn external_ref_outside_allowlist_needs_both_flags() {
    let unknown = [0xd1u8; 32];
    for kind in [ContractKind::Verifier, ContractKind::Policy] {
        // Only the mutable flag: the allowlist miss refuses first.
        let (result, entries) =
            pin_with(external_ref_responder(TAG, unknown), kind, true, false).await;
        let error = result.expect_err(&format!("{kind}: allowlist miss must refuse"));
        assert!(
            matches!(
                (&error, kind),
                (SaError::VerifierWasmNotInAllowlist { observed_hash_first8, .. }, ContractKind::Verifier)
                | (SaError::PolicyWasmNotInAllowlist { observed_hash_first8, .. }, ContractKind::Policy)
                    if observed_hash_first8 == "d1d1d1d1d1d1d1d1"
            ),
            "{kind}: {error:?}"
        );
        assert_eq!(count_rows(&entries, is_unknown_override), 0, "{kind}");
        assert_eq!(count_rows(&entries, is_mutable_override), 0, "{kind}");

        // Only the unknown flag: the unknown row is written, then the
        // reference is refused as mutable.
        let (result, entries) =
            pin_with(external_ref_responder(TAG, unknown), kind, false, true).await;
        let error = result.expect_err(&format!("{kind}: mutable must refuse"));
        assert!(
            matches!(
                (&error, kind),
                (
                    SaError::VerifierMutable {
                        admin_or_owner_key: AdminOrOwnerKey::ExternalRefExecutable,
                        ..
                    },
                    ContractKind::Verifier
                ) | (
                    SaError::PolicyMutable {
                        admin_or_owner_key: AdminOrOwnerKey::ExternalRefExecutable,
                        ..
                    },
                    ContractKind::Policy
                )
            ),
            "{kind}: {error:?}"
        );
        assert_eq!(count_rows(&entries, is_unknown_override), 1, "{kind}");
        assert_eq!(count_rows(&entries, is_mutable_override), 0, "{kind}");

        // Both flags: installs, with both rows and the pin.
        let (result, entries) =
            pin_with(external_ref_responder(TAG, unknown), kind, true, true).await;
        let pin_result = result.unwrap_or_else(|e| panic!("{kind}: both flags install: {e}"));
        assert!(
            pin_result.mutable_override && pin_result.unknown_override,
            "{kind}"
        );
        let refs = if kind == ContractKind::Policy {
            &pin_result.pinned_policy_executable_refs
        } else {
            &pin_result.pinned_verifier_executable_refs
        };
        assert_eq!(refs, &vec![Some(expected_pin(TAG, unknown))], "{kind}");
        assert!(
            entries.iter().any(|e| matches!(
                &e.event_kind,
                EventKind::SaUnknownContractOverride { observed_hash_first8, contract_kind, .. }
                    if observed_hash_first8 == "d1d1d1d1d1d1d1d1" && *contract_kind == kind
            )),
            "{kind}: unknown override row"
        );
        assert_eq!(count_rows(&entries, is_mutable_override), 1, "{kind}");
    }
}

/// A mutability probe that observes a different executable than
/// identification is refused with `ExecutableChanged` whatever the flags: a
/// different external reference, a reference replacing a Wasm executable,
/// and a Wasm executable replacing a reference.
#[tokio::test]
async fn probe_observing_a_different_executable_is_refused_as_executable_changed() {
    for kind in [ContractKind::Verifier, ContractKind::Policy] {
        let allowlisted = allowlisted_hash(kind);
        let wasm_responder = || {
            KeyedLedgerEntriesResponder::new().with_entry(
                xdr_fixtures::ledger_entry_from_response_json(
                    &xdr_fixtures::contract_instance_ledger_entries_json(
                        &contract_strkey(),
                        allowlisted,
                    ),
                ),
            )
        };
        for (case, before, after) in [
            (
                "different tag",
                external_ref_responder(TAG, allowlisted),
                external_ref_responder(b"verifier-v2", allowlisted),
            ),
            (
                "wasm became a reference",
                wasm_responder(),
                external_ref_responder(TAG, allowlisted),
            ),
            (
                "reference became wasm",
                external_ref_responder(TAG, allowlisted),
                wasm_responder(),
            ),
        ] {
            let responder = SwitchingResponder {
                before,
                after,
                instance_key: contract_instance_key_xdr(&contract_addr()),
                switch_after: 2,
                instance_requests: AtomicUsize::new(0),
            };
            let (result, entries) = pin_with(responder, kind, true, true).await;
            let error = result.expect_err(&format!("{kind}, {case}: must refuse"));
            assert!(
                matches!(
                    &error,
                    SaError::ContractInstanceUnsupported {
                        reason: AdminOrOwnerKey::ExecutableChanged,
                        contract_kind,
                        ..
                    } if *contract_kind == kind
                ),
                "{kind}, {case}: {error:?}"
            );
            assert!(
                error
                    .to_string()
                    .contains("executable changed during install"),
                "{kind}, {case}: {error}"
            );
            assert_eq!(
                count_rows(&entries, is_mutable_override),
                0,
                "{kind}, {case}: no mutable override row"
            );
        }
    }
}
