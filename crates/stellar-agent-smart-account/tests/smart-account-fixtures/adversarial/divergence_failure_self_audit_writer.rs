//! Adversarial fixture: divergence-failure self-audit-writer fallback.
//!
//! Scenario: every context-rule write path is called with `audit_writer: None`
//! (the production CLI pattern) while the manager has a shared
//! `self.audit_writer`. The auth rule's version-1 state row records one
//! signer and the chain holds two, so the submit path's signer-set
//! comparison refuses before any signing or submission. The comparison
//! writes the `SaSignerSetDiverged` row through the signers manager's writer,
//! then the write path writes its `SaRawInvocation(PreSubmissionRefused)` row
//! through the shared writer, both with the call's original `request_id`.
//!
//! The submit path reads the rule from the primary for its pin check first
//! (the rule has no pin record, so the check reads nothing else), then
//! reads the rule and the threshold from each endpoint for the comparison.
//! The canned simulations follow that order.
//!
//! # Invariant
//!
//! Signer-set divergence detected before any write operation causes an
//! immediate refusal, the diverged row, then a
//! `SaRawInvocation(PreSubmissionRefused)` audit row carrying the original
//! `request_id`. No signing or submission occurs.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use stellar_agent_core::audit_log::entry::AuditEntry;
use stellar_agent_core::audit_log::schema::{EventKind, SaInvocationResult};
use stellar_agent_core::smart_account::rule_id::ContextRuleId;
use stellar_agent_network::signing::{Signer, SoftwareSigningKey};
use stellar_agent_smart_account::error::SaError;
use stellar_agent_smart_account::managers::rules::RuleContext;
use stellar_agent_smart_account::managers::rules::{
    ContextRuleDefinition, ContextRuleManager, ContextRuleManagerConfig, ContextRuleSignerInput,
    parse_g_strkey_to_signer_address,
};
use stellar_xdr::ScAddress;
use uuid::Uuid;
use wiremock::{
    Mock, MockServer,
    matchers::{method, path},
};

use super::combined_rpc_responder::{CombinedRpcResponder, SequencedSimulate};
use super::rpc_mock_helpers::{
    KNOWN_WASM_HASH, ZERO_CONTRACT_REDACTED, build_context_rule_scval_xdr, build_simulate_response,
    build_threshold_scval_xdr, manager_two_url, policy_sc_address, signer_set_n_of_n,
    tmp_audit_writer, write_baseline, zero_sc_address,
};

const NETWORK_PASSPHRASE: &str = "Test SDF Network ; September 2015";
const CHAIN_ID: &str = "stellar:testnet";
const RULE_ID: u32 = 1;

struct DivergenceFixture {
    manager: ContextRuleManager,
    signer: Box<dyn Signer + Send + Sync>,
    signer_address: ScAddress,
    smart_account: ScAddress,
    audit_log_path: PathBuf,
    _dir: tempfile::TempDir,
    primary_server: MockServer,
    secondary_server: MockServer,
}

impl DivergenceFixture {
    /// The `sendTransaction` requests both endpoints received.
    async fn sends(&self) -> usize {
        let mut sends = 0;
        for server in [&self.primary_server, &self.secondary_server] {
            sends += server
                .received_requests()
                .await
                .unwrap_or_default()
                .iter()
                .filter(|request| {
                    serde_json::from_slice::<serde_json::Value>(&request.body)
                        .is_ok_and(|body| body["method"] == "sendTransaction")
                })
                .count();
        }
        sends
    }
}

async fn build_fixture() -> DivergenceFixture {
    let (audit_writer, audit_log_path, dir) = tmp_audit_writer();
    write_baseline(
        &audit_writer,
        RULE_ID,
        ZERO_CONTRACT_REDACTED,
        &signer_set_n_of_n(1),
    );

    let signer = SoftwareSigningKey::new_from_bytes([0x29; 32]);
    let signer_g = signer
        .public_key()
        .await
        .expect("fixture signer public key must derive")
        .to_string();
    let signer_address =
        parse_g_strkey_to_signer_address(&signer_g).expect("fixture signer G-strkey must parse");

    let policy = policy_sc_address();
    let on_chain = signer_set_n_of_n(2);
    let cr_xdr = build_context_rule_scval_xdr(RULE_ID, &on_chain, std::slice::from_ref(&policy));
    let th_xdr = build_threshold_scval_xdr(2);
    let sim_cr = build_simulate_response(&cr_xdr);
    let sim_th = build_simulate_response(&th_xdr);

    let primary_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(CombinedRpcResponder::new(
            &signer_g,
            &policy,
            KNOWN_WASM_HASH,
            // The pin check's rule read, then the comparison's rule and
            // threshold reads.
            SequencedSimulate::new(vec![sim_cr.clone(), sim_cr.clone(), sim_th.clone()]),
        ))
        .mount(&primary_server)
        .await;

    let secondary_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(CombinedRpcResponder::new(
            &signer_g,
            &policy,
            KNOWN_WASM_HASH,
            SequencedSimulate::new(vec![sim_cr, sim_th]),
        ))
        .mount(&secondary_server)
        .await;

    let signers_manager = Arc::new(manager_two_url(
        &primary_server.uri(),
        &secondary_server.uri(),
        Arc::clone(&audit_writer),
        audit_log_path.clone(),
    ));
    let manager = ContextRuleManager::new(
        ContextRuleManagerConfig::new(
            primary_server.uri(),
            NETWORK_PASSPHRASE.to_owned(),
            Duration::from_secs(5),
            CHAIN_ID.to_owned(),
        )
        .with_signers_manager(signers_manager)
        .with_audit_writer(audit_writer),
    )
    .expect("ContextRuleManager::new must succeed");

    DivergenceFixture {
        manager,
        signer: Box::new(signer),
        signer_address,
        smart_account: zero_sc_address(),
        audit_log_path,
        _dir: dir,
        primary_server,
        secondary_server,
    }
}

fn rule_definition(signer_address: ScAddress) -> ContextRuleDefinition {
    ContextRuleDefinition::new(
        RuleContext::Default,
        "divergence-fixture".to_owned(),
        None,
        vec![ContextRuleSignerInput::Delegated {
            address: signer_address,
        }],
        vec![],
    )
}

fn auth_rule_ids() -> Vec<ContextRuleId> {
    vec![ContextRuleId::new(RULE_ID)]
}

/// The serialized kind of `entry`'s event.
fn row_kind(entry: &AuditEntry) -> String {
    serde_json::to_value(&entry.event_kind).expect("an event kind serializes")["kind"]
        .as_str()
        .expect("an event kind carries its kind")
        .to_owned()
}

fn read_audit_entries(log_path: &Path) -> Vec<AuditEntry> {
    let content = std::fs::read_to_string(log_path).expect("audit log JSONL must be readable");
    content
        .lines()
        .filter_map(|line| serde_json::from_str::<AuditEntry>(line).ok())
        .collect()
}

/// Asserts the refusal's rows: the diverged row, then exactly one
/// `SaRawInvocation(PreSubmissionRefused)` row with the divergence code, each
/// carrying `request_id`; and that nothing was sent.
async fn assert_divergence_rows(fixture: &DivergenceFixture, request_id: &str, op: &str) {
    let entries = read_audit_entries(&fixture.audit_log_path);
    let kinds: Vec<String> = entries
        .iter()
        .filter(|entry| entry.request_id == request_id)
        .map(row_kind)
        .collect();
    assert_eq!(
        kinds,
        ["sa_signer_set_diverged", "sa_raw_invocation"],
        "{op}: the diverged row precedes the raw invocation row"
    );
    assert_eq!(fixture.sends().await, 0, "{op}: nothing is sent");
    assert_divergence_raw_row(&fixture.audit_log_path, request_id, op);
}

fn assert_divergence_raw_row(log_path: &Path, request_id: &str, op: &str) {
    let entries = read_audit_entries(log_path);
    let raw_rows: Vec<&AuditEntry> = entries
        .iter()
        .filter(|entry| {
            matches!(
                &entry.event_kind,
                EventKind::SaRawInvocation {
                    wire_code,
                    result: SaInvocationResult::PreSubmissionRefused,
                    ..
                } if wire_code == "sa.signer_set_diverged"
            )
        })
        .collect();

    assert_eq!(
        raw_rows.len(),
        1,
        "{op}: exactly one SaRawInvocation(PreSubmissionRefused) divergence row must be emitted"
    );
    assert_eq!(
        raw_rows[0].request_id, request_id,
        "{op}: divergence failure audit row must carry the call request_id"
    );
    assert_eq!(
        raw_rows[0].chain_id.as_deref(),
        Some(CHAIN_ID),
        "{op}: divergence failure audit row must carry chain_id={CHAIN_ID}"
    );
}

/// `install_rule` must emit the divergence failure via `self.audit_writer`.
///
/// Divergence is refused before signing/submission and the failure row
/// preserves the call request ID.
#[tokio::test]
async fn install_rule_divergence_failure_emits_via_self_audit_writer() {
    let fixture = build_fixture().await;
    let request_id = Uuid::new_v4().to_string();

    let result = fixture
        .manager
        .install_rule(
            fixture.smart_account.clone(),
            rule_definition(fixture.signer_address.clone()),
            auth_rule_ids(),
            fixture.signer.as_ref(),
            None,
            request_id.clone(),
            false,
            false,
        )
        .await;

    assert!(
        matches!(
            result,
            Err(SaError::SignerSetDiverged {
                rule_id: RULE_ID,
                ..
            })
        ),
        "install_rule must return SignerSetDiverged; got {result:?}"
    );
    assert_divergence_rows(&fixture, &request_id, "install_rule").await;
}

/// `delete_rule` must emit the divergence failure via `self.audit_writer`.
///
/// Divergence is refused before signing/submission and the failure row
/// preserves the call request ID.
#[tokio::test]
async fn delete_rule_divergence_failure_emits_via_self_audit_writer() {
    let fixture = build_fixture().await;
    let request_id = Uuid::new_v4().to_string();

    let result = fixture
        .manager
        .delete_rule(
            fixture.smart_account.clone(),
            7,
            auth_rule_ids(),
            fixture.signer.as_ref(),
            None,
            request_id.clone(),
        )
        .await;

    assert!(
        matches!(
            result,
            Err(SaError::SignerSetDiverged {
                rule_id: RULE_ID,
                ..
            })
        ),
        "delete_rule must return SignerSetDiverged; got {result:?}"
    );
    assert_divergence_rows(&fixture, &request_id, "delete_rule").await;
}

/// `update_name` must emit the divergence failure via `self.audit_writer`.
///
/// Divergence is refused before signing/submission and the failure row
/// preserves the call request ID.
#[tokio::test]
async fn update_name_divergence_failure_emits_via_self_audit_writer() {
    let fixture = build_fixture().await;
    let request_id = Uuid::new_v4().to_string();

    let result = fixture
        .manager
        .update_name(
            fixture.smart_account.clone(),
            7,
            "renamed".to_owned(),
            auth_rule_ids(),
            fixture.signer.as_ref(),
            None,
            request_id.clone(),
        )
        .await;

    assert!(
        matches!(
            result,
            Err(SaError::SignerSetDiverged {
                rule_id: RULE_ID,
                ..
            })
        ),
        "update_name must return SignerSetDiverged; got {result:?}"
    );
    assert_divergence_rows(&fixture, &request_id, "update_name").await;
}

/// `update_valid_until` must emit the divergence failure via `self.audit_writer`.
///
/// Divergence is refused before signing/submission and the failure row
/// preserves the call request ID.
#[tokio::test]
async fn update_valid_until_divergence_failure_emits_via_self_audit_writer() {
    let fixture = build_fixture().await;
    let request_id = Uuid::new_v4().to_string();

    let result = fixture
        .manager
        .update_valid_until(
            fixture.smart_account.clone(),
            7,
            Some(123_456),
            auth_rule_ids(),
            fixture.signer.as_ref(),
            None,
            request_id.clone(),
        )
        .await;

    assert!(
        matches!(
            result,
            Err(SaError::SignerSetDiverged {
                rule_id: RULE_ID,
                ..
            })
        ),
        "update_valid_until must return SignerSetDiverged; got {result:?}"
    );
    assert_divergence_rows(&fixture, &request_id, "update_valid_until").await;
}
