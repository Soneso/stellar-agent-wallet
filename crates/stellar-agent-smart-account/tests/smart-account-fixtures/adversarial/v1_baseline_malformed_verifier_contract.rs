//! Adversarial fixture: a version-1 signer-set state row whose `External`
//! signer names a malformed verifier contract.
//!
//! A version-1 row deserializes `verifier_contract` without validating it;
//! the comparison with the chain computes the row's digest and refuses the
//! address there. Both comparison entries, the signers manager's
//! `verify_signer_set_against_chain` and the passkey signing path, refuse
//! with the audit-log integrity error and hold no fragment of the address:
//! neither its first nor its last five characters reach the `Display` or
//! `Debug` of any error in the refusal's source chain.

use std::sync::Arc;

use stellar_agent_core::audit_log::signer_set::{
    ObservedSignerSet, SignerPubkey, SignerSetCanonicalBodyError,
};
use stellar_agent_core::audit_log::verify::VerifyError;
use stellar_agent_smart_account::error::SaError;
use stellar_agent_test_support::rejected_value::assert_no_marker;
use uuid::Uuid;
use wiremock::{
    Mock, MockServer,
    matchers::{method, path},
};

use super::combined_rpc_responder::{CombinedRpcResponder, SequencedSimulate};
use super::rpc_mock_helpers::{
    KNOWN_WASM_HASH, SOURCE_G, ZERO_CONTRACT_REDACTED, build_context_rule_scval_xdr,
    build_simulate_response, build_threshold_scval_xdr, manager_two_url, policy_sc_address,
    signer_set_n_of_n, tmp_audit_writer, write_baseline, zero_sc_address,
};

const RULE_ID: u32 = 1;

/// The leading five characters of [`malformed_verifier_contract`].
const LEADING_MARKER: &str = "CMRKQ";

/// The trailing five characters of [`malformed_verifier_contract`].
const TRAILING_MARKER: &str = "QMRKZ";

/// A C-prefixed 56-character address whose checksum does not hold.
fn malformed_verifier_contract() -> String {
    format!("{LEADING_MARKER}{}{TRAILING_MARKER}", "A".repeat(46))
}

/// A version-1 two-of-two state: an Ed25519 signer and an `External` signer
/// on the malformed verifier contract.
fn malformed_v1_state() -> ObservedSignerSet {
    ObservedSignerSet {
        signer_count: 2,
        threshold: 2,
        signer_ids: vec![0, 1],
        signer_pubkeys: vec![
            SignerPubkey::Ed25519 { pubkey: [0x10; 32] },
            SignerPubkey::External {
                verifier_contract: malformed_verifier_contract(),
                key_data_first16: [0x22; 16],
            },
        ],
    }
}

/// Asserts that `err` is the refusal of the row's verifier contract and that
/// no error in its source chain renders either marker.
fn assert_refused_without_fragments(err: &SaError) {
    assert!(
        matches!(
            err,
            SaError::AuditLog(VerifyError::SignerSetCanonicalBody(
                SignerSetCanonicalBodyError::InvalidVerifierContract { .. }
            ))
        ),
        "the row's verifier contract is refused: {err:?}"
    );
    assert_no_marker(err, LEADING_MARKER);
    assert_no_marker(err, TRAILING_MARKER);
}

/// One endpoint's responder: `simulations` in order, and the
/// simple-threshold policy's instance for every ledger-entry read.
fn two_of_two_responder(simulations: Vec<serde_json::Value>) -> CombinedRpcResponder {
    CombinedRpcResponder::new(
        SOURCE_G,
        &policy_sc_address(),
        KNOWN_WASM_HASH,
        SequencedSimulate::new(simulations),
    )
}

/// The simulate responses of one endpoint's observation: the rule read,
/// then the threshold read.
fn observation_simulations() -> Vec<serde_json::Value> {
    let policy = policy_sc_address();
    let rule = build_simulate_response(&build_context_rule_scval_xdr(
        RULE_ID,
        &signer_set_n_of_n(2),
        std::slice::from_ref(&policy),
    ));
    let threshold = build_simulate_response(&build_threshold_scval_xdr(2));
    vec![rule, threshold]
}

/// `verify_signer_set_against_chain` refuses a version-1 row whose verifier
/// contract is malformed, and the refusal holds no fragment of the address.
#[tokio::test]
#[serial_test::serial]
async fn signers_path_refuses_the_malformed_verifier_without_its_fragments() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let (audit_writer, audit_log_path, _dir) = tmp_audit_writer();
    write_baseline(
        &audit_writer,
        RULE_ID,
        ZERO_CONTRACT_REDACTED,
        &malformed_v1_state(),
    );

    let primary = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(two_of_two_responder(observation_simulations()))
        .mount(&primary)
        .await;
    let secondary = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(two_of_two_responder(observation_simulations()))
        .mount(&secondary)
        .await;
    let manager = manager_two_url(
        &primary.uri(),
        &secondary.uri(),
        Arc::clone(&audit_writer),
        audit_log_path,
    );

    let err = manager
        .verify_signer_set_against_chain(
            zero_sc_address(),
            RULE_ID,
            Some(SOURCE_G),
            Uuid::new_v4().to_string(),
        )
        .await
        .expect_err("a malformed verifier contract in the row is refused");

    assert_refused_without_fragments(&err);
}

/// The passkey signing path refuses at the signer-set comparison, after the
/// drift check passed, with the same refusal wrapped as a signer-set
/// divergence; no ceremony starts.
#[cfg(feature = "test-helpers")]
#[tokio::test]
#[serial_test::serial]
async fn credentials_path_refuses_the_malformed_verifier_without_its_fragments() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    stellar_agent_test_support::keyring_mock::install().unwrap();
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE;
    use stellar_agent_core::smart_account::rule_id::ContextRuleId;
    use stellar_agent_smart_account::managers::auth_entry::test_helpers::partial_authorization_entry;
    use stellar_agent_smart_account::managers::credentials::{
        CredentialsError, CredentialsManager,
    };
    use stellar_agent_smart_account::managers::signers::{SignersManager, SignersManagerConfig};
    use stellar_xdr::{ContractId, Hash, ScAddress};

    use super::rpc_mock_helpers::{SorobanRpcDispatcher, build_ledger_entries_contract_instance};

    let (audit_writer, audit_log_path, dir) = tmp_audit_writer();
    write_baseline(
        &audit_writer,
        RULE_ID,
        ZERO_CONTRACT_REDACTED,
        &malformed_v1_state(),
    );

    // One endpoint serves both roles: the drift check's rule read, then each
    // comparison endpoint's rule read, then each one's threshold read.
    let policy = policy_sc_address();
    let rule = build_simulate_response(&build_context_rule_scval_xdr(
        RULE_ID,
        &signer_set_n_of_n(2),
        std::slice::from_ref(&policy),
    ));
    let threshold = build_simulate_response(&build_threshold_scval_xdr(2));
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(SorobanRpcDispatcher::new_multi_simulate(
            build_ledger_entries_contract_instance(&policy, KNOWN_WASM_HASH),
            vec![rule.clone(), rule.clone(), rule, threshold],
        ))
        .mount(&server)
        .await;
    let manager = Arc::new(
        SignersManager::new(
            SignersManagerConfig::new(
                server.uri(),
                server.uri(),
                Arc::clone(&audit_writer),
                audit_log_path,
                TESTNET_PASSPHRASE.to_owned(),
                "test-profile".to_owned(),
                Duration::from_secs(5),
                "stellar:testnet".to_owned(),
            )
            .with_intent_admission(stellar_agent_smart_account::signing::intent_test_helpers::shared_no_value_admission()),
        )
        .expect("SignersManager::new must succeed"),
    );
    let credentials =
        CredentialsManager::new(dir.path().join("passkeys"), "default", "localhost", None);
    let entry = partial_authorization_entry(
        ScAddress::Contract(ContractId(Hash([0u8; 32]))),
        TESTNET_PASSPHRASE,
        vec![ContextRuleId::new(RULE_ID)],
    )
    .expect("fixture auth entry builds");
    let ceremony_started = AtomicBool::new(false);

    let result = credentials
        .sign_with_passkey_rule(
            &stellar_agent_smart_account::signing::intent_test_helpers::gate(vec![]),
            "laptop-passkey",
            &entry,
            manager,
            "127.0.0.1:0".parse().expect("socket addr parses"),
            Duration::from_millis(10),
            |_| ceremony_started.store(true, Ordering::SeqCst),
            // The diversification gate, which reads the log only, passes.
            true,
        )
        .await;

    match &result {
        Err(err @ CredentialsError::SignerSetDivergence { source }) => {
            assert_refused_without_fragments(source);
            assert_no_marker(err, LEADING_MARKER);
            assert_no_marker(err, TRAILING_MARKER);
        }
        other => panic!("expected SignerSetDivergence; got {other:?}"),
    }
    assert!(!ceremony_started.load(Ordering::SeqCst));
}
