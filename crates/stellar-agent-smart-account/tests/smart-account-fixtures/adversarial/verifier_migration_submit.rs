//! Mock-substrate tests for the migration submit path.
//!
//! # Coverage map
//!
//! | Test | Mechanism | Coverage |
//! |------|-----------|----------|
//! | [`submit_refuses_the_first_step_without_a_state_row_before_any_rpc`] | wiremock + `MigrationPlan::submit` | `sa.signer_set_missing_baseline` at `failed_step_index=0`, no pending add, no RPC request |
//!
//! The test invokes [`MigrationPlan::submit`] against a wiremock-backed
//! [`SignersManager`] whose audit log holds no signer-set state row. The
//! pair entry, its state rows, its pending add and its partial-failure
//! shapes are pinned against the stateful mock RPC in
//! `tests/smart_account_test_helpers/execute_path_drift_check_mock.rs`.
//!
//! # Gating
//!
//! `--features test-helpers` enables the test-only struct constructors
//! (`MigrationPlan::new_for_test`, `RuleMigration::new_for_test`,
//! `SignerMigrationStep::new_for_test`).
//!
//! Wiremock tests additionally require `wiremock` in `[dev-dependencies]`
//! (already declared in `crates/stellar-agent-smart-account/Cargo.toml`).
//!
//! Run with:
//!
//! ```text
//! cargo test -p stellar-agent-smart-account --features test-helpers \
//!   --test smart_account adversarial_fixtures::verifier_migration
//! ```
//!
//! # Implements
//!
//! Verifier diversification acceptance criteria for the migration submit path.

use stellar_agent_network::SoftwareSigningKey;
use stellar_agent_smart_account::managers::migration::{
    MigrationPlan, RuleMigration, SignerMigrationStep,
};
use stellar_agent_smart_account::managers::signers::SignersManager;
use stellar_agent_smart_account::verifier_allowlist::VerifierAuditStatus;
use stellar_xdr::{ContractId, Hash, HostFunction, InvokeContractArgs, ScAddress, ScSymbol, VecM};
use uuid::Uuid;
use wiremock::{
    Mock, MockServer,
    matchers::{method, path},
};

use super::rpc_mock_helpers::{
    SorobanRpcDispatcher, build_context_rule_external_signers_xdr, build_ledger_entries_account,
    build_simulate_response, manager_two_url, tmp_audit_writer,
};

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// OZ WebAuthn verifier v0.7.1 wasm hash — the legacy `VERIFIER_ALLOWLIST[1]`
/// entry (Provisional: OZ-internal artefact review; still recognised).
///
/// `vendor/oz-webauthn-verifier/v0.7.1/PROVENANCE.md` SHA-256 anchor.
/// OZ source SHA: `3f81125bed3114cc93f5fca6d13240082050269a` (tag v0.7.1).
const OZ_VERIFIER_HASH: [u8; 32] = [
    0x67, 0x80, 0x06, 0x90, 0x9b, 0x50, 0xc6, 0xc3, 0x65, 0xc0, 0x33, 0xf1, 0x37, 0x19, 0x7e, 0x91,
    0x0d, 0x83, 0x96, 0xa2, 0xc6, 0x8e, 0x92, 0x81, 0x32, 0x7a, 0x2e, 0xd7, 0xdb, 0xf4, 0xb2, 0x7a,
];

/// Fixed ed25519 seed for the mock signer.
///
/// A deterministic seed so the G-strkey is reproducible; never used on any
/// live network.  Secret material stays in-process for the test only.
const MOCK_SIGNER_SEED: [u8; 32] = [
    0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81, 0x92, 0xa3, 0xb4, 0xc5, 0xd6, 0xe7, 0xf8, 0x09,
    0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81, 0x92, 0xa3, 0xb4, 0xc5, 0xd6, 0xe7, 0xf8, 0x09,
];

// ─────────────────────────────────────────────────────────────────────────────
// Shared helpers
// ─────────────────────────────────────────────────────────────────────────────

/// A contract address with the given byte fill.
fn addr(byte: u8) -> ScAddress {
    ScAddress::Contract(ContractId(Hash([byte; 32])))
}

/// Builds a minimal but syntactically-valid `HostFunction::InvokeContract` for the
/// given entrypoint name.
///
/// The args are empty; only the function name and contract address matter for
/// the `extract_invoke_args` decode step inside `MigrationPlan::submit`.
///
/// # Byte-layout citation
///
/// `stellar_xdr::InvokeContractArgs` is the XDR-wire struct under
/// `HostFunction::InvokeContract`; no byte-layout citation needed (standard
/// XDR discriminant + struct encoding).
fn dummy_host_function(contract: &ScAddress, name: &str) -> HostFunction {
    HostFunction::InvokeContract(InvokeContractArgs {
        contract_address: contract.clone(),
        function_name: ScSymbol::try_from(name).unwrap(),
        args: VecM::default(),
    })
}

/// Builds a `SignersManager` backed by the given wiremock server.
///
/// Both primary and secondary RPC URLs point at the same server. The `_tmp_dir`
/// returned by `tmp_audit_writer` must be held by the caller for the duration
/// of the test.
async fn manager_with_server(server: &MockServer) -> (SignersManager, tempfile::TempDir) {
    let (audit_writer, audit_log_path, tmp_dir) = tmp_audit_writer();
    let manager = manager_two_url(&server.uri(), &server.uri(), audit_writer, audit_log_path);
    (manager, tmp_dir)
}

/// Returns the G-strkey for the fixed `MOCK_SIGNER_SEED`.
///
/// `SoftwareSigningKey::public_key` is async, so we compute the G-strkey
/// directly via ed25519-dalek (both use the same seed → same key pair).
fn mock_signer_g() -> String {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&MOCK_SIGNER_SEED);
    let verifying_key = signing_key.verifying_key();
    // `stellar_strkey` `Display` / `to_string` returns a `heapless::String<56>`,
    // not `std::string::String`.  Format through `{}` to get a heap-allocated copy.
    format!(
        "{}",
        stellar_strkey::ed25519::PublicKey(verifying_key.to_bytes())
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// a first step without a state row: wiremock end-to-end
// ─────────────────────────────────────────────────────────────────────────────

/// `MigrationPlan::submit` refuses the first pair with
/// `sa.signer_set_missing_baseline` when the migrating rule has no
/// signer-set state row, before any RPC request.
///
/// # Mock sequence
///
/// The dispatcher would answer `getLedgerEntries` with the source account,
/// the first `simulateTransaction` with rule 1 holding one External signer
/// (id 10) and every later one with an error. The fixture's audit log is
/// fresh, so the pair's comparison reads no state row for rule 1 and
/// refuses before it reaches the dispatcher.
///
/// # Assertions
///
/// - `result.failed_step_index == Some(0)`, `total_steps_attempted == 1`,
///   no successful step.
/// - `result.failed_step_error` has the wire code
///   `sa.signer_set_missing_baseline`.
/// - `result.pending_add` and `failed_step_remove_tx_hash` are `None`.
/// - The dispatcher received no request.
///
/// # Implements
///
/// Verifier diversification: a migration compares each rule with its state
/// row before anything is sent.
#[tokio::test]
async fn submit_refuses_the_first_step_without_a_state_row_before_any_rpc() {
    let server = MockServer::start().await;

    let signer_g = mock_signer_g();
    let account_resp = build_ledger_entries_account(&signer_g);
    let simulate_resp = serde_json::json!({
        "error": "mock-rpc-simulate-error",
        "latestLedger": 1000
    });
    let rule_resp = build_simulate_response(&build_context_rule_external_signers_xdr(
        1,
        &[10],
        &addr(0x05),
        &[0x04; 65],
    ));

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(SorobanRpcDispatcher::new_multi_simulate(
            account_resp,
            vec![rule_resp, simulate_resp],
        ))
        .mount(&server)
        .await;

    let (manager, _tmp_dir) = manager_with_server(&server).await;

    let smart_account = addr(0x01);

    // One affected rule with one signer step; `extract_invoke_args` decodes
    // both host functions, whose target is the smart account.
    let step = SignerMigrationStep::new_for_test(
        10,
        "aabbccdd",
        dummy_host_function(&smart_account, "remove_signer"),
        dummy_host_function(&smart_account, "add_signer"),
    );
    let rule = RuleMigration::new_for_test(1, "aabbccdd", vec![step]);
    let plan = MigrationPlan::new_for_test(
        smart_account.clone(),
        [0x11u8; 32],
        OZ_VERIFIER_HASH,
        addr(0x02),
        vec![rule],
        VerifierAuditStatus::Provisional {
            attested_by: "OpenZeppelin",
            attested_at: "2025-11-01",
        },
        Uuid::new_v4().to_string(),
    );

    use zeroize::Zeroizing;
    let seed = Zeroizing::new(MOCK_SIGNER_SEED);
    let signer: Box<dyn stellar_agent_network::Signer + Send + Sync> =
        Box::new(SoftwareSigningKey::new_from_zeroizing(seed));

    let request_id = Uuid::new_v4().to_string();
    let result = plan.submit(signer.as_ref(), &manager, &request_id).await;

    assert_eq!(result.failed_step_index, Some(0));
    assert!(
        result.successful_steps.is_empty(),
        "successful_steps must be empty; got: {:?}",
        result.successful_steps
    );
    assert_eq!(result.total_steps_attempted, 1);
    let err = result
        .failed_step_error
        .expect("failed_step_error must be Some when failed_step_index is Some");
    assert_eq!(
        err.wire_code(),
        "sa.signer_set_missing_baseline",
        "the pair refuses a rule without a state row; got: {err:?}"
    );
    assert!(result.pending_add.is_none());
    assert!(result.failed_step_remove_tx_hash.is_none());

    let requests = server
        .received_requests()
        .await
        .expect("wiremock records requests");
    assert!(
        requests.is_empty(),
        "the refusal comes before any RPC request; got {} requests",
        requests.len()
    );
}
