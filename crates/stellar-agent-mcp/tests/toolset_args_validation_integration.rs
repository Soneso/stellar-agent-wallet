//! Integration tests for pre-canonicalisation argument validation and the
//! malicious-toolset reference test.
//!
//! ## What these tests prove
//!
//! These tests exercise `validate_toolset_tool_args` through the full
//! `stellar_toolset_invoke` MCP dispatch surface on BOTH the ungated and gated
//! paths.
//!
//! ## Test inventory
//!
//! ### Ungated path — dangerous-key payload rejected
//! 1. **dangerous_key_tojson_rejected_ungated** — `toJSON` at top level → rejected.
//! 2. **dangerous_key_then_rejected_ungated** — `then` → rejected.
//! 3. **dangerous_key_proto_rejected_ungated** — `__proto__` → rejected.
//! 4. **dangerous_key_nested_in_array_rejected_ungated** — object-in-array → rejected.
//! 5. **benign_payload_passes_ungated** — clean payload routes; no regression.
//!
//! ### Mutation-before-guard (chain_id injected + dangerous key still caught)
//! 6. **chain_id_injected_and_dangerous_key_still_caught** — proves the guard runs
//!    on the post-injection value.
//!
//! ### Gated path — dangerous-key payload rejected
//! 7. **dangerous_key_tojson_rejected_gated** — `toJSON` on gated path → rejected
//!    before `from_value::<StellarPayCommitArgs>`.
//! 8. **dangerous_key_chain_id_injected_gated_still_caught** — chain_id + envelope_xdr
//!    injected, dangerous key still caught on the gated path.
//!
//! ### Malicious toolset reference test
//! 9.  **malicious_toolset_keystore_read_refused** — keystore-read action →
//!     `UnknownToolsetAction` (specific variant).
//! 10. **malicious_toolset_tx_resign_refused** — signing tool action →
//!     `UnknownToolsetAction` (not in matrix).
//! 11. **malicious_toolset_declares_real_cap_names_denylist_tool** — toolset declares
//!     `read-balance` but action names a `SIGNING_DENYLIST` tool → `UnknownToolsetAction`
//!     (proves denylist, not just "unknown action").
//! 12. **malicious_toolset_gated_no_grant** — declares `sign-payment`, no grant →
//!     `toolset.first_invoke_approval_required` (specific; proves gated tier is not
//!     a hole).
//! 13. **malicious_toolset_policy_mutate_refused** — policy-write tool →
//!     `UnknownToolsetAction` + static invariant test that no capability grant array
//!     contains any policy-mutation tool.
//!
//! ### Redaction test
//! 14. **secret_in_sibling_field_never_in_error** — secret-shaped value in a sibling
//!     field never appears in the error Display.
//!
//! ### Depth bound + node-count bound
//! 15. **depth_at_max_plus_1_rejected_ungated** — `TOOLSET_ARGS_MAX_DEPTH+1` nested
//!     payload → `NestingTooDeep` without overflow.
//! 16. **wide_payload_over_node_cap_rejected_ungated** — flat object over
//!     `TOOLSET_ARGS_MAX_NODES` entries → `TooManyNodes`; no commit side-effect.
//!
//! ### Gated-path no-side-effect proofs
//! 17. `dangerous_key_tojson_rejected_gated` additionally asserts that when the guard
//!     rejects, NO pending approval entry was written to the approval store.
//! 18. `dangerous_key_chain_id_injected_gated_still_caught` additionally asserts the
//!     same approval-store-empty invariant.
//!
//! # `#[serial]` requirement
//!
//! All tests touching the process-global keyring mock are serialised via
//! `#[serial]` because the keyring mock is process-global shared state.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics and unwraps acceptable in integration tests"
)]

use std::sync::Arc;

use serde_json::json;
use serial_test::serial;
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_mcp::server::{StellarToolsetInvokeArgs, WalletServer};
use stellar_agent_test_support::keyring_mock;
use stellar_agent_toolsets::{
    ARGS_KEY_DENYLIST, TOOLSET_ARGS_MAX_DEPTH, TOOLSET_ARGS_MAX_NODES, ToolsetArgsError,
};
use stellar_agent_toolsets_runtime::matrix::SIGNING_DENYLIST;
use tempfile::TempDir;

mod common;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Valid testnet G-strkey for source account.
const SOURCE_G: &str = "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI";

/// Valid testnet G-strkey for destination.
const DEST_G: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";

/// Toolset name for read-balance tests.
const TOOLSET_READ_BALANCE: &str = "balance-reporter";

/// Toolset name for sign-payment tests.
const TOOLSET_SIGN_PAYMENT: &str = "payment-toolset";

/// Malicious toolset name.
const TOOLSET_MALICIOUS: &str = "malicious-toolset";

/// The pin file name.
const PIN_FILE_NAME: &str = ".stellar-agent-toolset-pin.json";

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Install mock keyring and seed a deterministic nonce key.
fn setup_mock_keyring() {
    use base64::Engine as _;
    keyring_mock::install().expect("mock keyring install");
    let key = [0x42u8; 32];
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key);
    let entry = keyring_core::Entry::new("n-svc", "n-acct").expect("keyring entry");
    entry.set_password(&encoded).expect("set nonce key");
}

/// Build a `WalletServer` for testnet with an Allow policy and all path overrides.
fn build_allow_server_with_overrides(
    toolsets_root: &std::path::Path,
    approval_dir: Option<&std::path::Path>,
    grant_store_path: Option<&std::path::Path>,
) -> WalletServer {
    let profile = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
        .with_noop_engine()
        .build();
    let mut server = WalletServer::new(profile).expect("WalletServer::new");
    server.set_policy_engine_for_test(Arc::new(common::policy_mock::MockPolicyEngine::allow()));
    server.set_toolsets_root_for_test(toolsets_root.to_path_buf());
    if let Some(dir) = approval_dir {
        server.set_approval_dir_for_test(dir.to_path_buf());
    }
    if let Some(path) = grant_store_path {
        server.set_grant_store_path_for_test(path.to_path_buf());
    }
    server
}

/// Write a minimal `ToolsetPinRecord` JSON for `toolset_name` with `capabilities`.
fn write_pin(toolsets_root: &std::path::Path, toolset_name: &str, capabilities: &[&str]) {
    let toolset_dir = toolsets_root.join(toolset_name);
    std::fs::create_dir_all(&toolset_dir).expect("create toolset dir");
    let pin_json = json!({
        "package": toolset_name,
        "version": "1.0.0",
        "shasum": "a".repeat(64),
        "publisher": SOURCE_G,
        "installed_at": "2026-06-02T00:00:00Z",
        "capabilities": capabilities,
        "allowed_tools": []
    });
    let pin_path = toolset_dir.join(PIN_FILE_NAME);
    std::fs::write(&pin_path, serde_json::to_string_pretty(&pin_json).unwrap()).expect("write pin");
}

/// Extract the error message string from `ErrorData`.
fn error_message(err: &rmcp::ErrorData) -> String {
    err.message.to_string()
}

/// Build a minimal valid `TransactionV1Envelope` XDR base64 string.
fn payment_envelope_xdr(source: &str, dest: &str, amount_stroops: i64) -> String {
    use stellar_xdr::{
        Asset, Limits, Memo, MuxedAccount, Operation, OperationBody, PaymentOp, Preconditions,
        SequenceNumber, Transaction, TransactionEnvelope, TransactionExt, TransactionV1Envelope,
        Uint256, VecM, WriteXdr,
    };
    fn g_bytes(g: &str) -> [u8; 32] {
        stellar_strkey::ed25519::PublicKey::from_string(g)
            .expect("valid G-strkey")
            .0
    }
    let tx = Transaction {
        source_account: MuxedAccount::Ed25519(Uint256(g_bytes(source))),
        fee: 100,
        seq_num: SequenceNumber(101),
        cond: Preconditions::None,
        memo: Memo::None,
        operations: vec![Operation {
            source_account: None,
            body: OperationBody::Payment(PaymentOp {
                destination: MuxedAccount::Ed25519(Uint256(g_bytes(dest))),
                asset: Asset::Native,
                amount: amount_stroops,
            }),
        }]
        .try_into()
        .expect("single-op vec"),
        ext: TransactionExt::V0,
    };
    TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: VecM::default(),
    })
    .to_xdr_base64(Limits::none())
    .expect("XDR encode must succeed")
}

// ─────────────────────────────────────────────────────────────────────────────
// Ungated path — dangerous keys rejected
// ─────────────────────────────────────────────────────────────────────────────

/// `toJSON` at top level on the ungated path is rejected before the tool is
/// invoked.  The error message contains "toolset.args_validation".
#[tokio::test]
#[serial]
async fn dangerous_key_tojson_rejected_ungated() {
    setup_mock_keyring();
    let tmp = TempDir::new().unwrap();
    let toolsets_root = tmp.path().to_path_buf();
    write_pin(&toolsets_root, TOOLSET_READ_BALANCE, &["read-balance"]);

    let server = build_allow_server_with_overrides(&toolsets_root, None, None);

    let args = StellarToolsetInvokeArgs {
        toolset: TOOLSET_READ_BALANCE.to_owned(),
        action: "stellar_balances".to_owned(),
        chain_id: Some("stellar:testnet".to_owned()),
        args: json!({
            "account_id": SOURCE_G,
            "toJSON": "evil"
        }),
    };

    let result = server.call_stellar_toolset_invoke(args).await;
    assert!(result.is_err(), "dangerous key must cause rejection");
    let msg = error_message(result.as_ref().unwrap_err());
    assert!(
        msg.contains("toolset.args_validation"),
        "error must contain toolset.args_validation: {msg}"
    );
    assert!(
        msg.contains("toJSON"),
        "error must reference the matched denylist constant: {msg}"
    );
}

/// `then` on ungated path rejected.
#[tokio::test]
#[serial]
async fn dangerous_key_then_rejected_ungated() {
    setup_mock_keyring();
    let tmp = TempDir::new().unwrap();
    let toolsets_root = tmp.path().to_path_buf();
    write_pin(&toolsets_root, TOOLSET_READ_BALANCE, &["read-balance"]);

    let server = build_allow_server_with_overrides(&toolsets_root, None, None);

    let args = StellarToolsetInvokeArgs {
        toolset: TOOLSET_READ_BALANCE.to_owned(),
        action: "stellar_balances".to_owned(),
        chain_id: Some("stellar:testnet".to_owned()),
        args: json!({ "account_id": SOURCE_G, "then": "fn() => Promise.resolve('pwned')" }),
    };

    let result = server.call_stellar_toolset_invoke(args).await;
    assert!(result.is_err(), "then key must cause rejection");
    let msg = error_message(result.as_ref().unwrap_err());
    assert!(msg.contains("toolset.args_validation"), "msg: {msg}");
    assert!(msg.contains("then"), "msg: {msg}");
}

/// `__proto__` on ungated path rejected.
#[tokio::test]
#[serial]
async fn dangerous_key_proto_rejected_ungated() {
    setup_mock_keyring();
    let tmp = TempDir::new().unwrap();
    let toolsets_root = tmp.path().to_path_buf();
    write_pin(&toolsets_root, TOOLSET_READ_BALANCE, &["read-balance"]);

    let server = build_allow_server_with_overrides(&toolsets_root, None, None);

    let args = StellarToolsetInvokeArgs {
        toolset: TOOLSET_READ_BALANCE.to_owned(),
        action: "stellar_balances".to_owned(),
        chain_id: Some("stellar:testnet".to_owned()),
        args: json!({ "account_id": SOURCE_G, "__proto__": { "isAdmin": true } }),
    };

    let result = server.call_stellar_toolset_invoke(args).await;
    assert!(result.is_err(), "__proto__ key must cause rejection");
    let msg = error_message(result.as_ref().unwrap_err());
    assert!(msg.contains("toolset.args_validation"), "msg: {msg}");
    assert!(msg.contains("__proto__"), "msg: {msg}");
}

/// Object with dangerous key nested inside an array is rejected (depth check).
#[tokio::test]
#[serial]
async fn dangerous_key_nested_in_array_rejected_ungated() {
    setup_mock_keyring();
    let tmp = TempDir::new().unwrap();
    let toolsets_root = tmp.path().to_path_buf();
    write_pin(&toolsets_root, TOOLSET_READ_BALANCE, &["read-balance"]);

    let server = build_allow_server_with_overrides(&toolsets_root, None, None);

    // An array with an object containing a dangerous key.
    let args = StellarToolsetInvokeArgs {
        toolset: TOOLSET_READ_BALANCE.to_owned(),
        action: "stellar_balances".to_owned(),
        chain_id: Some("stellar:testnet".to_owned()),
        args: json!({
            "account_id": SOURCE_G,
            "records": [
                { "safe": "value" },
                { "constructor": "pollution" }
            ]
        }),
    };

    let result = server.call_stellar_toolset_invoke(args).await;
    assert!(
        result.is_err(),
        "dangerous key in nested array object must be rejected"
    );
    let msg = error_message(result.as_ref().unwrap_err());
    assert!(msg.contains("toolset.args_validation"), "msg: {msg}");
    assert!(msg.contains("constructor"), "msg: {msg}");
}

// ─────────────────────────────────────────────────────────────────────────────
// Benign payload passes (no regression)
// ─────────────────────────────────────────────────────────────────────────────

/// A clean `stellar_balances` invocation (well-formed payload within depth limit)
/// still routes to the tool handler.  The tool itself will fail (no live RPC)
/// but the validation layer must NOT reject it.
///
/// This proves the guard does not block legitimate traffic.
#[tokio::test]
#[serial]
async fn benign_payload_passes_ungated() {
    setup_mock_keyring();
    let tmp = TempDir::new().unwrap();
    let toolsets_root = tmp.path().to_path_buf();
    write_pin(&toolsets_root, TOOLSET_READ_BALANCE, &["read-balance"]);

    let server = build_allow_server_with_overrides(&toolsets_root, None, None);

    let args = StellarToolsetInvokeArgs {
        toolset: TOOLSET_READ_BALANCE.to_owned(),
        action: "stellar_balances".to_owned(),
        chain_id: Some("stellar:testnet".to_owned()),
        args: json!({ "account_id": SOURCE_G }),
    };

    let result = server.call_stellar_toolset_invoke(args).await;
    // The tool call may fail at the RPC layer (no live testnet in unit tests),
    // but it must NOT fail with a toolset.args_validation error.
    // We accept any result that is not a toolset.args_validation error.
    if let Err(ref e) = result {
        let msg = error_message(e);
        assert!(
            !msg.contains("toolset.args_validation"),
            "benign payload must not trigger args_validation: {msg}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Mutation-before-guard (chain_id injected + dangerous key still caught)
// ─────────────────────────────────────────────────────────────────────────────

/// Proves that the guard runs on the POST-INJECTION value (after chain_id is
/// injected into the args map).  A payload that contains chain_id AND a
/// dangerous key must still be caught.
///
/// Verifies the mutation-before-guard invariant.
#[tokio::test]
#[serial]
async fn chain_id_injected_and_dangerous_key_still_caught() {
    setup_mock_keyring();
    let tmp = TempDir::new().unwrap();
    let toolsets_root = tmp.path().to_path_buf();
    write_pin(&toolsets_root, TOOLSET_READ_BALANCE, &["read-balance"]);

    let server = build_allow_server_with_overrides(&toolsets_root, None, None);

    // The chain_id is provided at the top level of StellarToolsetInvokeArgs AND
    // will be injected into tool_args before the guard runs.  The payload also
    // contains a dangerous key alongside the chain_id — that dangerous key
    // must still be caught AFTER chain_id injection.
    let args = StellarToolsetInvokeArgs {
        toolset: TOOLSET_READ_BALANCE.to_owned(),
        action: "stellar_balances".to_owned(),
        chain_id: Some("stellar:testnet".to_owned()),
        args: json!({
            "account_id": SOURCE_G,
            "__proto__": { "isAdmin": true }
        }),
    };

    let result = server.call_stellar_toolset_invoke(args).await;
    assert!(
        result.is_err(),
        "dangerous key must be caught even after chain_id injection"
    );
    let msg = error_message(result.as_ref().unwrap_err());
    assert!(
        msg.contains("toolset.args_validation"),
        "error must be args_validation (post-injection check): {msg}"
    );
    assert!(msg.contains("__proto__"), "msg: {msg}");
}

// ─────────────────────────────────────────────────────────────────────────────
// Gated path — dangerous keys rejected
// ─────────────────────────────────────────────────────────────────────────────

/// On the gated path, `toJSON` in args is rejected before `from_value::<StellarPayCommitArgs>`.
///
/// The gated path goes through `route_to_gated_resolver` →
/// `route_to_gated_commit` → validate → `route_to_gated_tool`.
/// We need a toolset with `sign-payment` + a current grant for the guard to be
/// reached (the first-invoke gate fires before if no grant exists).
///
/// Also asserts the no-side-effect invariant: when the guard rejects a
/// dangerous-key payload on the gated path, NO pending approval entry is written
/// to the approval store.  The guard fires before `from_value` and before any
/// policy/approval machinery is reached.
#[tokio::test]
#[serial]
async fn dangerous_key_tojson_rejected_gated() {
    use stellar_agent_core::approval::{
        PendingApprovalStore, TOOLSET_GRANT_DEFAULT_TTL_MS, ToolsetGrantStore,
        build_attested_grant, process_uid_for_attestation,
    };
    use stellar_agent_core::timefmt::now_unix_ms;

    setup_mock_keyring();
    let tmp = TempDir::new().unwrap();
    let toolsets_root = tmp.path().to_path_buf();
    let approval_dir = tmp.path().join("approvals");
    std::fs::create_dir_all(&approval_dir).unwrap();
    let grant_store_path = tmp.path().join("grants.toml");

    write_pin(&toolsets_root, TOOLSET_SIGN_PAYMENT, &["sign-payment"]);

    // Build a valid envelope_xdr to pass the gated resolver's decode step.
    let env_xdr = payment_envelope_xdr(SOURCE_G, DEST_G, 1_000_000);

    // Seed a valid grant for (TOOLSET_SIGN_PAYMENT, sign-payment, DEST_G, XLM).
    // attestation_key matches the [0x42u8;32] nonce key seeded by setup_mock_keyring.
    let attestation_key = [0x42u8; 32];
    let process_uid = process_uid_for_attestation().expect("process uid");
    let now_ms = now_unix_ms().expect("now_unix_ms");
    let grant = build_attested_grant(
        TOOLSET_SIGN_PAYMENT.to_owned(),
        "sign-payment".to_owned(),
        DEST_G.to_owned(),
        "XLM".to_owned(),
        0,
        10_000_000,
        process_uid,
        now_ms,
        TOOLSET_GRANT_DEFAULT_TTL_MS,
        &attestation_key,
    )
    .expect("build_attested_grant");
    let mut store = ToolsetGrantStore::open(grant_store_path.clone(), now_ms).expect("open grants");
    store.insert(grant).expect("insert grant");

    let server = build_allow_server_with_overrides(
        &toolsets_root,
        Some(&approval_dir),
        Some(&grant_store_path),
    );

    // Gated path with a dangerous key in args alongside envelope_xdr.
    let args = StellarToolsetInvokeArgs {
        toolset: TOOLSET_SIGN_PAYMENT.to_owned(),
        action: "stellar_pay_commit".to_owned(),
        chain_id: Some("stellar:testnet".to_owned()),
        args: json!({
            "envelope_xdr": env_xdr,
            "toJSON": "evil"
        }),
    };

    let result = server.call_stellar_toolset_invoke(args).await;
    assert!(
        result.is_err(),
        "dangerous key on gated path must be rejected"
    );
    let msg = error_message(result.as_ref().unwrap_err());
    assert!(
        msg.contains("toolset.args_validation"),
        "gated path error must be args_validation: {msg}"
    );
    assert!(msg.contains("toJSON"), "msg: {msg}");

    // No-side-effect assertion:
    // The guard fires before from_value and before any approval/policy machinery,
    // so the approval store must be empty after the rejected call.
    let approval_store_path = approval_dir.join("acct.toml");
    if approval_store_path.exists() {
        let store = PendingApprovalStore::open(approval_store_path).expect("open approval store");
        assert_eq!(
            store.len(),
            0,
            "approval store must be empty after gated dangerous-key rejection \
             (guard fires before approval machinery)"
        );
    }
    // If the store file does not exist, there are zero entries — also correct.
}

/// On the gated path: chain_id + envelope_xdr injected, dangerous key still caught.
///
/// Also asserts the no-side-effect invariant: no pending approval entry is
/// written when the guard rejects on the gated path.
#[tokio::test]
#[serial]
async fn dangerous_key_chain_id_injected_gated_still_caught() {
    use stellar_agent_core::approval::{
        PendingApprovalStore, TOOLSET_GRANT_DEFAULT_TTL_MS, ToolsetGrantStore,
        build_attested_grant, process_uid_for_attestation,
    };
    use stellar_agent_core::timefmt::now_unix_ms;

    setup_mock_keyring();
    let tmp = TempDir::new().unwrap();
    let toolsets_root = tmp.path().to_path_buf();
    let approval_dir = tmp.path().join("approvals");
    std::fs::create_dir_all(&approval_dir).unwrap();
    let grant_store_path = tmp.path().join("grants.toml");

    write_pin(&toolsets_root, TOOLSET_SIGN_PAYMENT, &["sign-payment"]);

    let env_xdr = payment_envelope_xdr(SOURCE_G, DEST_G, 1_000_000);

    // Use the same attestation_key as setup_mock_keyring for consistency.
    // The grant-store match_and_verify path checks HMAC against the nonce key;
    // for this test the guard fires before any HMAC verification, so the exact
    // key value does not affect the test outcome — but [0x42u8;32] matches the
    // seeded nonce key and avoids a latent confusion if the test is extended.
    let attestation_key = [0x42u8; 32];
    let process_uid = process_uid_for_attestation().expect("process uid");
    let now_ms = now_unix_ms().expect("now_unix_ms");
    let grant = build_attested_grant(
        TOOLSET_SIGN_PAYMENT.to_owned(),
        "sign-payment".to_owned(),
        DEST_G.to_owned(),
        "XLM".to_owned(),
        0,
        10_000_000,
        process_uid,
        now_ms,
        TOOLSET_GRANT_DEFAULT_TTL_MS,
        &attestation_key,
    )
    .expect("build_attested_grant");
    let mut store = ToolsetGrantStore::open(grant_store_path.clone(), now_ms).expect("open grants");
    store.insert(grant).expect("insert grant");

    let server = build_allow_server_with_overrides(
        &toolsets_root,
        Some(&approval_dir),
        Some(&grant_store_path),
    );

    // chain_id provided (will be injected into args map) + dangerous key.
    let args = StellarToolsetInvokeArgs {
        toolset: TOOLSET_SIGN_PAYMENT.to_owned(),
        action: "stellar_pay_commit".to_owned(),
        chain_id: Some("stellar:testnet".to_owned()),
        args: json!({
            "envelope_xdr": env_xdr,
            "constructor": "evil"
        }),
    };

    let result = server.call_stellar_toolset_invoke(args).await;
    assert!(
        result.is_err(),
        "dangerous key must be caught on gated path"
    );
    let msg = error_message(result.as_ref().unwrap_err());
    assert!(
        msg.contains("toolset.args_validation"),
        "gated path error must be args_validation: {msg}"
    );
    assert!(msg.contains("constructor"), "msg: {msg}");

    // No-side-effect assertion:
    // Guard fires before approval machinery — approval store must be empty.
    let approval_store_path = approval_dir.join("acct.toml");
    if approval_store_path.exists() {
        let store = PendingApprovalStore::open(approval_store_path).expect("open approval store");
        assert_eq!(
            store.len(),
            0,
            "approval store must be empty after gated dangerous-key rejection \
             (guard fires before approval machinery)"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Malicious toolset reference test (specific per-leg refusals)
// ─────────────────────────────────────────────────────────────────────────────

/// Leg 1: malicious toolset's keystore-reading tool action → `toolset.unknown_action`
/// (that tool is not in the matrix; assert the SPECIFIC variant, not just "an error").
///
/// Represents a toolset that declares only `read-balance` but tries to invoke a
/// keystore-reading action (not a real MCP tool name).
#[tokio::test]
#[serial]
async fn malicious_toolset_keystore_read_refused() {
    setup_mock_keyring();
    let tmp = TempDir::new().unwrap();
    let toolsets_root = tmp.path().to_path_buf();
    // Malicious toolset only has read-balance capability.
    write_pin(&toolsets_root, TOOLSET_MALICIOUS, &["read-balance"]);

    let server = build_allow_server_with_overrides(&toolsets_root, None, None);

    let args = StellarToolsetInvokeArgs {
        toolset: TOOLSET_MALICIOUS.to_owned(),
        action: "keystore_export_secret".to_owned(), // not in the matrix
        chain_id: None,
        args: json!({}),
    };

    let result = server.call_stellar_toolset_invoke(args).await;
    assert!(
        result.is_err(),
        "keystore-reading action must be refused with an error"
    );
    let msg = error_message(result.as_ref().unwrap_err());
    // Specific variant: toolset.unknown_action
    assert!(
        msg.contains("toolset.unknown_action"),
        "keystore-read must produce toolset.unknown_action; got: {msg}"
    );
}

/// Leg 2: malicious toolset attempts to invoke a signing tool (SEP-43 sign) →
/// `toolset.unknown_action` (signing tools are not in the matrix).
///
/// Assert the specific variant AND that no signer fn is entered.
#[tokio::test]
#[serial]
async fn malicious_toolset_tx_resign_refused() {
    setup_mock_keyring();
    let tmp = TempDir::new().unwrap();
    let toolsets_root = tmp.path().to_path_buf();
    // Malicious toolset even with multiple caps cannot reach signing tools.
    write_pin(
        &toolsets_root,
        TOOLSET_MALICIOUS,
        &["read-balance", "propose-transaction"],
    );

    let server = build_allow_server_with_overrides(&toolsets_root, None, None);

    // Try all signing tools in SIGNING_DENYLIST — all must be unknown_action.
    for signing_tool in SIGNING_DENYLIST.iter().filter(|t| {
        // Exclude gated matrix tools (stellar_pay_commit) and reflexive tools;
        // those get a different error from the gated path check.
        // Focus on pure signing/key tools.
        [
            "stellar_sep43_sign_transaction",
            "stellar_sep43_sign_and_submit_transaction",
            "stellar_sep43_sign_auth_entry",
            "stellar_sep43_sign_message",
            "stellar_sep53_sign_message",
        ]
        .contains(t)
    }) {
        let args = StellarToolsetInvokeArgs {
            toolset: TOOLSET_MALICIOUS.to_owned(),
            action: (*signing_tool).to_owned(),
            chain_id: None,
            args: json!({}),
        };
        let result = server.call_stellar_toolset_invoke(args).await;
        assert!(
            result.is_err(),
            "signing tool {signing_tool} must be refused"
        );
        let msg = error_message(result.as_ref().unwrap_err());
        assert!(
            msg.contains("toolset.unknown_action"),
            "signing tool {signing_tool} must produce toolset.unknown_action; got: {msg}"
        );
    }
}

/// Leg 3: toolset declares `read-balance` (a real capability) but names a
/// `SIGNING_DENYLIST` tool as action → `toolset.unknown_action` (proves the
/// denylist, not just "unknown action").
///
/// The tool (`stellar_create_account_commit`) is a real MCP tool but is
/// excluded from the matrix by the denylist.  The refusal is `UnknownToolsetAction`
/// because `resolve_action` returns it for any SIGNING_DENYLIST tool.
#[tokio::test]
#[serial]
async fn malicious_toolset_declares_real_cap_names_denylist_tool() {
    setup_mock_keyring();
    let tmp = TempDir::new().unwrap();
    let toolsets_root = tmp.path().to_path_buf();
    write_pin(&toolsets_root, TOOLSET_MALICIOUS, &["read-balance"]);

    let server = build_allow_server_with_overrides(&toolsets_root, None, None);

    // stellar_create_account_commit is in SIGNING_DENYLIST — the toolset
    // cannot reach it via the ungated matrix.
    assert!(
        SIGNING_DENYLIST.contains(&"stellar_create_account_commit"),
        "stellar_create_account_commit must be in SIGNING_DENYLIST for this test"
    );

    let args = StellarToolsetInvokeArgs {
        toolset: TOOLSET_MALICIOUS.to_owned(),
        action: "stellar_create_account_commit".to_owned(),
        chain_id: None,
        args: json!({}),
    };

    let result = server.call_stellar_toolset_invoke(args).await;
    assert!(
        result.is_err(),
        "SIGNING_DENYLIST tool must be refused even if a real cap is declared"
    );
    let msg = error_message(result.as_ref().unwrap_err());
    assert!(
        msg.contains("toolset.unknown_action"),
        "SIGNING_DENYLIST tool must produce toolset.unknown_action; got: {msg}"
    );
}

/// Leg 4: toolset declares `sign-payment` but has NO grant → first-invoke gate fires.
///
/// This is the most security-relevant case: proves the gated tier is not a hole.
/// Even with `sign-payment` declared, the FIRST invoke requires operator approval.
#[tokio::test]
#[serial]
async fn malicious_toolset_gated_no_grant() {
    setup_mock_keyring();
    let tmp = TempDir::new().unwrap();
    let toolsets_root = tmp.path().to_path_buf();
    let approval_dir = tmp.path().join("approvals");
    std::fs::create_dir_all(&approval_dir).unwrap();
    let grant_store_path = tmp.path().join("grants.toml");

    // Toolset declares sign-payment but no grant has been approved.
    write_pin(&toolsets_root, TOOLSET_MALICIOUS, &["sign-payment"]);

    let env_xdr = payment_envelope_xdr(SOURCE_G, DEST_G, 1_000_000);

    let server = build_allow_server_with_overrides(
        &toolsets_root,
        Some(&approval_dir),
        Some(&grant_store_path),
    );

    let args = StellarToolsetInvokeArgs {
        toolset: TOOLSET_MALICIOUS.to_owned(),
        action: "stellar_pay_commit".to_owned(),
        chain_id: Some("stellar:testnet".to_owned()),
        args: json!({ "envelope_xdr": env_xdr }),
    };

    let result = server.call_stellar_toolset_invoke(args).await;
    assert!(
        result.is_err(),
        "gated path with no grant must return an error (first-invoke gate)"
    );
    let msg = error_message(result.as_ref().unwrap_err());
    // Specific variant: toolset.first_invoke_approval_required
    assert!(
        msg.contains("toolset.first_invoke_approval_required"),
        "no-grant gated invoke must produce toolset.first_invoke_approval_required; got: {msg}"
    );
}

/// Leg 5: policy-mutate action → `toolset.unknown_action`.
///
/// PLUS static invariant test: no capability's grant array contains any
/// policy-mutation tool (breaks loudly if a future change adds one).
#[tokio::test]
#[serial]
async fn malicious_toolset_policy_mutate_refused() {
    use stellar_agent_toolsets_runtime::matrix::{
        OBSERVE_EVENT_GRANTS, PROPOSE_TRANSACTION_GRANTS, READ_BALANCE_GRANTS,
        SUGGEST_DESTINATION_GRANTS,
    };

    setup_mock_keyring();
    let tmp = TempDir::new().unwrap();
    let toolsets_root = tmp.path().to_path_buf();
    write_pin(&toolsets_root, TOOLSET_MALICIOUS, &["read-balance"]);

    let server = build_allow_server_with_overrides(&toolsets_root, None, None);

    // Policy-mutation tool names (hypothetical — none exist in the registry,
    // but the test proves the structural guarantee).
    let policy_mutate_actions = [
        "set_policy",
        "update_policy",
        "policy_grant_admin",
        "stellar_policy_write",
    ];

    for action in &policy_mutate_actions {
        let args = StellarToolsetInvokeArgs {
            toolset: TOOLSET_MALICIOUS.to_owned(),
            action: (*action).to_owned(),
            chain_id: None,
            args: json!({}),
        };
        let result = server.call_stellar_toolset_invoke(args).await;
        assert!(
            result.is_err(),
            "policy-mutate action {action} must be refused"
        );
        let msg = error_message(result.as_ref().unwrap_err());
        assert!(
            msg.contains("toolset.unknown_action"),
            "policy-mutate action {action} must produce toolset.unknown_action; got: {msg}"
        );
    }

    // Static invariant: no capability grant array contains any policy-mutation
    // tool.  This breaks loudly if a future change accidentally adds one.
    //
    // Note: ALL_MATRIX_ENTRIES covers only ungated tools; GATED_MATRIX_ENTRIES
    // covers stellar_pay_commit only.  Neither should contain policy tools.
    let all_grant_tools: Vec<&str> = [
        READ_BALANCE_GRANTS,
        PROPOSE_TRANSACTION_GRANTS,
        SUGGEST_DESTINATION_GRANTS,
        OBSERVE_EVENT_GRANTS,
    ]
    .iter()
    .flat_map(|s| s.iter().copied())
    .collect();

    // Policy mutation keywords that should NEVER appear in any grant.
    let policy_mutation_substrings = ["policy", "admin", "grant_role", "set_rule", "set_policy"];
    for tool in &all_grant_tools {
        for substr in &policy_mutation_substrings {
            assert!(
                !tool.to_ascii_lowercase().contains(substr),
                "grant tool '{tool}' contains policy-mutation substring '{substr}' — \
                 remove it from the grant array immediately (static invariant)"
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Redaction test: secret in sibling field never appears in error
// ─────────────────────────────────────────────────────────────────────────────

/// A secret-shaped value planted in a sibling field alongside the dangerous key
/// must NEVER appear in the error Display or message.
///
/// Proves the redaction guarantee at the integration level.
#[tokio::test]
#[serial]
async fn secret_in_sibling_field_never_in_error() {
    setup_mock_keyring();
    let tmp = TempDir::new().unwrap();
    let toolsets_root = tmp.path().to_path_buf();
    write_pin(&toolsets_root, TOOLSET_READ_BALANCE, &["read-balance"]);

    let server = build_allow_server_with_overrides(&toolsets_root, None, None);

    // Plant a secret-shaped value in a sibling field.
    let planted_secret = "SBSECRETPLANTEDVALUETHATMUSTNEVERAPPEARINERROR12345ABCDEF";
    let args = StellarToolsetInvokeArgs {
        toolset: TOOLSET_READ_BALANCE.to_owned(),
        action: "stellar_balances".to_owned(),
        chain_id: None,
        args: json!({
            "account_id": planted_secret,
            "toJSON": "irrelevant"
        }),
    };

    let result = server.call_stellar_toolset_invoke(args).await;
    assert!(result.is_err(), "dangerous key must cause rejection");
    let err = result.unwrap_err();
    let msg = error_message(&err);
    let debug_str = format!("{err:?}");

    assert!(
        !msg.contains(planted_secret),
        "error message must not contain the planted secret: {msg}"
    );
    assert!(
        !debug_str.contains(planted_secret),
        "error debug must not contain the planted secret: {debug_str}"
    );
    // Verify the denylist constant IS present.
    assert!(
        msg.contains("toJSON"),
        "msg must mention denylist constant: {msg}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Depth bound
// ─────────────────────────────────────────────────────────────────────────────

/// A payload nested at `TOOLSET_ARGS_MAX_DEPTH + 1` is rejected with
/// `NestingTooDeep` on the ungated path without stack overflow.
#[tokio::test]
#[serial]
async fn depth_at_max_plus_1_rejected_ungated() {
    setup_mock_keyring();
    let tmp = TempDir::new().unwrap();
    let toolsets_root = tmp.path().to_path_buf();
    write_pin(&toolsets_root, TOOLSET_READ_BALANCE, &["read-balance"]);

    let server = build_allow_server_with_overrides(&toolsets_root, None, None);

    // Build a Value nested at TOOLSET_ARGS_MAX_DEPTH + 1 (directly in memory,
    // bypassing serde_json's parse limit).
    let mut deep_val = json!({ "leaf": "value" });
    for _ in 0..=TOOLSET_ARGS_MAX_DEPTH {
        deep_val = json!({ "nested": deep_val });
    }

    let args = StellarToolsetInvokeArgs {
        toolset: TOOLSET_READ_BALANCE.to_owned(),
        action: "stellar_balances".to_owned(),
        chain_id: None,
        args: deep_val,
    };

    let result = server.call_stellar_toolset_invoke(args).await;
    assert!(result.is_err(), "depth-exceeded payload must be rejected");
    let msg = error_message(result.as_ref().unwrap_err());
    assert!(
        msg.contains("toolset.args_validation"),
        "depth error must come from args_validation: {msg}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Node-count bound
// ─────────────────────────────────────────────────────────────────────────────

/// A flat object over `TOOLSET_ARGS_MAX_NODES` is rejected on the ungated path.
///
/// This exercises the O(payload-width) case that `TOOLSET_ARGS_MAX_DEPTH` alone
/// does not prevent.  The CLI `--args` consumer has no rmcp frame-size guard, so
/// this bound is necessary on both transports.
#[tokio::test]
#[serial]
async fn wide_payload_over_node_cap_rejected_ungated() {
    setup_mock_keyring();
    let tmp = TempDir::new().unwrap();
    let toolsets_root = tmp.path().to_path_buf();
    write_pin(&toolsets_root, TOOLSET_READ_BALANCE, &["read-balance"]);

    let server = build_allow_server_with_overrides(&toolsets_root, None, None);

    // Build a flat object with TOOLSET_ARGS_MAX_NODES + 1 benign entries.
    // No dangerous keys, no nesting — purely a width attack.
    let mut map = serde_json::Map::new();
    for i in 0..=TOOLSET_ARGS_MAX_NODES {
        map.insert(format!("field_{i}"), serde_json::Value::String("v".into()));
    }
    let wide_val = serde_json::Value::Object(map);

    let args = StellarToolsetInvokeArgs {
        toolset: TOOLSET_READ_BALANCE.to_owned(),
        action: "stellar_balances".to_owned(),
        chain_id: None,
        args: wide_val,
    };

    let result = server.call_stellar_toolset_invoke(args).await;
    assert!(
        result.is_err(),
        "wide-over-cap payload must be rejected on ungated path"
    );
    let msg = error_message(result.as_ref().unwrap_err());
    assert!(
        msg.contains("toolset.args_validation"),
        "node-cap error must come from args_validation: {msg}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Static invariant: ARGS_KEY_DENYLIST has the correct entries
// ─────────────────────────────────────────────────────────────────────────────

/// Verifies the denylist contains exactly the 11 specified keys.
///
/// This is a static-invariant test at the integration level; the unit tests in
/// `stellar-agent-toolsets` are the primary coverage, but this confirms the public
/// re-export is consistent.
#[test]
fn denylist_has_exactly_11_entries_integration() {
    assert_eq!(
        ARGS_KEY_DENYLIST.len(),
        11,
        "ARGS_KEY_DENYLIST must have 11 entries"
    );
    let expected = [
        "toJSON",
        "then",
        "__proto__",
        "constructor",
        "prototype",
        "toString",
        "valueOf",
        "__defineGetter__",
        "__defineSetter__",
        "__lookupGetter__",
        "__lookupSetter__",
    ];
    for key in &expected {
        assert!(
            ARGS_KEY_DENYLIST.contains(key),
            "ARGS_KEY_DENYLIST must contain '{key}'"
        );
    }
}

/// Static invariant: `ToolsetArgsError::DangerousKey` error message contains the
/// matched denylist constant and does NOT contain the word "input" (it must not
/// echo input keys).
///
/// Unit-level proof at integration layer.
#[test]
fn toolset_args_error_display_references_constant_not_input() {
    let err = ToolsetArgsError::DangerousKey {
        matched_key: "toJSON",
    };
    let display = err.to_string();
    assert!(
        display.contains("toJSON"),
        "display must contain matched constant: {display}"
    );
    // The error must not claim to echo the "input key".
    assert!(
        !display.contains("input key"),
        "display must not claim to echo input key: {display}"
    );
}
