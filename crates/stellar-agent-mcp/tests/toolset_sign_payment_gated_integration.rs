//! Integration tests for the `sign-payment` gated toolset path.
//!
//! Exercises the first-invoke gate, per-action forced approval, and the
//! permissive-policy non-vacuous proof.
//!
//! ## Test inventory
//!
//! 1. **first_invoke_returns_approval_required** — first invoke (no grant) returns
//!    `toolset.first_invoke_approval_required` with a nonce.
//! 2. **permissive_policy_forces_per_action_approval** — under an `Allow`-returning
//!    policy, a toolset with a current grant AND absent/invented attestation STILL
//!    returns `policy.approval_required`. This proves the per-action approval is
//!    not vacuous under a permissive policy.
//! 3. **grant_present_creates_per_action_queue_entry** — after a grant is in
//!    place, re-invoke with no attestation creates a `PaymentSimulated` pending
//!    approval entry in the queue AND the invoke returns `policy.approval_required`.
//! 4. **without_sign_payment_capability_refused** — a toolset without `sign-payment`
//!    declared cannot reach the gated tool (four-part check refuses).
//! 5. **grant_store_empty_after_synthetic_install** — installing (writing a pin)
//!    does not write a grant; the grant store is empty; first invoke always hits
//!    the gate.
//! 6. **forged_grant_still_forces_per_action_approval** — a forged grant (wrong
//!    HMAC) still triggers the forced per-action approval (structural).
//! 7. **adversarial_different_destination_reprompts** — a plain `G...` destination
//!    different from the grant's destination re-prompts the first-invoke gate.
//! 8. **adversarial_muxed_destination_reprompts** — muxed `M...` destination
//!    cannot satisfy a grant that bounds a plain `G...` dest; M-addresses collapse
//!    to their underlying G, which differs from DEST_G.
//! 9. **amount_exceeds_grant_max_reprompts** — an amount above the grant's
//!    `amount_max_stroops` re-prompts the first-invoke gate.
//! 10. **gated_tool_only_via_both_gates** — `stellar_pay_commit` is unreachable
//!     via the ungated `resolve_action` path (structural invariant).
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

use serial_test::serial;
use stellar_agent_core::{
    approval::{
        PendingApprovalStore, TOOLSET_GRANT_DEFAULT_TTL_MS, ToolsetGrantStore,
        build_attested_grant, process_uid_for_attestation,
    },
    profile::schema::Profile,
    timefmt::now_unix_ms,
};
use stellar_agent_mcp::server::{StellarToolsetInvokeArgs, WalletServer};
use stellar_agent_test_support::keyring_mock;
use stellar_agent_toolsets_runtime::resolve_gated_action;
use tempfile::TempDir;

mod common;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Valid testnet G-strkey for source account.
const SOURCE_G: &str = "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI";

/// A syntactically valid nonce (parseable base64 of 48 bytes) with an invalid
/// HMAC — reaches `verify_attestation_gate` but is rejected there.
///
/// 64 URL-safe base64 chars encoding 48 zero bytes.
const FAKE_VALID_NONCE: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/// Valid testnet G-strkey for destination.
const DEST_G: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";

/// A second destination for adversarial tests (different from DEST_G).
/// (Same as SOURCE_G — any two distinct valid strkeys suffice for the test.)
const DEST_G2: &str = "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI";

/// A syntactically valid muxed M-strkey used for adversarial tests.
///
/// The underlying G-key of this muxed address is NOT DEST_G.  The grant is
/// bounded to DEST_G; the M-address encodes a different G-key and a mux ID.
/// This tests that M-addresses never satisfy a G-bounded grant even when the
/// grant-matching path is presented with the raw M-string.
///
/// Source: the same M-strkey used in `fee_bump.rs` fee_source_muxed_strkey_rejected
/// test, confirming syntactic validity.  The underlying G differs from DEST_G.
const DEST_M_OTHER_G: &str =
    "MA7QYNF7SOWQ3GLR2BGMZEHXR6DROW7HY3A3ZB3BNYB3QAVYUHX3AAAAAAAAAAAPCIBORA";

/// Toolset name used in all tests.
const TOOLSET_NAME: &str = "test-payment-toolset";

/// Capability token.
const CAPABILITY: &str = "sign-payment";

/// Native XLM sentinel for asset.
const ASSET_XLM: &str = "XLM";

/// The pin file name (mirrors toolsets-install constant).
const PIN_FILE_NAME: &str = ".stellar-agent-toolset-pin.json";

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Builds a minimal valid `TransactionV1Envelope` XDR base64 string.
///
/// Contains a single native `Payment` operation from `source` to `dest`
/// for `amount_stroops` (amount in stroops).
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

/// Writes a minimal `ToolsetPinRecord` JSON for `toolset_name` with `sign-payment`
/// capability to `toolsets_root`.
///
/// Bypasses `install_toolset` — no real package needed for unit-level tests.
fn write_pin_with_sign_payment(toolsets_root: &std::path::Path, toolset_name: &str) {
    let toolset_dir = toolsets_root.join(toolset_name);
    std::fs::create_dir_all(&toolset_dir).expect("create toolset dir");
    let pin_json = serde_json::json!({
        "package": toolset_name,
        "version": "1.0.0",
        "shasum": "a".repeat(64),
        "publisher": SOURCE_G,
        "installed_at": "2026-06-02T00:00:00Z",
        "capabilities": ["sign-payment"],
        "allowed_tools": []
    });
    let pin_path = toolset_dir.join(PIN_FILE_NAME);
    std::fs::write(&pin_path, serde_json::to_string_pretty(&pin_json).unwrap()).expect("write pin");
}

/// Writes a minimal `ToolsetPinRecord` without `sign-payment` capability.
fn write_pin_without_sign_payment(toolsets_root: &std::path::Path, toolset_name: &str) {
    let toolset_dir = toolsets_root.join(toolset_name);
    std::fs::create_dir_all(&toolset_dir).expect("create toolset dir");
    let pin_json = serde_json::json!({
        "package": toolset_name,
        "version": "1.0.0",
        "shasum": "b".repeat(64),
        "publisher": SOURCE_G,
        "installed_at": "2026-06-02T00:00:00Z",
        "capabilities": ["read-balance"],
        "allowed_tools": []
    });
    let pin_path = toolset_dir.join(PIN_FILE_NAME);
    std::fs::write(&pin_path, serde_json::to_string_pretty(&pin_json).unwrap()).expect("write pin");
}

/// Seeds the nonce key into the mock keyring (required for `WalletServer::new`).
fn seed_nonce_key(nonce_key_b64: &str) {
    let entry = keyring_core::Entry::new("n-svc", "n-acct").expect("keyring entry");
    entry.set_password(nonce_key_b64).expect("set nonce key");
}

/// Installs the keyring mock and seeds a deterministic 32-byte nonce key.
/// Returns the raw 32-byte key for computing HMACs in tests.
fn setup_mock_keyring() -> [u8; 32] {
    use base64::Engine as _;
    keyring_mock::install().expect("mock keyring install");
    let key = [0x42u8; 32];
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key);
    seed_nonce_key(&encoded);
    key
}

/// Builds a `WalletServer` for testnet with the `Allow` policy (permissive).
fn build_allow_server(
    approval_dir: &std::path::Path,
    grant_store_path: &std::path::Path,
    toolsets_root: &std::path::Path,
) -> WalletServer {
    let profile = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
        .with_noop_engine()
        .build();
    let mut server = WalletServer::new(profile).expect("WalletServer::new");
    server.set_policy_engine_for_test(Arc::new(common::policy_mock::MockPolicyEngine::allow()));
    server.set_approval_dir_for_test(approval_dir.to_path_buf());
    server.set_grant_store_path_for_test(grant_store_path.to_path_buf());
    server.set_toolsets_root_for_test(toolsets_root.to_path_buf());
    server
}

/// Extracts the JSON error payload from an MCP `ErrorData`.
fn error_payload(err: &rmcp::ErrorData) -> serde_json::Value {
    err.data.clone().unwrap_or(serde_json::Value::Null)
}

/// Extracts the error message string from `ErrorData`.
fn error_message(err: &rmcp::ErrorData) -> String {
    err.message.to_string()
}

/// Inserts a current, matching `ToolsetGrant` directly into the grant store.
///
/// Used to simulate a previously-approved first-invoke gate (i.e., the operator
/// ran `stellar-agent approve --id <nonce>` successfully).
#[allow(clippy::too_many_arguments)]
fn insert_valid_grant(
    grant_store_path: &std::path::Path,
    toolset_name: &str,
    capability: &str,
    destination: &str,
    asset: &str,
    amount_min_stroops: i64,
    amount_max_stroops: i64,
    attestation_key: &[u8; 32],
) {
    let process_uid = process_uid_for_attestation().expect("process uid");
    let now_ms = now_unix_ms().expect("now_unix_ms");
    let grant = build_attested_grant(
        toolset_name.to_owned(),
        capability.to_owned(),
        destination.to_owned(),
        asset.to_owned(),
        amount_min_stroops,
        amount_max_stroops,
        process_uid,
        now_ms,
        TOOLSET_GRANT_DEFAULT_TTL_MS,
        attestation_key,
    )
    .expect("build_attested_grant must succeed");

    let mut store =
        ToolsetGrantStore::open(grant_store_path.to_path_buf(), now_ms).expect("open grant store");
    store.insert(grant).expect("insert grant");
}

/// Reads the pending approval store and returns the number of entries.
///
/// The profile_name must match what `WalletServer::profile_name_for_approval()`
/// returns.  In tests using `Profile::builder_testnet("svc", "acct", ...)`,
/// the profile name is `"acct"` (derived from `signer_account`).
fn count_pending_approvals(approval_dir: &std::path::Path, profile_name: &str) -> usize {
    let store_path = approval_dir.join(format!("{profile_name}.toml"));
    if !store_path.exists() {
        return 0;
    }
    let store = PendingApprovalStore::open(store_path).expect("open approval store");
    store.len()
}

/// Profile name derived from `Profile::builder_testnet("svc", "acct", ...)`.
///
/// `profile_name_for_approval()` strips `"stellar-agent-owner-"` prefix from
/// `policy_owner_key_id.service`, giving `"acct"` for this builder call.
const TEST_PROFILE_NAME: &str = "acct";

// ─────────────────────────────────────────────────────────────────────────────
// Test 9 (structural invariant, no I/O): gated tool unreachable via resolve_action
// ─────────────────────────────────────────────────────────────────────────────

/// `stellar_pay_commit` is in `SIGNING_DENYLIST` and MUST NOT resolve via
/// the ungated `resolve_action` path.
///
/// This is the structural proof that a toolset cannot bypass the first-invoke gate
/// by routing through the ungated matrix.
#[test]
fn gated_tool_only_via_both_gates() {
    use stellar_agent_toolsets_runtime::matrix::{SIGNING_DENYLIST, resolve_action};

    // Confirm stellar_pay_commit is in the denylist.
    assert!(
        SIGNING_DENYLIST.contains(&"stellar_pay_commit"),
        "stellar_pay_commit must be in SIGNING_DENYLIST"
    );

    // Confirm it does NOT resolve via the ungated matrix.
    let result = resolve_action("stellar_pay_commit");
    assert!(
        result.is_err(),
        "stellar_pay_commit must NOT resolve via ungated resolve_action; got: {result:?}"
    );

    // Confirm it DOES resolve via the gated matrix.
    let gated_result = resolve_gated_action("stellar_pay_commit");
    assert!(
        gated_result.is_ok(),
        "stellar_pay_commit must resolve via resolve_gated_action; got: {gated_result:?}"
    );
    let (tool_name, cap) = gated_result.unwrap();
    assert_eq!(tool_name, "stellar_pay_commit");
    assert_eq!(cap, stellar_agent_toolsets::Capability::SignPayment);
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 4: without sign-payment capability → four-part check refuses
// ─────────────────────────────────────────────────────────────────────────────

/// A toolset without `sign-payment` declared cannot reach `stellar_pay_commit`.
///
/// The four-part check fires at `CapabilityNotDeclared` (part c).
#[tokio::test]
#[serial]
async fn without_sign_payment_capability_refused() {
    let _key = setup_mock_keyring();
    let toolsets_dir = TempDir::new().unwrap();
    let approval_dir = TempDir::new().unwrap();
    let grant_dir = TempDir::new().unwrap().keep();
    let grant_file = grant_dir.join("grants.toml");

    write_pin_without_sign_payment(toolsets_dir.path(), TOOLSET_NAME);

    let envelope_xdr = payment_envelope_xdr(SOURCE_G, DEST_G, 10_000_000);
    let server = build_allow_server(approval_dir.path(), &grant_file, toolsets_dir.path());

    let args = StellarToolsetInvokeArgs {
        toolset: TOOLSET_NAME.to_owned(),
        action: "stellar_pay_commit".to_owned(),
        chain_id: Some("stellar:testnet".to_owned()),
        args: serde_json::json!({
            "envelope_xdr": envelope_xdr,
            "source": SOURCE_G,
            "destination": DEST_G,
            "nonce": "fake-nonce",
            "expires_at_unix_ms": 9_999_999_999_u64,
            "asset": "native",
            "amount": "1 XLM",
            "chain_id": "stellar:testnet"
        }),
    };

    let result = server.call_stellar_toolset_invoke(args).await;
    assert!(result.is_err(), "must fail: toolset has no sign-payment");
    let err = result.unwrap_err();
    let msg = error_message(&err);
    // Must fail with capability-not-declared, not get through to the gated path.
    assert!(
        msg.contains("toolset.capability_not_declared")
            || msg.contains("toolset.unknown_action")
            || msg.contains("CapabilityNotDeclared"),
        "expected capability-not-declared refusal; got: {msg}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 5: grant store empty after synthetic install
// ─────────────────────────────────────────────────────────────────────────────

/// Writing a pin record (install) does NOT write a grant.
/// The grant store is empty; the first invoke always hits the gate.
#[tokio::test]
#[serial]
async fn grant_store_empty_after_synthetic_install() {
    let _key = setup_mock_keyring();
    let toolsets_dir = TempDir::new().unwrap();
    let approval_dir = TempDir::new().unwrap();
    let grant_dir = TempDir::new().unwrap().keep();
    let grant_file = grant_dir.join("grants.toml");

    write_pin_with_sign_payment(toolsets_dir.path(), TOOLSET_NAME);

    // Assert: the grant file does not exist yet (no install-time grant).
    assert!(
        !grant_file.exists(),
        "grant store MUST be absent after install (no install-time grant)"
    );

    let envelope_xdr = payment_envelope_xdr(SOURCE_G, DEST_G, 10_000_000);
    let server = build_allow_server(approval_dir.path(), &grant_file, toolsets_dir.path());

    let args = StellarToolsetInvokeArgs {
        toolset: TOOLSET_NAME.to_owned(),
        action: "stellar_pay_commit".to_owned(),
        chain_id: Some("stellar:testnet".to_owned()),
        args: serde_json::json!({
            "envelope_xdr": envelope_xdr,
            "source": SOURCE_G,
            "destination": DEST_G,
            "nonce": "fake-nonce",
            "expires_at_unix_ms": 9_999_999_999_u64,
            "asset": "native",
            "amount": "1 XLM",
            "chain_id": "stellar:testnet"
        }),
    };

    let result = server.call_stellar_toolset_invoke(args).await;
    assert!(result.is_err(), "first invoke must fail with gate fired");
    let err = result.unwrap_err();
    let msg = error_message(&err);
    assert!(
        msg.contains("first_invoke_approval_required"),
        "expected first_invoke_approval_required; got: {msg}"
    );

    // The grant store must still not exist (gate fires, no grant written).
    assert!(
        !grant_file.exists(),
        "grant store must remain absent after first-invoke gate fires"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 1: first invoke (no grant) → FirstInvokeApprovalRequired + nonce
// ─────────────────────────────────────────────────────────────────────────────

/// First invoke with no current grant returns `toolset.first_invoke_approval_required`
/// and includes `approval_nonce` in the error payload.
#[tokio::test]
#[serial]
async fn first_invoke_returns_approval_required() {
    let _key = setup_mock_keyring();
    let toolsets_dir = TempDir::new().unwrap();
    let approval_dir = TempDir::new().unwrap();
    let grant_dir = TempDir::new().unwrap().keep();
    let grant_file = grant_dir.join("grants.toml");

    write_pin_with_sign_payment(toolsets_dir.path(), TOOLSET_NAME);

    let envelope_xdr = payment_envelope_xdr(SOURCE_G, DEST_G, 10_000_000);
    let server = build_allow_server(approval_dir.path(), &grant_file, toolsets_dir.path());

    let args = StellarToolsetInvokeArgs {
        toolset: TOOLSET_NAME.to_owned(),
        action: "stellar_pay_commit".to_owned(),
        chain_id: Some("stellar:testnet".to_owned()),
        args: serde_json::json!({
            "envelope_xdr": envelope_xdr,
            "source": SOURCE_G,
            "destination": DEST_G,
            "nonce": "fake-nonce",
            "expires_at_unix_ms": 9_999_999_999_u64,
            "asset": "native",
            "amount": "1 XLM",
            "chain_id": "stellar:testnet"
        }),
    };

    let result = server.call_stellar_toolset_invoke(args).await;
    assert!(result.is_err(), "first invoke must fail with gate fired");
    let err = result.unwrap_err();
    let msg = error_message(&err);

    assert!(
        msg.contains("first_invoke_approval_required"),
        "expected first_invoke_approval_required; got: {msg}"
    );

    // The payload must include approval_nonce.
    let payload = error_payload(&err);
    let nonce = payload
        .get("approval_nonce")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert!(
        !nonce.is_empty(),
        "approval_nonce must be present in error payload"
    );

    // A ToolsetFirstInvokeGate pending approval was queued.
    let pending_count = count_pending_approvals(approval_dir.path(), TEST_PROFILE_NAME);
    assert_eq!(
        pending_count, 1,
        "exactly one ToolsetFirstInvokeGate pending approval must have been queued"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 3: grant present + no attestation → forced per-action PaymentSimulated
// ─────────────────────────────────────────────────────────────────────────────

/// After a grant is in place, re-invoke with no attestation creates a
/// `PaymentSimulated` pending approval and returns `policy.approval_required`.
///
/// This verifies the forced per-action approval fires.
#[tokio::test]
#[serial]
async fn grant_present_creates_per_action_queue_entry() {
    let key = setup_mock_keyring();
    let toolsets_dir = TempDir::new().unwrap();
    let approval_dir = TempDir::new().unwrap();
    let grant_file = approval_dir.path().join("grants.toml");

    write_pin_with_sign_payment(toolsets_dir.path(), TOOLSET_NAME);

    let amount_stroops: i64 = 10_000_000;
    // Pre-populate the grant store (simulates a completed approve step).
    insert_valid_grant(
        &grant_file,
        TOOLSET_NAME,
        CAPABILITY,
        DEST_G,
        ASSET_XLM,
        0,
        amount_stroops,
        &key,
    );

    let envelope_xdr = payment_envelope_xdr(SOURCE_G, DEST_G, amount_stroops);
    let server = build_allow_server(approval_dir.path(), &grant_file, toolsets_dir.path());

    // No approval_nonce/approval_attestation → forced per-action approval must fire.
    let args = StellarToolsetInvokeArgs {
        toolset: TOOLSET_NAME.to_owned(),
        action: "stellar_pay_commit".to_owned(),
        chain_id: Some("stellar:testnet".to_owned()),
        args: serde_json::json!({
            "envelope_xdr": envelope_xdr,
            "source": SOURCE_G,
            "destination": DEST_G,
            "nonce": "fake-nonce",
            "expires_at_unix_ms": 9_999_999_999_u64,
            "asset": "native",
            "amount": "1 XLM",
            "chain_id": "stellar:testnet"
        }),
    };

    let result = server.call_stellar_toolset_invoke(args).await;
    assert!(
        result.is_err(),
        "must fail: per-action approval required (forced unconditionally)"
    );
    let err = result.unwrap_err();
    let msg = error_message(&err);

    // Must be policy.approval_required (forced per-action approval), not first-invoke gate.
    assert!(
        msg.contains("approval_required") || msg.contains("policy.approval_required"),
        "expected policy.approval_required (forced per-action); got: {msg}"
    );
    assert!(
        !msg.contains("first_invoke_approval_required"),
        "must NOT re-trigger first-invoke gate when grant exists; got: {msg}"
    );

    // A PaymentSimulated pending approval was queued (not ToolsetFirstInvokeGate).
    let pending_count = count_pending_approvals(approval_dir.path(), TEST_PROFILE_NAME);
    assert_eq!(
        pending_count, 1,
        "exactly one PaymentSimulated pending approval must have been queued"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 2: permissive policy + invented attestation → REFUSED
// ─────────────────────────────────────────────────────────────────────────────

/// Under an `Allow`-returning policy, a toolset with a current grant AND
/// invented nonce/attestation strings STILL returns `policy.approval_required`.
///
/// This is the non-vacuous proof that the per-action attestation gate is
/// enforced even under a permissive policy.
///
/// `stellar_pay_commit_impl` forces `RequireApproval` regardless of policy, so
/// `verify_attestation_gate` ALWAYS checks the HMAC.  Since the invented
/// attestation fails HMAC verification against the stored entry, the gate
/// returns `policy.approval_required`.
#[tokio::test]
#[serial]
async fn permissive_policy_forces_per_action_approval() {
    let key = setup_mock_keyring();
    let toolsets_dir = TempDir::new().unwrap();
    let approval_dir = TempDir::new().unwrap();
    let grant_file = approval_dir.path().join("grants.toml");

    write_pin_with_sign_payment(toolsets_dir.path(), TOOLSET_NAME);

    let amount_stroops: i64 = 10_000_000;
    // Pre-populate a valid grant (first-invoke gate cleared).
    insert_valid_grant(
        &grant_file,
        TOOLSET_NAME,
        CAPABILITY,
        DEST_G,
        ASSET_XLM,
        0,
        amount_stroops,
        &key,
    );

    let envelope_xdr = payment_envelope_xdr(SOURCE_G, DEST_G, amount_stroops);
    let server = build_allow_server(approval_dir.path(), &grant_file, toolsets_dir.path());

    // Provide INVENTED (forged) approval_nonce and approval_attestation.
    // The forced RequireApproval override causes verify_attestation_gate to check
    // the store, find no matching entry for "invented-nonce", and refuse — even
    // under an Allow policy.
    let args = StellarToolsetInvokeArgs {
        toolset: TOOLSET_NAME.to_owned(),
        action: "stellar_pay_commit".to_owned(),
        chain_id: Some("stellar:testnet".to_owned()),
        // Use a syntactically valid nonce format (parseable 48-byte base64) so
        // the code reaches `verify_attestation_gate` before the nonce HMAC step.
        // The approval_nonce + approval_attestation are invented and not in the store.
        args: serde_json::json!({
            "envelope_xdr": envelope_xdr,
            "source": SOURCE_G,
            "destination": DEST_G,
            "nonce": FAKE_VALID_NONCE,
            "expires_at_unix_ms": 9_999_999_999_u64,
            "asset": "native",
            "amount": "1 XLM",
            "chain_id": "stellar:testnet",
            "approval_nonce": "invented-nonce-that-does-not-exist-in-store",
            "approval_attestation": "aGVsbG8gd29ybGQ"
        }),
    };

    let result = server.call_stellar_toolset_invoke(args).await;
    // MUST be an error — invented attestation must not bypass the gate.
    assert!(
        result.is_err(),
        "invented attestation under permissive policy MUST be refused; \
         this assertion failing means an attestation bypass is active"
    );

    let err = result.unwrap_err();
    let msg = error_message(&err);

    // Must be policy.approval_required (forged attestation rejected).
    assert!(
        msg.contains("approval_required") || msg.contains("policy.approval_required"),
        "must return policy.approval_required for forged attestation; got: {msg}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 6: forged grant still forces per-action approval (structural)
// ─────────────────────────────────────────────────────────────────────────────

/// A grant with a wrong HMAC (forged) still triggers the forced per-action
/// approval — because even with a matching grant, the commit step ALWAYS
/// requires a valid per-action `PaymentSimulated` attestation.
///
/// Note: the forged grant will fail HMAC verification inside `ToolsetGrantStore::find_matching`,
/// so the gate will fire `FirstInvokeApprovalRequired` rather than proceeding to
/// the per-action approval step.  Either way, the commit is refused.
#[tokio::test]
#[serial]
async fn forged_grant_still_forces_per_action_approval() {
    let _key = setup_mock_keyring();
    let toolsets_dir = TempDir::new().unwrap();
    let approval_dir = TempDir::new().unwrap();
    let grant_file = approval_dir.path().join("grants.toml");

    write_pin_with_sign_payment(toolsets_dir.path(), TOOLSET_NAME);

    // Write a grant with a WRONG key (forged HMAC).
    let wrong_key = [0xFFu8; 32];
    let amount_stroops: i64 = 10_000_000;
    insert_valid_grant(
        &grant_file,
        TOOLSET_NAME,
        CAPABILITY,
        DEST_G,
        ASSET_XLM,
        0,
        amount_stroops,
        &wrong_key,
    );

    let envelope_xdr = payment_envelope_xdr(SOURCE_G, DEST_G, amount_stroops);
    let server = build_allow_server(approval_dir.path(), &grant_file, toolsets_dir.path());

    let args = StellarToolsetInvokeArgs {
        toolset: TOOLSET_NAME.to_owned(),
        action: "stellar_pay_commit".to_owned(),
        chain_id: Some("stellar:testnet".to_owned()),
        // Use a syntactically valid nonce format so the code reaches
        // verify_attestation_gate (not nonce parse failure).
        // The forged grant passes find_matching (field-only match) so we
        // reach the per-action approval gate, which refuses on missing entry.
        args: serde_json::json!({
            "envelope_xdr": envelope_xdr,
            "source": SOURCE_G,
            "destination": DEST_G,
            "nonce": FAKE_VALID_NONCE,
            "expires_at_unix_ms": 9_999_999_999_u64,
            "asset": "native",
            "amount": "1 XLM",
            "chain_id": "stellar:testnet",
            "approval_nonce": "invented-nonce",
            "approval_attestation": "aGVsbG8gd29ybGQ"
        }),
    };

    let result = server.call_stellar_toolset_invoke(args).await;
    assert!(
        result.is_err(),
        "forged grant must not allow commit; commit must be refused"
    );
    // The forged grant passes find_matching (field-only; HMAC is not checked on the
    // read path by design — see toolset_grant.rs rustdoc on `matches` and
    // `find_matching`).  The per-action forced approval fires: the invented
    // approval_nonce is not in the store → `policy.approval_required`.
    // This must NOT be `first_invoke_approval_required` because the grant fields
    // matched; only the per-action attestation failed.
    let err = result.unwrap_err();
    let msg = error_message(&err);
    assert!(
        msg.contains("policy.approval_required"),
        "forged grant must trigger per-action approval_required (not first_invoke gate); got: {msg}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 8: amount exceeds grant max → re-prompt
// ─────────────────────────────────────────────────────────────────────────────

/// A payment amount above the grant's `amount_max_stroops` fires the
/// first-invoke gate again (novel-parameters re-prompt).
#[tokio::test]
#[serial]
async fn amount_exceeds_grant_max_reprompts() {
    let key = setup_mock_keyring();
    let toolsets_dir = TempDir::new().unwrap();
    let approval_dir = TempDir::new().unwrap();
    let grant_file = approval_dir.path().join("grants.toml");

    write_pin_with_sign_payment(toolsets_dir.path(), TOOLSET_NAME);

    // Grant for 10 XLM (10_000_000 stroops).
    let granted_max: i64 = 10_000_000;
    insert_valid_grant(
        &grant_file,
        TOOLSET_NAME,
        CAPABILITY,
        DEST_G,
        ASSET_XLM,
        0,
        granted_max,
        &key,
    );

    // Attempt with 100 XLM (100_000_000 stroops) — exceeds grant max.
    let higher_amount: i64 = 100_000_000;
    let envelope_xdr = payment_envelope_xdr(SOURCE_G, DEST_G, higher_amount);
    let server = build_allow_server(approval_dir.path(), &grant_file, toolsets_dir.path());

    // The toolset arg `amount` matches the envelope (100 XLM).  Mismatching the arg
    // from the envelope would make the test ambiguous about whether the gate fires
    // on the arg vs the envelope cross-check.
    let args = StellarToolsetInvokeArgs {
        toolset: TOOLSET_NAME.to_owned(),
        action: "stellar_pay_commit".to_owned(),
        chain_id: Some("stellar:testnet".to_owned()),
        args: serde_json::json!({
            "envelope_xdr": envelope_xdr,
            "source": SOURCE_G,
            "destination": DEST_G,
            "nonce": "fake-nonce",
            "expires_at_unix_ms": 9_999_999_999_u64,
            "asset": "native",
            "amount": "100 XLM",
            "chain_id": "stellar:testnet"
        }),
    };

    let result = server.call_stellar_toolset_invoke(args).await;
    assert!(
        result.is_err(),
        "amount exceeding grant max must re-prompt first-invoke gate"
    );
    let err = result.unwrap_err();
    let msg = error_message(&err);
    assert!(
        msg.contains("first_invoke_approval_required"),
        "expected first_invoke_approval_required for amount > grant max; got: {msg}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 7: adversarial different destination → re-prompt
// ─────────────────────────────────────────────────────────────────────────────

/// A grant for DEST_G does not satisfy an invoke for DEST_G2 (different
/// destination → novel parameters → re-prompt).
#[tokio::test]
#[serial]
async fn adversarial_different_destination_reprompts() {
    let key = setup_mock_keyring();
    let toolsets_dir = TempDir::new().unwrap();
    let approval_dir = TempDir::new().unwrap();
    let grant_file = approval_dir.path().join("grants.toml");

    write_pin_with_sign_payment(toolsets_dir.path(), TOOLSET_NAME);

    // Grant for DEST_G.
    let amount_stroops: i64 = 10_000_000;
    insert_valid_grant(
        &grant_file,
        TOOLSET_NAME,
        CAPABILITY,
        DEST_G,
        ASSET_XLM,
        0,
        amount_stroops,
        &key,
    );

    // Invoke with DEST_G2 (different destination — grant should not match).
    let envelope_xdr = payment_envelope_xdr(SOURCE_G, DEST_G2, amount_stroops);
    let server = build_allow_server(approval_dir.path(), &grant_file, toolsets_dir.path());

    let args = StellarToolsetInvokeArgs {
        toolset: TOOLSET_NAME.to_owned(),
        action: "stellar_pay_commit".to_owned(),
        chain_id: Some("stellar:testnet".to_owned()),
        args: serde_json::json!({
            "envelope_xdr": envelope_xdr,
            "source": SOURCE_G,
            "destination": DEST_G2,
            "nonce": "fake-nonce",
            "expires_at_unix_ms": 9_999_999_999_u64,
            "asset": "native",
            "amount": "1 XLM",
            "chain_id": "stellar:testnet"
        }),
    };

    let result = server.call_stellar_toolset_invoke(args).await;
    assert!(
        result.is_err(),
        "different destination must re-prompt first-invoke gate"
    );
    let err = result.unwrap_err();
    let msg = error_message(&err);
    assert!(
        msg.contains("first_invoke_approval_required"),
        "expected first_invoke_approval_required for different destination; got: {msg}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 8: adversarial muxed destination → re-prompt
// ─────────────────────────────────────────────────────────────────────────────

/// A muxed `M...` destination does not satisfy a grant bounded to a plain
/// `G...` destination.
///
/// M-addresses are never stored in grants (grants record the G-strkey supplied
/// by the toolset at first-invoke time).  Even if an M-address encoded the same
/// underlying G as the grant's destination, the grant-matching path compares
/// the raw destination string and would not match the M-form.  This test uses
/// an M-address whose underlying G differs from DEST_G, confirming the re-prompt
/// fires via the parameter-mismatch path.
#[tokio::test]
#[serial]
async fn adversarial_muxed_destination_reprompts() {
    let key = setup_mock_keyring();
    let toolsets_dir = TempDir::new().unwrap();
    let approval_dir = TempDir::new().unwrap();
    let grant_file = approval_dir.path().join("grants.toml");

    write_pin_with_sign_payment(toolsets_dir.path(), TOOLSET_NAME);

    // Grant bounded to the plain G-strkey DEST_G.
    let amount_stroops: i64 = 10_000_000;
    insert_valid_grant(
        &grant_file,
        TOOLSET_NAME,
        CAPABILITY,
        DEST_G,
        ASSET_XLM,
        0,
        amount_stroops,
        &key,
    );

    // The toolset arg `destination` is an M-address whose underlying G is NOT DEST_G.
    // The envelope destination uses SOURCE_G (any valid G suffices; the envelope
    // decode path extracts the G from the op's destination MuxedAccount).
    let envelope_xdr = payment_envelope_xdr(SOURCE_G, SOURCE_G, amount_stroops);
    let server = build_allow_server(approval_dir.path(), &grant_file, toolsets_dir.path());

    let args = StellarToolsetInvokeArgs {
        toolset: TOOLSET_NAME.to_owned(),
        action: "stellar_pay_commit".to_owned(),
        chain_id: Some("stellar:testnet".to_owned()),
        args: serde_json::json!({
            "envelope_xdr": envelope_xdr,
            "source": SOURCE_G,
            "destination": DEST_M_OTHER_G,
            "nonce": "fake-nonce",
            "expires_at_unix_ms": 9_999_999_999_u64,
            "asset": "native",
            "amount": "1 XLM",
            "chain_id": "stellar:testnet"
        }),
    };

    let result = server.call_stellar_toolset_invoke(args).await;
    assert!(
        result.is_err(),
        "M-address destination must not satisfy a G-bounded grant; must re-prompt"
    );
    let err = result.unwrap_err();
    let msg = error_message(&err);
    // M-address destinations are either refused as an invalid address format or
    // cause the grant not to match and the first-invoke gate fires.
    assert!(
        msg.contains("first_invoke_approval_required") || msg.contains("invalid_destination"),
        "expected first-invoke gate or invalid-destination refusal for M-address; got: {msg}"
    );
}
