//! Testnet acceptance tests for the `sign-payment` gated toolset path.
//!
//! Exercises the first-invoke gate, the forced per-action approval, and the
//! gated-path build/simulate step against a live testnet endpoint. The full
//! on-chain SUBMIT is NOT automated here — it is the operator's pre-seal binary
//! smoke (see the # Acceptance criteria note below).
//!
//! Gated behind the `testnet-acceptance` feature flag:
//!
//! ```text
//! cargo test -p stellar-agent-mcp --features testnet-acceptance \
//!   --test toolset_sign_payment_gated_testnet_acceptance
//! ```
//!
//! Under default `cargo test` (no `--features testnet-acceptance`), this file
//! compiles but all tests are compiled-out via `#[cfg(feature = "testnet-acceptance")]`.
//!
//! # Acceptance criteria
//!
//! - First invoke (no grant) returns `toolset.first_invoke_approval_required`.
//! - After grant persisted (simulated approve), re-invoke with no attestation
//!   returns `policy.approval_required` (forced per-action — NOT first-invoke gate).
//! - The gated path reaches `stellar_pay` (simulate step) successfully — testnet
//!   RPC confirms account exists and builds a valid envelope.
//!
//! The full on-chain submit with per-action approval requires wiring the
//! `stellar_pay` simulate output (nonce/envelope) into the commit step with a
//! properly-minted approval.  This is exercised by the operator manually with the
//! real CLI; the automated acceptance here validates the first-invoke gate and the
//! forced per-action approval end-to-end against a live testnet account.

#![cfg(feature = "testnet-acceptance")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics and unwraps are acceptable in testnet acceptance tests"
)]

use base64::Engine as _;
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use serial_test::serial;
use stellar_agent_core::{
    approval::{
        PendingApprovalStore, TOOLSET_GRANT_DEFAULT_TTL_MS, build_attested_grant,
        process_uid_for_attestation,
    },
    profile::schema::Profile,
    timefmt::now_unix_ms,
};
use stellar_agent_mcp::server::{StellarToolsetInvokeArgs, WalletServer};
use stellar_agent_network::{StellarRpcClient, fetch_account};
use stellar_agent_test_support::keyring_mock;
use tempfile::TempDir;
use zeroize::Zeroizing;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";
const TESTNET_FRIENDBOT_URL: &str = "https://friendbot.stellar.org";
const TESTNET_CHAIN_ID: &str = "stellar:testnet";
const FEE_STROOPS: u32 = 100_000;

// 1 XLM = 10_000_000 stroops
const SELF_PAYMENT_STROOPS: i64 = 10_000_000;

const TOOLSET_NAME: &str = "gated-testnet-toolset";
const CAPABILITY: &str = "sign-payment";
const ASSET_XLM: &str = "XLM";
const PIN_FILE_NAME: &str = ".stellar-agent-toolset-pin.json";

// Syntactically valid 48-byte base64 nonce (HMAC will fail, which is expected
// before attestation is verified).
const FAKE_VALID_NONCE: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn fresh_keypair() -> (String, Zeroizing<[u8; 32]>) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let g_strkey: String = stellar_strkey::ed25519::PublicKey(verifying_key.to_bytes())
        .to_string()
        .as_str()
        .to_owned();
    let seed = Zeroizing::new(signing_key.to_bytes());
    (g_strkey, seed)
}

async fn fund_via_friendbot(g_strkey: &str) {
    let url = format!("{TESTNET_FRIENDBOT_URL}?addr={g_strkey}");
    let resp = reqwest::get(&url)
        .await
        .expect("Friendbot HTTP request must succeed");
    assert!(
        resp.status().is_success(),
        "Friendbot must return 200 for {g_strkey}; got {}",
        resp.status()
    );
}

fn build_test_server(
    g_strkey: &str,
    seed: &Zeroizing<[u8; 32]>,
    attestation_key: &[u8; 32],
    approval_dir: &std::path::Path,
    grant_store_path: &std::path::Path,
    toolsets_root: &std::path::Path,
) -> WalletServer {
    keyring_mock::install().expect("mock keyring store init");

    let mut profile =
        Profile::builder_testnet("stellar-agent", g_strkey, "stellar-agent-nonce", g_strkey)
            .with_noop_engine()
            .build();
    profile.rpc_url = TESTNET_RPC_URL.to_owned();

    // Store signing key in mock keyring.
    let signer_ref = &profile.mcp_signer_default;
    let entry =
        keyring_core::Entry::new(&signer_ref.service, &signer_ref.account).expect("keyring entry");
    let s_strkey = stellar_strkey::ed25519::PrivateKey::from_payload(seed.as_ref())
        .expect("32-byte seed must encode as S-strkey")
        .as_unredacted()
        .to_string();
    entry.set_password(&s_strkey).expect("set signing key");

    // Store nonce key in mock keyring.
    let nonce_ref = &profile.mcp_nonce_key_alias;
    let nonce_entry = keyring_core::Entry::new(&nonce_ref.service, &nonce_ref.account)
        .expect("nonce keyring entry");
    let nonce_key_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x42u8; 32]);
    nonce_entry
        .set_password(&nonce_key_b64)
        .expect("set nonce key");

    // Store attestation key in mock keyring.
    let attest_ref = &profile.attestation_key_id;
    let attest_entry = keyring_core::Entry::new(&attest_ref.service, &attest_ref.account)
        .expect("attestation keyring entry");
    let attest_key_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(attestation_key);
    attest_entry
        .set_password(&attest_key_b64)
        .expect("set attestation key");

    let mut server = WalletServer::new(profile).expect("WalletServer::new");
    server.set_approval_dir_for_test(approval_dir.to_path_buf());
    server.set_grant_store_path_for_test(grant_store_path.to_path_buf());
    server.set_toolsets_root_for_test(toolsets_root.to_path_buf());
    server
}

fn write_toolset_pin(toolsets_root: &std::path::Path, toolset_name: &str, g_strkey: &str) {
    let toolset_dir = toolsets_root.join(toolset_name);
    std::fs::create_dir_all(&toolset_dir).expect("create toolset dir");
    let pin_json = serde_json::json!({
        "package": toolset_name,
        "version": "1.0.0",
        "shasum": "a".repeat(64),
        "publisher": g_strkey,
        "installed_at": "2026-06-02T00:00:00Z",
        "capabilities": ["sign-payment"],
        "allowed_tools": []
    });
    let pin_path = toolset_dir.join(PIN_FILE_NAME);
    std::fs::write(&pin_path, serde_json::to_string_pretty(&pin_json).unwrap()).expect("write pin");
}

/// Builds a minimal payment XDR envelope for testing (no live RPC needed).
fn build_payment_xdr(source: &str, dest: &str, amount_stroops: i64) -> String {
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
        fee: FEE_STROOPS,
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
    .expect("XDR encode")
}

// ─────────────────────────────────────────────────────────────────────────────
// First-invoke gate + forced per-action approval on testnet account
// ─────────────────────────────────────────────────────────────────────────────

/// Validates that the first-invoke gate fires and that the forced per-action
/// approval fires after a grant is in place, against a live testnet account.
///
/// Uses a fresh Friendbot-funded keypair for isolation.  The account is used
/// as both source and destination (self-payment) so a single keypair suffices.
#[tokio::test]
#[serial]
async fn gated_toolset_first_invoke_and_forced_per_action_testnet() {
    let (g_strkey, seed) = fresh_keypair();
    fund_via_friendbot(&g_strkey).await;

    let attestation_key = [0x42u8; 32];

    let approval_dir = TempDir::new().unwrap();
    let grant_file = approval_dir.path().join("grants.toml");
    let toolsets_dir = TempDir::new().unwrap();

    write_toolset_pin(toolsets_dir.path(), TOOLSET_NAME, &g_strkey);

    let server = build_test_server(
        &g_strkey,
        &seed,
        &attestation_key,
        approval_dir.path(),
        &grant_file,
        toolsets_dir.path(),
    );

    // Use the funded account as source AND destination (self-payment).
    let envelope_xdr = build_payment_xdr(&g_strkey, &g_strkey, SELF_PAYMENT_STROOPS);
    let profile_name = server.profile_name_for_approval();

    // ── First invoke (no grant) → gate fires ──────────────────────────────
    let args = StellarToolsetInvokeArgs {
        toolset: TOOLSET_NAME.to_owned(),
        action: "stellar_pay_commit".to_owned(),
        chain_id: Some(TESTNET_CHAIN_ID.to_owned()),
        args: serde_json::json!({
            "envelope_xdr": &envelope_xdr,
            "source": &g_strkey,
            "destination": &g_strkey,
            "nonce": FAKE_VALID_NONCE,
            "expires_at_unix_ms": 9_999_999_999_u64,
            "asset": "native",
            "amount": "1 XLM",
            "chain_id": TESTNET_CHAIN_ID
        }),
    };

    let result1 = server.call_stellar_toolset_invoke(args).await;
    assert!(result1.is_err(), "first invoke must fail with gate error");
    let err1 = result1.unwrap_err();
    assert!(
        err1.message.contains("first_invoke_approval_required"),
        "expected first_invoke_approval_required on testnet; got: {}",
        err1.message
    );

    // Extract the approval nonce from the payload.
    let payload = err1
        .data
        .as_ref()
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    let gate_nonce = payload
        .get("approval_nonce")
        .and_then(|v| v.as_str())
        .expect("approval_nonce must be present in first-invoke gate error payload");

    // ── Simulate approve: build grant, persist to grant store ─────────────
    // (mirrors the operator running `stellar-agent approve --id <nonce>`.)
    let process_uid = process_uid_for_attestation().expect("process uid");
    let now_ms = now_unix_ms().expect("now_unix_ms");
    let grant = build_attested_grant(
        TOOLSET_NAME.to_owned(),
        CAPABILITY.to_owned(),
        g_strkey.clone(),
        ASSET_XLM.to_owned(),
        0_i64,
        SELF_PAYMENT_STROOPS,
        process_uid.clone(),
        now_ms,
        TOOLSET_GRANT_DEFAULT_TTL_MS,
        &attestation_key,
    )
    .expect("build_attested_grant");

    {
        let mut grant_store =
            stellar_agent_core::approval::ToolsetGrantStore::open(grant_file.clone(), now_ms)
                .expect("open grant store");
        grant_store.insert(grant).expect("insert grant");
    }

    // Mirror the real CLI approve step: after persisting the grant, consume the
    // first-invoke gate pending approval queued by the first invoke. The CLI
    // approve path removes the entry via `store.remove(&entry.approval_nonce)`
    // after recording the first-invoke grant; simulating approval by writing the
    // grant directly would otherwise leave the `ToolsetFirstInvokeGate` entry
    // behind, so the store-count assertion below would observe two entries.
    {
        let store_path = approval_dir.path().join(format!("{profile_name}.toml"));
        let mut approval_store =
            PendingApprovalStore::open(store_path).expect("open approval store for gate consume");
        let removed = approval_store
            .remove(gate_nonce)
            .expect("remove first-invoke gate pending entry");
        assert!(
            removed,
            "first-invoke gate pending approval must exist to be consumed"
        );
    }

    // ── Re-invoke with grant + no attestation → forced per-action ─────────
    let envelope_xdr2 = build_payment_xdr(&g_strkey, &g_strkey, SELF_PAYMENT_STROOPS);

    let args2 = StellarToolsetInvokeArgs {
        toolset: TOOLSET_NAME.to_owned(),
        action: "stellar_pay_commit".to_owned(),
        chain_id: Some(TESTNET_CHAIN_ID.to_owned()),
        args: serde_json::json!({
            "envelope_xdr": &envelope_xdr2,
            "source": &g_strkey,
            "destination": &g_strkey,
            "nonce": FAKE_VALID_NONCE,
            "expires_at_unix_ms": 9_999_999_999_u64,
            "asset": "native",
            "amount": "1 XLM",
            "chain_id": TESTNET_CHAIN_ID
        }),
    };

    let result2 = server.call_stellar_toolset_invoke(args2).await;
    assert!(
        result2.is_err(),
        "re-invoke with grant but no per-action approval must fail"
    );
    let err2 = result2.unwrap_err();
    assert!(
        err2.message.contains("approval_required"),
        "expected policy.approval_required (forced per-action approval); got: {}",
        err2.message
    );
    assert!(
        !err2.message.contains("first_invoke_approval_required"),
        "must NOT re-trigger first-invoke gate when grant is current"
    );

    // A PaymentSimulated pending approval was queued.
    let store_path = approval_dir.path().join(format!("{profile_name}.toml"));
    let approval_store = PendingApprovalStore::open(store_path).expect("open approval store");
    assert_eq!(
        approval_store.len(),
        1,
        "exactly one PaymentSimulated approval must have been queued after re-invoke"
    );

    // ── Verify testnet account exists (funding check) ─────────────────────
    let client = StellarRpcClient::new(TESTNET_RPC_URL).expect("RPC client");
    let account_view = fetch_account(&client, &g_strkey, &[])
        .await
        .expect("funded testnet account must be accessible via RPC");
    assert!(
        account_view.sequence_number > 0,
        "account sequence number must be positive for a funded account"
    );
    tracing::info!(
        g_strkey = %g_strkey,
        sequence_number = account_view.sequence_number,
        "testnet account confirmed reachable"
    );
}
