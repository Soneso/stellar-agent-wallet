//! Integration tests for the `deploy_smart_account` function using mocked RPC.
//!
//! Exercises the deployment orchestration at the library boundary with a
//! `wiremock::MockServer` standing in for the Soroban RPC endpoint. No testnet
//! or network access is required; all tests run under default `cargo test`.
//!
//! # Test scope
//!
//! This file covers:
//! - **Dry-run envelope shape** — verifies the `DeploymentResult` field
//!   set and types returned in dry-run mode (no RPC traffic).
//! - **Input-validation paths** — invalid deployer G-strkey, invalid initial
//!   signer, invalid salt derivation edge cases.
//! - **Mock-RPC: malformed simulation pre-check** — verifies that a
//!   `simulateTransaction` response without `minResourceFee` triggers the
//!   panic-insulation pre-check path (`phase: "simulate"`) rather than a
//!   a panic inside the deployment path.
//! - **Mock-RPC: WASM on-chain detection** — verifies that
//!   `getLedgerEntries` returning a non-empty entry list causes
//!   `wasm_uploaded: false` in the result (WASM-already-on-chain path), while
//!   an empty list causes `wasm_uploaded: true` (upload-needed path).
//! - **Mock-RPC: upload path (stateful)** — exercises the `UploadContractWasm`
//!   branch via `StatefulSorobanRpcResponder`. Three
//!   scenarios: happy-path upload+deploy, simulate error on upload, send error
//!   on upload. Covers the ~135-line upload branch that `SorobanRpcResponder`
//!   never reaches (it always returns a non-empty WASM entry → already-on-chain).
//!   Covers the ~135-line upload branch that `SorobanRpcResponder` never reaches.
//!
//! # Not covered here
//!
//! Full happy-path deployment (signed Tx → `sendTransaction` → `getTransaction`
//! → `post_deploy_verification`) is covered by the testnet acceptance tests at
//! `tests/deploy_c_testnet_acceptance.rs` (gated by `--features testnet-integration`).
//!
//! # Coverage
//!
//! Wiremock mock-RPC test layer for `deploy_smart_account`.

// reason: integration tests use unwrap/expect to make fixture construction failures explicit.
#![allow(clippy::unwrap_used, clippy::expect_used, reason = "test-only")]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_core::error::{AuthError, WalletError};
use stellar_agent_network::{Signer, SoftwareSigningKey};
use stellar_agent_smart_account::SaError;
use stellar_agent_smart_account::deployment::{
    DeployerKeypair, DeploymentArgs, DeploymentResult, MULTISIG_ACCOUNT_WASM_SHA256,
    ResolvedFeePerOp, deploy_smart_account, derive_smart_account_address, interop_deployer,
    interop_deployer_pubkey,
};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};
use zeroize::Zeroizing;

// ── Test constants ────────────────────────────────────────────────────────────

const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";

/// A stable initial-signer G-strkey (seed `[0x11; 32]`).
///
/// Derived from an all-0x11 seed; does not need to be Friendbot-funded for
/// deployment tests (the deployer pays; the initial-signer is an on-chain
/// parameter for the constructor only).
const INITIAL_SIGNER_G: &str = "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL";

/// Asserts an `Option<&str>` transaction hash against an expected hash, redacting on failure.
macro_rules! assert_redacted_tx_hash_eq {
    ($actual:expr, $expected:expr $(,)?) => {{
        let actual: Option<&str> = $actual;
        let expected: &str = $expected;
        if actual != Some(expected) {
            let actual_redacted = actual
                .map(stellar_agent_network::redact_tx_hash)
                .unwrap_or_else(|| "<absent>".to_owned());
            let expected_redacted = stellar_agent_network::redact_tx_hash(expected);
            panic!("tx hash mismatch: actual={actual_redacted}, expected={expected_redacted}");
        }
    }};
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Generates a fresh ed25519 keypair and returns `(g_strkey, seed_zeroizing)`.
fn fresh_keypair() -> (String, Zeroizing<[u8; 32]>) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let g_strkey = format!(
        "{}",
        stellar_strkey::ed25519::PublicKey(verifying_key.to_bytes())
    );
    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(signing_key.to_bytes());
    (g_strkey, seed)
}

/// Constructs a `DeployerKeypair` from the well-known interop seed.
fn interop_deployer_g() -> DeployerKeypair {
    interop_deployer()
}

/// Constructs a `DeployerKeypair::SecretEnv`-style signer from a fresh seed.
///
/// Used in tests where we need a real signer without a live secret env-var.
fn fresh_deployer() -> (String, DeployerKeypair) {
    let (g_strkey, seed) = fresh_keypair();
    let signer: Box<dyn stellar_agent_network::Signer + Send + Sync> =
        Box::new(SoftwareSigningKey::new_from_zeroizing(seed));
    let deployer = DeployerKeypair::SecretEnv {
        var_name: "test-integration".to_owned(),
        signer,
    };
    (g_strkey, deployer)
}

/// Constructs minimal `DeploymentArgs` for dry-run mode (no network access).
fn dry_run_args(deployer: DeployerKeypair, rpc_url: &str, salt: [u8; 32]) -> DeploymentArgs {
    DeploymentArgs {
        deployer,
        initial_signer: INITIAL_SIGNER_G.to_owned(),
        salt,
        network_passphrase: TESTNET_PASSPHRASE.to_owned(),
        rpc_url: rpc_url.to_owned(),
        timeout: Duration::from_secs(5),
        fee: ResolvedFeePerOp {
            stroops: 100,
            percentile_label: "profile_default".to_owned(),
        },
        dry_run: true,
    }
}

// ── Envelope-shape tests (dry-run) ───────────────────────────────────────────

/// Asserts the `DeploymentResult` field set in dry-run mode.
///
/// Dry-run exercises the address-derivation path and returns the full
/// envelope shape without any network access. Verifies re-derivation from
/// (deployer, salt, passphrase) without testnet access.
#[tokio::test]
async fn dry_run_returns_valid_envelope_shape_with_all_required_fields() {
    let (deployer_g, deployer) = fresh_deployer();
    let mut salt = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut OsRng, &mut salt);

    let args = dry_run_args(deployer, "http://unused.example.com:8000", salt);
    let result: DeploymentResult = deploy_smart_account(args, None)
        .await
        .expect("dry-run must succeed for valid inputs");

    // smart_account must be a valid C-strkey.
    assert!(
        result.smart_account.starts_with('C'),
        "smart_account must start with 'C': {}",
        result.smart_account
    );
    assert_eq!(
        result.smart_account.len(),
        56,
        "smart_account must be 56 chars: {}",
        result.smart_account
    );
    stellar_strkey::Contract::from_string(&result.smart_account)
        .expect("smart_account must decode as a valid C-strkey");

    // salt_hex must be 64 lowercase hex chars.
    assert_eq!(
        result.salt_hex.len(),
        64,
        "salt_hex must be 64 chars: {}",
        result.salt_hex
    );
    assert!(
        result
            .salt_hex
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()),
        "salt_hex must be lowercase hex: {}",
        result.salt_hex
    );

    // deployer_pubkey must match the deployer we passed.
    assert_eq!(
        result.deployer_pubkey, deployer_g,
        "deployer_pubkey must match the deployer arg"
    );

    // wasm_hash must be the pinned MULTISIG_ACCOUNT_WASM_SHA256.
    assert_eq!(
        result.wasm_hash, MULTISIG_ACCOUNT_WASM_SHA256,
        "wasm_hash must equal MULTISIG_ACCOUNT_WASM_SHA256"
    );
    assert_eq!(
        result.wasm_hash.len(),
        64,
        "wasm_hash must be 64 chars: {}",
        result.wasm_hash
    );

    // wasm_uploaded must be false in dry-run (no upload was performed).
    assert!(
        !result.wasm_uploaded,
        "wasm_uploaded must be false in dry-run"
    );

    // tx_hash must be None in dry-run.
    assert!(
        result.tx_hash.is_none(),
        "tx_hash must be None in dry-run; got: {:?}",
        result.tx_hash
    );

    // ledger must be None in dry-run.
    assert!(
        result.ledger.is_none(),
        "ledger must be None in dry-run; got: {:?}",
        result.ledger
    );

    // initial_signer must round-trip.
    assert_eq!(
        result.initial_signer, INITIAL_SIGNER_G,
        "initial_signer must round-trip through DeploymentResult"
    );

    // selected_fee_per_op_stroops must reflect the input fee.
    assert_eq!(
        result.selected_fee_per_op_stroops, 100,
        "selected_fee_per_op_stroops must equal the input fee"
    );
    assert_eq!(
        result.selected_fee_percentile, "profile_default",
        "selected_fee_percentile must equal the input fee percentile label"
    );
}

/// Asserts that `DeploymentResult` is JSON-serialisable and the serialised JSON
/// contains all required fields.
///
/// Validates the wire-format shape consumed by the CLI `render_json` output
/// and the MCP tool response envelope.
#[tokio::test]
async fn dry_run_result_serialises_to_json_with_required_fields() {
    let deployer = interop_deployer_g();
    let salt = [0x42u8; 32];
    let args = dry_run_args(deployer, "http://unused.example.com:8000", salt);

    let result = deploy_smart_account(args, None)
        .await
        .expect("dry-run must succeed");

    let json_str = serde_json::to_string(&result).expect("DeploymentResult must serialise to JSON");
    let json_val: serde_json::Value =
        serde_json::from_str(&json_str).expect("serialised JSON must be valid");

    // All required fields must be present.
    for field in &[
        "smart_account",
        "salt_hex",
        "deployer_pubkey",
        "wasm_hash",
        "wasm_uploaded",
        "initial_signer",
        "selected_fee_per_op_stroops",
        "selected_fee_percentile",
    ] {
        assert!(
            json_val.get(field).is_some(),
            "JSON must contain field '{field}'; got: {json_str}"
        );
    }

    // tx_hash and ledger must not be present (or be JSON null) in dry-run.
    // serde's Option<T> with default serde behaviour serialises None as null.
    if let Some(tx_hash) = json_val.get("tx_hash") {
        assert!(
            tx_hash.is_null(),
            "tx_hash must be null in dry-run JSON; got: {tx_hash}"
        );
    }
    if let Some(ledger) = json_val.get("ledger") {
        assert!(
            ledger.is_null(),
            "ledger must be null in dry-run JSON; got: {ledger}"
        );
    }

    // Validate the C-strkey prefix in JSON.
    let smart_account = json_val["smart_account"]
        .as_str()
        .expect("smart_account must be a string");
    assert!(
        smart_account.starts_with('C'),
        "smart_account in JSON must start with 'C'"
    );

    // Validate salt_hex length.
    let salt_hex = json_val["salt_hex"]
        .as_str()
        .expect("salt_hex must be a string");
    assert_eq!(salt_hex.len(), 64, "salt_hex in JSON must be 64 chars");
}

/// Asserts that dry-run is deterministic: same inputs → same `DeploymentResult.smart_account`.
#[tokio::test]
async fn dry_run_is_deterministic_for_same_inputs() {
    let salt = [0xABu8; 32];
    let deployer_g = interop_deployer_pubkey();

    let deployer_a = interop_deployer_g();
    let args_a = dry_run_args(deployer_a, "http://unused.example.com:8000", salt);
    let result_a = deploy_smart_account(args_a, None)
        .await
        .expect("dry-run A must succeed");

    let deployer_b = interop_deployer_g();
    let args_b = dry_run_args(deployer_b, "http://unused.example.com:8000", salt);
    let result_b = deploy_smart_account(args_b, None)
        .await
        .expect("dry-run B must succeed");

    assert_eq!(
        result_a.smart_account, result_b.smart_account,
        "two dry-runs with identical inputs must produce the same smart_account"
    );
    assert_eq!(
        result_a.deployer_pubkey, deployer_g,
        "deployer_pubkey must match well-known interop deployer"
    );
}

/// Asserts that `derive_smart_account_address` and `deploy_smart_account(dry_run=true)`
/// produce the same C-strkey.
///
/// Validates that the dry-run path in `deploy_smart_account` is equivalent to
/// calling `derive_smart_account_address` directly.
#[tokio::test]
async fn dry_run_smart_account_matches_derive_smart_account_address() {
    let deployer_g = interop_deployer_pubkey();
    let salt = [0x77u8; 32];

    // Direct derivation.
    let expected_c = derive_smart_account_address(&deployer_g, &salt, TESTNET_PASSPHRASE)
        .expect("direct derivation must succeed");

    // Via deploy_smart_account dry-run.
    let deployer = interop_deployer_g();
    let args = dry_run_args(deployer, "http://unused.example.com:8000", salt);
    let result = deploy_smart_account(args, None)
        .await
        .expect("dry-run must succeed");

    assert_eq!(
        result.smart_account, expected_c,
        "dry-run smart_account must match direct derive_smart_account_address output"
    );
}

// ── Input-validation error paths ──────────────────────────────────────────────

/// Asserts that passing an invalid G-strkey as `initial_signer` returns
/// `SaError::DeploymentFailed { phase: "constructor", .. }`.
#[tokio::test]
async fn invalid_initial_signer_returns_constructor_phase_error() {
    let deployer = interop_deployer_g();
    let salt = [0u8; 32];
    let args = DeploymentArgs {
        deployer,
        initial_signer: "NOT-A-VALID-G-STRKEY".to_owned(),
        salt,
        network_passphrase: TESTNET_PASSPHRASE.to_owned(),
        rpc_url: "http://unused.example.com:8000".to_owned(),
        timeout: Duration::from_secs(5),
        fee: ResolvedFeePerOp {
            stroops: 100,
            percentile_label: "profile_default".to_owned(),
        },
        // dry_run = false triggers the constructor-arg build path before any RPC call.
        dry_run: false,
    };

    let err = deploy_smart_account(args, None)
        .await
        .expect_err("invalid initial_signer must cause an error");

    // Constructor-arg build failure maps to phase "constructor".
    assert!(
        matches!(
            err,
            SaError::DeploymentFailed {
                phase: "build" | "constructor",
                ..
            }
        ),
        "invalid initial_signer must return DeploymentFailed at build or constructor phase; got: {err:?}"
    );
}

// ── Mock-RPC: malformed simulation pre-check ──────────────────────────────────

/// A `wiremock::Respond` implementation that dispatches by JSON-RPC `method`.
///
/// Routes multiple Soroban RPC methods to canned responses in a single mock
/// mount. Used to exercise the `deploy_smart_account` flow with a controlled
/// RPC surface.
struct SorobanRpcResponder {
    /// JSON-RPC result for `getLedgerEntries` (same response for both
    /// account-sequence and WASM pre-flight calls).
    ledger_entries_result: serde_json::Value,
    /// JSON-RPC result for `simulateTransaction`.
    simulate_result: serde_json::Value,
}

impl SorobanRpcResponder {
    fn new(ledger_entries_result: serde_json::Value, simulate_result: serde_json::Value) -> Self {
        Self {
            ledger_entries_result,
            simulate_result,
        }
    }
}

impl Respond for SorobanRpcResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body_text = String::from_utf8_lossy(&request.body);
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap_or_default();
        let req_id = body.get("id").cloned().unwrap_or(serde_json::json!(1));
        let parsed_method = body
            .get("method")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let method = if parsed_method.is_empty() && body_text.contains("getTransaction") {
            "getTransaction"
        } else {
            parsed_method
        };

        let result = match method {
            "getLedgerEntries" => self.ledger_entries_result.clone(),
            "simulateTransaction" => self.simulate_result.clone(),
            "sendTransaction" => serde_json::json!({
                "status": "PENDING",
                "hash": "a".repeat(64),
                "latestLedger": 1000,
                "latestLedgerCloseTime": "1234567890"
            }),
            "getTransaction" => serde_json::json!({
                "status": "NOT_FOUND",
                "latestLedger": 1000,
                "latestLedgerCloseTime": "1234567890",
                "oldestLedger": 1,
                "oldestLedgerCloseTime": "1234000000"
            }),
            _ => serde_json::json!({}),
        };

        ResponseTemplate::new(200)
            .set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": result
            }))
            .insert_header("content-type", "application/json")
    }
}

/// Constructs a `LedgerKey::Account` XDR base64 for a given G-strkey.
///
/// `fetch_account` in `stellar-agent-network` decodes `response.entries[].key`
/// as `LedgerKey` before dispatching on the variant.  Mock responses that use a
/// placeholder like `"AAAAAAAAAA=="` (all-zeros, too short to form a valid XDR
/// discriminant) will fail with an XDR decode error at the `fetch_account` level,
/// which maps to `SaError::DeploymentFailed { phase: "build" }`.
///
/// Use this helper to produce the correctly-encoded key so that `fetch_account`
/// classifies the entry as `LedgerKey::Account` and extracts the sequence number.
fn account_key_xdr(account_g: &str) -> String {
    use stellar_xdr::{
        AccountId, LedgerKey, LedgerKeyAccount, Limits, PublicKey, Uint256, WriteXdr,
    };
    let pk_bytes = stellar_strkey::ed25519::PublicKey::from_string(account_g)
        .expect("valid G-strkey")
        .0;
    LedgerKey::Account(LedgerKeyAccount {
        account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk_bytes))),
    })
    .to_xdr_base64(Limits::none())
    .expect("LedgerKey::Account XDR must encode")
}

/// Constructs an `AccountEntry` XDR base64 for a test deployer account.
///
/// Returns the XDR-base64 encoded `LedgerEntryData::Account` with sequence 100
/// and balance sufficient for deployment fees.
fn account_entry_xdr(account_g: &str, sequence: i64) -> String {
    use stellar_xdr::{
        AccountEntry, AccountEntryExt, AccountId, LedgerEntryData, Limits, PublicKey,
        SequenceNumber, String32, Thresholds, Uint256, WriteXdr,
    };
    let pk_bytes = stellar_strkey::ed25519::PublicKey::from_string(account_g)
        .expect("valid G-strkey")
        .0;
    let entry = AccountEntry {
        account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk_bytes))),
        balance: 100_000_000_000, // 10,000 XLM in stroops
        seq_num: SequenceNumber(sequence),
        num_sub_entries: 0,
        inflation_dest: None,
        flags: 0,
        home_domain: String32::default(),
        thresholds: Thresholds([1, 0, 0, 0]),
        signers: vec![].try_into().expect("empty signers"),
        ext: AccountEntryExt::V0,
    };
    LedgerEntryData::Account(entry)
        .to_xdr_base64(Limits::none())
        .expect("AccountEntry XDR must encode")
}

/// Returns a minimal valid XDR base64 `SorobanTransactionData` for use in
/// synthetic simulation responses.
///
/// A minimal valid XDR base64 `SorobanTransactionData` used in synthetic
/// simulation responses. The value is a valid XDR-encoded `SorobanTransactionData`
/// with a non-empty footprint.
fn minimal_soroban_transaction_data_xdr() -> &'static str {
    // A valid SorobanTransactionData base64 with a non-trivial footprint,
    // used to produce well-formed simulate responses in mock tests.
    "AAAAAAAAAAIAAAAGAAAAAcwD/nT9D7Dc2LxRdab+2vEUF8B+XoN7mQW21oxPT8ALAAAAFAAAAAEAAAAHy8vNUZ8vyZ2ybPHW0XbSrRtP7gEWsJ6zDzcfY9P8z88AAAABAAAABgAAAAHMA/50/Q+w3Ni8UXWm/trxFBfAfl6De5kFttaMT0/ACwAAABAAAAABAAAAAgAAAA8AAAAHQ291bnRlcgAAAAASAAAAAAAAAAAg4dbAxsGAGICfBG3iT2cKGYQ6hK4sJWzZ6or1C5v6GAAAAAEAHfKyAAAFiAAAAIgAAAAAAAAAAw=="
}

/// Asserts that a `simulateTransaction` response without `minResourceFee`
/// causes `deploy_smart_account` to return
/// `SaError::DeploymentFailed { phase: "simulate", .. }` rather than
/// panicking in the deployment path.
///
/// This regression gate exercises the panic-insulation pre-check at
/// `deploy.rs: sim_response.min_resource_fee == 0`.
#[tokio::test]
async fn malformed_simulation_response_without_min_fee_returns_simulate_phase_error() {
    let server = MockServer::start().await;

    // Account-sequence response: return a funded account entry.
    // The same `getLedgerEntries` responder is used for both account + WASM calls.
    // For the account lookup: return an entry; for the WASM lookup: return empty.
    // Since this responder returns the same response for all getLedgerEntries calls,
    // we use a stateless responder with account data. The WASM pre-flight will
    // see account XDR as the first entry; that parse will fail gracefully since
    // it's not a ContractCode entry — resulting in wasm_already_on_chain=false.
    // This is acceptable for the test's purpose: we care only about the simulate error.
    let (deployer_g, seed) = fresh_keypair();
    let account_key = account_key_xdr(&deployer_g);
    let account_xdr = account_entry_xdr(&deployer_g, 100);

    Mock::given(method("POST"))
        .respond_with(SorobanRpcResponder::new(
            // getLedgerEntries: return an account entry with a properly-encoded
            // `LedgerKey::Account` XDR in the `key` field.  `fetch_account` in
            // stellar-agent-network decodes each entry's `key` field as LedgerKey
            // before classifying Account vs ContractCode entries.
            // A placeholder like `"AAAAAAAAAA=="` is too short to form a valid XDR
            // discriminant and causes a `phase: "build"` error before `simulate`.
            // Using the correctly-encoded account key ensures `fetch_account` succeeds
            // and the test reaches the `simulateTransaction` pre-check path.
            //
            // The same `getLedgerEntries` response is returned for both the
            // account-sequence fetch and the WASM pre-flight check.  The WASM pre-flight
            // sees an account entry (not ContractCode) → `wasm_already_on_chain = true`,
            // which skips the upload op and goes straight to simulate.
            serde_json::json!({
                "entries": [{
                    "key": account_key,
                    "xdr": account_xdr,
                    "lastModifiedLedgerSeq": 100,
                    "liveUntilLedgerSeq": 10000
                }],
                "latestLedger": 100
            }),
            // simulateTransaction: MISSING minResourceFee → triggers pre-check rejection.
            serde_json::json!({
                "latestLedger": 100
                // minResourceFee intentionally absent → triggers SaError::DeploymentFailed
                // { phase: "simulate", .. } via the `sim_response.min_resource_fee == 0`
                // pre-check in deploy.rs.
            }),
        ))
        .mount(&server)
        .await;

    let signer: Box<dyn stellar_agent_network::Signer + Send + Sync> =
        Box::new(SoftwareSigningKey::new_from_zeroizing(seed));
    let deployer = DeployerKeypair::SecretEnv {
        var_name: "test-sim-error".to_owned(),
        signer,
    };
    let salt = [0xCCu8; 32];
    let args = DeploymentArgs {
        deployer,
        initial_signer: INITIAL_SIGNER_G.to_owned(),
        salt,
        network_passphrase: TESTNET_PASSPHRASE.to_owned(),
        rpc_url: server.uri(),
        timeout: Duration::from_secs(5),
        fee: ResolvedFeePerOp {
            stroops: 100,
            percentile_label: "profile_default".to_owned(),
        },
        dry_run: false,
    };

    let err = deploy_smart_account(args, None)
        .await
        .expect_err("malformed simulation response must return an error");

    assert!(
        matches!(
            err,
            SaError::DeploymentFailed {
                phase: "simulate",
                ..
            }
        ),
        "malformed simulateTransaction must return DeploymentFailed at phase 'simulate'; got: {err:?}"
    );
}

/// Asserts that a `simulateTransaction` response WITH valid `minResourceFee`
/// and `transactionData` causes the deployment to proceed past the pre-check
/// and fail at the `submit` phase (because the mock `sendTransaction` returns
/// `PENDING` and `getTransaction` returns `NOT_FOUND` until timeout).
///
/// This test exercises the "simulate succeeds, submit times out" path, validating
/// the panic-insulation pre-check passes when the simulation response is well-formed.
#[tokio::test]
async fn valid_simulation_response_proceeds_past_simulate_phase() {
    let server = MockServer::start().await;

    let (deployer_g, seed) = fresh_keypair();
    let account_key = account_key_xdr(&deployer_g);
    let account_xdr = account_entry_xdr(&deployer_g, 100);

    Mock::given(method("POST"))
        .respond_with(SorobanRpcResponder::new(
            // getLedgerEntries: properly-encoded account key XDR so fetch_account
            // classifies the entry as LedgerKey::Account and extracts sequence number.
            // The same response is returned for both fetch_account and WASM pre-flight.
            // The WASM pre-flight sees the account entry (not ContractCode) →
            // wasm_already_on_chain = true → skips upload → goes straight to simulate.
            serde_json::json!({
                "entries": [{
                    "key": account_key,
                    "xdr": account_xdr,
                    "lastModifiedLedgerSeq": 100,
                    "liveUntilLedgerSeq": 10000
                }],
                "latestLedger": 100
            }),
            // simulateTransaction: valid min_resource_fee + transactionData.
            // The transactionData XDR is a valid SorobanTransactionData value.
            serde_json::json!({
                "latestLedger": 100,
                "minResourceFee": "5000",
                "transactionData": minimal_soroban_transaction_data_xdr(),
                "results": [{"auth": [], "xdr": "AAAAAwAAAAQ="}],
                "events": []
            }),
        ))
        .mount(&server)
        .await;

    let signer: Box<dyn stellar_agent_network::Signer + Send + Sync> =
        Box::new(SoftwareSigningKey::new_from_zeroizing(seed));
    let deployer = DeployerKeypair::SecretEnv {
        var_name: "test-sim-valid".to_owned(),
        signer,
    };
    let salt = [0xDDu8; 32];
    let args = DeploymentArgs {
        deployer,
        initial_signer: INITIAL_SIGNER_G.to_owned(),
        salt,
        network_passphrase: TESTNET_PASSPHRASE.to_owned(),
        rpc_url: server.uri(),
        // Short timeout — the mock returns NOT_FOUND indefinitely, so the test
        // times out at submission without racing pre-submit RPC calls.
        timeout: Duration::from_secs(3),
        fee: ResolvedFeePerOp {
            stroops: 100,
            percentile_label: "profile_default".to_owned(),
        },
        dry_run: false,
    };

    let err = deploy_smart_account(args, None)
        .await
        .expect_err("deployment must fail (submit timeout or simulate error)");

    // The error must NOT be at the "simulate" phase (the pre-check passed).
    // It can be at "submit" (timeout) or "build" (if XDR assembly fails).
    // We just assert it is NOT "simulate", confirming the pre-check was satisfied.
    assert!(
        !matches!(
            err,
            SaError::DeploymentFailed {
                phase: "simulate",
                ..
            }
        ),
        "valid simulation response must not produce a 'simulate' phase error; got: {err:?}"
    );
}

// ── Clap arg-group compilation checks ────────────────────────────────────────

/// Asserts that `DeploymentArgs` with `dry_run: true` never makes network calls
/// regardless of the `rpc_url` value (even an unreachable URL).
///
/// Uses an unreachable URL to ensure no actual TCP connections are opened.
#[tokio::test]
async fn dry_run_does_not_make_network_calls_to_unreachable_url() {
    let deployer = interop_deployer_g();
    let salt = [0x11u8; 32];
    // An unreachable URL — any network call would fail or time out.
    let args = dry_run_args(deployer, "http://127.0.0.1:1", salt);

    let result = deploy_smart_account(args, None)
        .await
        .expect("dry-run must succeed even with an unreachable RPC URL");

    // The C-strkey must be derived successfully (pure computation, no I/O).
    assert!(
        result.smart_account.starts_with('C'),
        "smart_account must be derived from (deployer, salt, passphrase): {}",
        result.smart_account
    );
    // Neither tx_hash nor ledger should be set (no submission occurred).
    assert!(result.tx_hash.is_none(), "tx_hash must be None in dry-run");
    assert!(result.ledger.is_none(), "ledger must be None in dry-run");
}

/// Asserts `derive_smart_account_address` with the same deployer + salt produces
/// the same address as `deploy_smart_account(dry_run=true)` for the well-known interop deployer.
///
/// Covers the address-recovery property: re-derive from (deployer, salt, passphrase)
/// without a network call.
#[test]
fn interop_deployer_address_recovery_is_deterministic() {
    let interop_g = interop_deployer_pubkey();
    let salt = [0u8; 32];

    let c1 = derive_smart_account_address(&interop_g, &salt, TESTNET_PASSPHRASE)
        .expect("derivation 1 must succeed");
    let c2 = derive_smart_account_address(&interop_g, &salt, TESTNET_PASSPHRASE)
        .expect("derivation 2 must succeed");

    assert_eq!(c1, c2, "recovery must be deterministic");
    stellar_strkey::Contract::from_string(&c1).expect("recovered C-strkey must be valid");
}

/// Asserts that `MULTISIG_ACCOUNT_WASM_SHA256` in `DeploymentResult.wasm_hash`
/// is exactly the pinned value from `deploy.rs`, matching `PROVENANCE.md`.
///
/// Verifies the `wasm_hash` field semantics: it is the SHA-256 of the
/// embedded vendored WASM, not a per-deployment value.
#[tokio::test]
async fn dry_run_wasm_hash_matches_pinned_multisig_account_wasm_sha256() {
    let deployer = interop_deployer_g();
    let args = dry_run_args(deployer, "http://unused.example.com:8000", [0u8; 32]);
    let result = deploy_smart_account(args, None)
        .await
        .expect("dry-run must succeed");

    assert_eq!(
        result.wasm_hash, MULTISIG_ACCOUNT_WASM_SHA256,
        "wasm_hash must equal the pinned MULTISIG_ACCOUNT_WASM_SHA256 constant"
    );
}

/// Asserts that different deployers with the same salt produce different
/// `smart_account` addresses in the `DeploymentResult`.
///
/// Validates the deployer-isolation property required for non-collision
/// guarantees across operators.
#[tokio::test]
async fn dry_run_different_deployers_produce_different_addresses() {
    let salt = [0x42u8; 32];

    let interop_dep = interop_deployer_g();
    let interop_args = dry_run_args(interop_dep, "http://unused.example.com:8000", salt);
    let interop_result = deploy_smart_account(interop_args, None)
        .await
        .expect("dry-run (interop deployer) must succeed");

    let (_, fresh_dep) = fresh_deployer();
    let fresh_args = dry_run_args(fresh_dep, "http://unused.example.com:8000", salt);
    let fresh_result = deploy_smart_account(fresh_args, None)
        .await
        .expect("dry-run (fresh deployer) must succeed");

    assert_ne!(
        interop_result.smart_account, fresh_result.smart_account,
        "different deployers must produce different smart_account addresses"
    );
}

/// Asserts that the same deployer with different salts produces different
/// `smart_account` addresses in the `DeploymentResult`.
///
/// Validates the salt-isolation property.
#[tokio::test]
async fn dry_run_different_salts_produce_different_addresses() {
    let interop_dep_a = interop_deployer_g();
    let args_a = dry_run_args(
        interop_dep_a,
        "http://unused.example.com:8000",
        [0x11u8; 32],
    );
    let result_a = deploy_smart_account(args_a, None)
        .await
        .expect("dry-run A must succeed");

    let interop_dep_b = interop_deployer_g();
    let args_b = dry_run_args(
        interop_dep_b,
        "http://unused.example.com:8000",
        [0x22u8; 32],
    );
    let result_b = deploy_smart_account(args_b, None)
        .await
        .expect("dry-run B must succeed");

    assert_ne!(
        result_a.smart_account, result_b.smart_account,
        "different salts must produce different smart_account addresses"
    );
    assert_ne!(
        result_a.salt_hex, result_b.salt_hex,
        "different salts must produce different salt_hex fields"
    );
}

// ── Stateful mock-RPC: upload path ────────────────────────────────────────────

/// Decoded host-function variant from an `InvokeHostFunction` operation.
///
/// Used by `StatefulSorobanRpcResponder` to dispatch `simulateTransaction`
/// and `sendTransaction` responses based on whether the incoming transaction
/// carries an `UploadContractWasm` or `CreateContractV2` op.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InvokeHostFunctionKind {
    UploadContractWasm,
    CreateContractV2,
    Other,
}

/// Decode the transaction XDR from a JSON-RPC request body's `params.transaction`
/// field and return the `InvokeHostFunctionKind` of the first operation.
///
/// Returns `InvokeHostFunctionKind::Other` when:
/// - the `params.transaction` field is absent or not a string,
/// - XDR decoding fails (e.g. not a `TransactionEnvelope`),
/// - the first operation is not `InvokeHostFunction`.
///
/// All XDR types are from `stellar_xdr` so that the decoding is consistent
/// with the wallet's encoded submissions.
fn host_function_kind_from_request(body: &serde_json::Value) -> InvokeHostFunctionKind {
    use stellar_xdr::{
        HostFunction, InvokeHostFunctionOp, Limits, OperationBody, ReadXdr, TransactionEnvelope,
        TransactionV1Envelope,
    };

    let tx_xdr = body
        .get("params")
        .and_then(|p| p.get("transaction"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();

    if tx_xdr.is_empty() {
        return InvokeHostFunctionKind::Other;
    }

    let Ok(envelope) = TransactionEnvelope::from_xdr_base64(tx_xdr, Limits::none()) else {
        return InvokeHostFunctionKind::Other;
    };

    let ops = match &envelope {
        TransactionEnvelope::Tx(TransactionV1Envelope { tx, .. }) => &tx.operations,
        _ => return InvokeHostFunctionKind::Other,
    };

    let Some(first_op) = ops.first() else {
        return InvokeHostFunctionKind::Other;
    };

    let OperationBody::InvokeHostFunction(InvokeHostFunctionOp { host_function, .. }) =
        &first_op.body
    else {
        return InvokeHostFunctionKind::Other;
    };

    match host_function {
        HostFunction::UploadContractWasm(_) => InvokeHostFunctionKind::UploadContractWasm,
        HostFunction::CreateContractV2(_) => InvokeHostFunctionKind::CreateContractV2,
        _ => InvokeHostFunctionKind::Other,
    }
}

/// Decode the first key from a `getLedgerEntries` request and return whether
/// it is a `LedgerKey::ContractCode` key (WASM pre-flight check) or not
/// (account key or other).
///
/// Uses `stellar_xdr` for decoding.  Returns `true` when the first
/// `params.keys[0]` decodes as `LedgerKey::ContractCode`.
fn first_key_is_contract_code(body: &serde_json::Value) -> bool {
    use stellar_xdr::{LedgerKey, Limits, ReadXdr};

    let key_b64 = first_ledger_key_b64(body).unwrap_or_default();

    if key_b64.is_empty() {
        return false;
    }

    matches!(
        LedgerKey::from_xdr_base64(key_b64, Limits::none()),
        Ok(LedgerKey::ContractCode(_))
    )
}

/// `true` when the first `params.keys[0]` decodes as `LedgerKey::ContractData`.
fn first_key_is_contract_data(body: &serde_json::Value) -> bool {
    use stellar_xdr::{LedgerKey, Limits, ReadXdr};

    let key_b64 = first_ledger_key_b64(body).unwrap_or_default();

    if key_b64.is_empty() {
        return false;
    }

    matches!(
        LedgerKey::from_xdr_base64(key_b64, Limits::none()),
        Ok(LedgerKey::ContractData(_))
    )
}

/// Returns the first ledger-key XDR string from a JSON-RPC `getLedgerEntries` request.
fn first_ledger_key_b64(body: &serde_json::Value) -> Option<&str> {
    body.get("params")
        .and_then(|p| p.get("keys"))
        .and_then(|k| k.get(0))
        .and_then(serde_json::Value::as_str)
}

/// Returns the transaction hash from a JSON-RPC `getTransaction` request.
fn request_transaction_hash(body: &serde_json::Value) -> Option<&str> {
    body.get("params")
        .and_then(|p| p.get("hash"))
        .and_then(serde_json::Value::as_str)
        .or_else(|| {
            body.get("params")
                .and_then(|p| p.get("transactionHash"))
                .and_then(serde_json::Value::as_str)
        })
        .or_else(|| {
            body.get("params")
                .and_then(serde_json::Value::as_array)
                .and_then(|params| params.first())
                .and_then(serde_json::Value::as_str)
        })
}

/// A stateful `wiremock::Respond` implementation that models the two-transaction
/// deploy flow (`UploadContractWasm` then `CreateContractV2`).
///
/// The responder tracks `wasm_uploaded` state across requests and adjusts its
/// `getLedgerEntries` WASM pre-flight response accordingly.  It also counts
/// the number of `sendTransaction` calls for each op kind, allowing tests to
/// assert that exactly one upload tx and one deploy tx were submitted.
///
/// # Dispatch logic
///
/// | Method | Condition | Response |
/// |---|---|---|
/// | `getLedgerEntries` | key is `ContractCode` and `wasm_uploaded = false` | empty entries |
/// | `getLedgerEntries` | key is `ContractCode` and `wasm_uploaded = true` | canned code entry |
/// | `getLedgerEntries` | key is `ContractData` | empty entries or canned instance entry |
/// | `getLedgerEntries` | key is `Account` (or other) | canned account entry or configured error |
/// | `simulateTransaction` | upload op, `simulate_error_on_upload = true` | `error` field set |
/// | `simulateTransaction` | deploy op, `simulate_error_on_deploy = true` | `error` field set |
/// | `simulateTransaction` | deploy op, or upload op without error | valid sim response |
/// | `sendTransaction` | upload op, `send_error_on_upload = true` | JSON-RPC error |
/// | `sendTransaction` | upload op, no error | flip `wasm_uploaded`; return upload hash |
/// | `sendTransaction` | deploy op, `send_error_on_deploy = true` | `status: "ERROR"` |
/// | `sendTransaction` | deploy op, no error | return deploy hash |
/// | `getTransaction` | upload hash with pending-forever flag | `NOT_FOUND` |
/// | `getTransaction` | any other hash | `SUCCESS` with ledger 1001 |
struct StatefulSorobanRpcResponder {
    /// Whether the WASM upload has been confirmed in this responder's lifetime.
    wasm_uploaded: Arc<AtomicBool>,
    /// Count of `sendTransaction` calls for `UploadContractWasm` ops.
    upload_send_count: Arc<AtomicUsize>,
    /// Count of `sendTransaction` calls for `CreateContractV2` ops.
    deploy_send_count: Arc<AtomicUsize>,
    /// Count of `getTransaction` polls for the upload transaction hash.
    upload_get_tx_count: Arc<AtomicUsize>,
    /// If `true`, return a `simulationError` when the upload tx is simulated.
    simulate_error_on_upload: bool,
    /// If `true`, return a JSON-RPC error envelope when the upload tx is sent.
    send_error_on_upload: bool,
    /// If `true`, return a `txMalformed`-class `status: "ERROR"` for the upload tx.
    typed_malformed_on_upload_send: bool,
    /// If `true`, return a `simulationError` when the deploy tx is simulated.
    simulate_error_on_deploy: bool,
    /// If `true`, return `status: "ERROR"` when the deploy tx is sent.
    send_error_on_deploy: bool,
    /// If `true`, the upload tx never confirms from `getTransaction`.
    upload_get_tx_pending_forever: bool,
    /// If `true`, the WASM pre-flight `getLedgerEntries` call returns an RPC error.
    wasm_preflight_rpc_error: bool,
    /// If `true`, the post-upload account sequence re-fetch returns malformed data.
    post_upload_account_fetch_failure: bool,
    /// Optional post-deploy `ContractInstance` entry with the configured WASM hash.
    post_deploy_contract_instance_wasm_hash: Option<[u8; 32]>,
    /// Canned account entry XDR (key + xdr) for `getLedgerEntries` account calls.
    account_key_b64: String,
    account_entry_b64: String,
}

/// Test signer that can fail on a configured signing call while still exposing a valid public key.
struct FailingSigner {
    signing_key: SoftwareSigningKey,
    fail_on_sign_call: usize,
    sign_calls: Arc<AtomicUsize>,
}

#[async_trait]
impl Signer for FailingSigner {
    async fn sign_tx_payload(&self, payload: &[u8; 32]) -> Result<[u8; 64], WalletError> {
        let call = self.sign_calls.fetch_add(1, Ordering::AcqRel) + 1;
        if call == self.fail_on_sign_call {
            return Err(WalletError::Auth(AuthError::HardwareUserRefused));
        }
        self.signing_key.sign_tx_payload(payload).await
    }

    async fn sign_auth_digest(&self, digest: &[u8; 32]) -> Result<[u8; 64], WalletError> {
        // FailingSigner is used by deploy-c tests which exercise
        // sign_tx_payload only; auth-digest signing is unreachable here.
        // Provide a faithful pass-through to keep the trait satisfied.
        self.signing_key.sign_auth_digest(digest).await
    }

    async fn sign_soroban_address_auth_payload(
        &self,
        payload: &[u8; 32],
    ) -> Result<[u8; 64], WalletError> {
        // FailingSigner is used by deploy-c tests which exercise
        // sign_tx_payload only; Soroban address-auth signing is unreachable
        // here. Pass-through preserves the trait.
        self.signing_key
            .sign_soroban_address_auth_payload(payload)
            .await
    }

    async fn sign_webauthn_assertion(
        &self,
        _auth_digest: &[u8; 32],
        _credential_id: &[u8],
    ) -> Result<stellar_agent_network::WebAuthnAssertion, WalletError> {
        // FailingSigner is used by deploy-c tests which exercise
        // sign_tx_payload only; WebAuthn assertion signing is unreachable here.
        // Return SignerKindMismatch to satisfy the trait.
        Err(WalletError::Auth(AuthError::SignerKindMismatch {
            signer_kind: "test_failing",
            requested_primitive: "sign_webauthn_assertion",
        }))
    }

    async fn public_key(&self) -> Result<stellar_strkey::ed25519::PublicKey, WalletError> {
        self.signing_key.public_key().await
    }
}

/// Fixed upload tx hash returned by the stateful responder.
///
/// Must be exactly 64 lowercase hex characters (32 bytes) so that
/// `stellar_xdr::Hash::from_str` succeeds inside `stellar-rpc-client`'s
/// `send_transaction` response parsing.
const UPLOAD_TX_HASH: &str = "aaaa000000000000000000000000000000000000000000000000000011111111";

/// Fixed deploy tx hash returned by the stateful responder.
///
/// Must be exactly 64 lowercase hex characters (32 bytes).
const DEPLOY_TX_HASH: &str = "bbbb000000000000000000000000000000000000000000000000000022222222";

/// TransactionResult XDR for `txMalformed`, used by deploy typed-submission tests.
const TX_MALFORMED_RESULT_XDR: &str = "AAAAAAAAAGT////wAAAAAA==";

/// Minimal `ContractCode` ledger entry XDR for the "WASM already uploaded" response.
///
/// The WASM pre-flight check in `deploy.rs` only inspects `entries.is_empty()`;
/// it does not decode the entry contents. A valid `LedgerEntryData::ContractCode`
/// with an arbitrary WASM blob is sufficient to signal that the WASM is on-chain.
///
/// Uses `stellar_xdr` to match the decoding side.
fn contract_code_entry_xdr() -> String {
    use stellar_xdr::{
        ContractCodeEntry, ContractCodeEntryExt, Hash, LedgerEntryData, Limits, WriteXdr,
    };
    // ContractCodeEntry has `code: BytesM<MAX>`.
    // The precheck only inspects `entries.is_empty()`, so any valid encoding suffices.
    let entry = ContractCodeEntry {
        ext: ContractCodeEntryExt::V0,
        hash: Hash([0xAB; 32]),
        code: vec![0x00u8].try_into().expect("1-byte BytesM must succeed"),
    };
    LedgerEntryData::ContractCode(entry)
        .to_xdr_base64(Limits::none())
        .expect("ContractCode XDR must encode")
}

/// Minimal valid XDR base64 for a `LedgerKey::ContractCode` key.
///
/// Used as the key field in the canned WASM-on-chain `getLedgerEntries` response.
fn contract_code_key_xdr() -> String {
    use stellar_xdr::{Hash, LedgerKey, LedgerKeyContractCode, Limits, WriteXdr};
    LedgerKey::ContractCode(LedgerKeyContractCode {
        hash: Hash([0xAB; 32]),
    })
    .to_xdr_base64(Limits::none())
    .expect("ContractCode key XDR must encode")
}

/// Minimal `ContractData` ledger entry XDR for post-deploy contract-instance verification.
fn contract_instance_entry_xdr(wasm_hash: [u8; 32]) -> String {
    use stellar_xdr::{
        ContractDataDurability, ContractDataEntry, ContractExecutable, ContractId, ExtensionPoint,
        Hash, LedgerEntryData, Limits, ScAddress, ScContractInstance, ScMap, ScVal, WriteXdr,
    };

    let instance = ScContractInstance {
        executable: ContractExecutable::Wasm(Hash(wasm_hash)),
        storage: Some(ScMap::default()),
    };
    let contract_data = ContractDataEntry {
        ext: ExtensionPoint::V0,
        contract: ScAddress::Contract(ContractId(Hash([0xCD; 32]))),
        key: ScVal::LedgerKeyContractInstance,
        durability: ContractDataDurability::Persistent,
        val: ScVal::ContractInstance(instance),
    };

    LedgerEntryData::ContractData(contract_data)
        .to_xdr_base64(Limits::none())
        .expect("ContractData XDR must encode")
}

/// Converts the pinned multisig WASM hash constant to raw bytes for test XDR fixtures.
fn multisig_wasm_hash_bytes() -> [u8; 32] {
    stellar_agent_core::hex::decode_hex32(MULTISIG_ACCOUNT_WASM_SHA256)
        .expect("MULTISIG_ACCOUNT_WASM_SHA256 must be valid 64-char lowercase hex")
}

impl StatefulSorobanRpcResponder {
    /// Create a new responder for the happy-path upload+deploy scenario.
    ///
    /// `wasm_uploaded` starts `false`; both simulate and send succeed for
    /// both op types.
    fn new(account_g: &str, sequence: i64) -> Self {
        let account_key_b64 = account_key_xdr(account_g);
        let account_entry_b64 = account_entry_xdr(account_g, sequence);
        Self {
            wasm_uploaded: Arc::new(AtomicBool::new(false)),
            upload_send_count: Arc::new(AtomicUsize::new(0)),
            deploy_send_count: Arc::new(AtomicUsize::new(0)),
            upload_get_tx_count: Arc::new(AtomicUsize::new(0)),
            simulate_error_on_upload: false,
            send_error_on_upload: false,
            typed_malformed_on_upload_send: false,
            simulate_error_on_deploy: false,
            send_error_on_deploy: false,
            upload_get_tx_pending_forever: false,
            wasm_preflight_rpc_error: false,
            post_upload_account_fetch_failure: false,
            post_deploy_contract_instance_wasm_hash: None,
            account_key_b64,
            account_entry_b64,
        }
    }

    /// Configure the responder to return a `simulationError` when the upload tx is simulated.
    fn with_simulate_error_on_upload(mut self) -> Self {
        self.simulate_error_on_upload = true;
        self
    }

    /// Configure the responder to return a JSON-RPC error envelope when the upload tx is sent.
    fn with_send_error_on_upload(mut self) -> Self {
        self.send_error_on_upload = true;
        self
    }

    /// Configure the responder to return a typed malformed error when the upload tx is sent.
    fn with_upload_send_error_typed_malformed(mut self) -> Self {
        self.typed_malformed_on_upload_send = true;
        self
    }

    /// Configure the responder to leave the upload tx in `NOT_FOUND` forever.
    fn with_upload_get_tx_pending_forever(mut self) -> Self {
        self.upload_get_tx_pending_forever = true;
        self
    }

    /// Configure the responder to fail the WASM pre-flight `getLedgerEntries` call.
    fn with_wasm_preflight_rpc_error(mut self) -> Self {
        self.wasm_preflight_rpc_error = true;
        self
    }

    /// Configure the responder to fail deploy simulation after a successful upload.
    fn with_deploy_simulate_error(mut self) -> Self {
        self.simulate_error_on_deploy = true;
        self
    }

    /// Configure the responder to fail deploy submission after a successful upload.
    fn with_deploy_send_error(mut self) -> Self {
        self.send_error_on_deploy = true;
        self
    }

    /// Configure the responder to fail the post-upload deployer sequence re-fetch.
    fn with_post_upload_account_fetch_failure(mut self) -> Self {
        self.post_upload_account_fetch_failure = true;
        self
    }

    /// Configure the responder to return a valid post-deploy contract-instance entry.
    fn with_post_deploy_contract_instance(mut self, wasm_hash: [u8; 32]) -> Self {
        self.post_deploy_contract_instance_wasm_hash = Some(wasm_hash);
        self
    }

    /// Return a cloned `Arc<AtomicBool>` tracking WASM upload state.
    fn wasm_uploaded_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.wasm_uploaded)
    }

    /// Return a cloned `Arc<AtomicUsize>` counting upload `sendTransaction` calls.
    fn upload_send_count_handle(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.upload_send_count)
    }

    /// Return a cloned `Arc<AtomicUsize>` counting deploy `sendTransaction` calls.
    fn deploy_send_count_handle(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.deploy_send_count)
    }

    /// Return a cloned `Arc<AtomicUsize>` counting upload `getTransaction` polls.
    fn upload_get_tx_count_handle(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.upload_get_tx_count)
    }
}

impl Respond for StatefulSorobanRpcResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap_or_default();
        let req_id = body.get("id").cloned().unwrap_or(serde_json::json!(1));
        let method = body
            .get("method")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");

        // Evaluated before all other dispatch branches; coexists with mutually-exclusive flags.
        if method == "getLedgerEntries"
            && self.wasm_preflight_rpc_error
            && first_key_is_contract_code(&body)
        {
            return ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32000,
                        "message": "mock WASM pre-flight getLedgerEntries failure"
                    }
                }))
                .insert_header("content-type", "application/json");
        }

        if method == "sendTransaction" && self.send_error_on_upload {
            let kind = host_function_kind_from_request(&body);
            let is_upload = match kind {
                InvokeHostFunctionKind::UploadContractWasm => true,
                InvokeHostFunctionKind::CreateContractV2 => false,
                InvokeHostFunctionKind::Other => !self.wasm_uploaded.load(Ordering::Acquire),
            };
            if is_upload {
                self.upload_send_count.fetch_add(1, Ordering::AcqRel);
                return ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {
                            "code": -32000,
                            "message": "mock upload sendTransaction RPC failure"
                        }
                    }))
                    .insert_header("content-type", "application/json");
            }
        }

        let result = match method {
            "getLedgerEntries" => self.respond_get_ledger_entries(&body),
            "simulateTransaction" => self.respond_simulate(&body),
            "sendTransaction" => self.respond_send(&body),
            "getTransaction" => self.respond_get_transaction(&body),
            _ => serde_json::json!({}),
        };

        ResponseTemplate::new(200)
            .set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": result
            }))
            .insert_header("content-type", "application/json")
    }
}

impl StatefulSorobanRpcResponder {
    fn respond_get_ledger_entries(&self, body: &serde_json::Value) -> serde_json::Value {
        if first_key_is_contract_code(body) {
            // WASM pre-flight check.
            if self.wasm_uploaded.load(Ordering::Acquire) {
                // WASM is on-chain: return a canned ContractCode entry.
                serde_json::json!({
                    "entries": [{
                        "key": contract_code_key_xdr(),
                        "xdr": contract_code_entry_xdr(),
                        "lastModifiedLedgerSeq": 999,
                        "liveUntilLedgerSeq": 99999
                    }],
                    "latestLedger": 1001
                })
            } else {
                // WASM absent: return empty entries.
                serde_json::json!({
                    "entries": [],
                    "latestLedger": 1000
                })
            }
        } else if first_key_is_contract_data(body) {
            if let Some(wasm_hash) = self.post_deploy_contract_instance_wasm_hash {
                serde_json::json!({
                    "entries": [{
                        "key": first_ledger_key_b64(body).unwrap_or_default(),
                        "xdr": contract_instance_entry_xdr(wasm_hash),
                        "lastModifiedLedgerSeq": 1001,
                        "liveUntilLedgerSeq": 99999
                    }],
                    "latestLedger": 1001
                })
            } else {
                serde_json::json!({
                    "entries": [],
                    "latestLedger": 1001
                })
            }
        } else if self.post_upload_account_fetch_failure
            && self.wasm_uploaded.load(Ordering::Acquire)
        {
            serde_json::json!({
                "entries": [{
                    "key": "not-valid-ledger-key-xdr",
                    "xdr": "not-valid-ledger-entry-xdr",
                    "lastModifiedLedgerSeq": 100,
                    "liveUntilLedgerSeq": 10000
                }],
                "latestLedger": 1000
            })
        } else {
            // Account key (fetch_account or post-upload re-fetch).
            serde_json::json!({
                "entries": [{
                    "key": self.account_key_b64,
                    "xdr": self.account_entry_b64,
                    "lastModifiedLedgerSeq": 100,
                    "liveUntilLedgerSeq": 10000
                }],
                "latestLedger": 1000
            })
        }
    }

    fn respond_simulate(&self, body: &serde_json::Value) -> serde_json::Value {
        // Classify the op kind.  Fallback: if `wasm_uploaded = false`, any simulate
        // must be for the upload tx (the first simulate in the flow); if
        // `wasm_uploaded = true`, it must be for the deploy tx.
        let kind = host_function_kind_from_request(body);
        let is_upload_sim = match kind {
            InvokeHostFunctionKind::UploadContractWasm => true,
            InvokeHostFunctionKind::CreateContractV2 => false,
            InvokeHostFunctionKind::Other => !self.wasm_uploaded.load(Ordering::Acquire),
        };

        if is_upload_sim && self.simulate_error_on_upload {
            // Return a simulationError for the upload tx.
            return serde_json::json!({
                "latestLedger": 1000,
                "error": "HostError: Value(Obj(Map(...))) upload simulation rejected by mock"
            });
        }

        if !is_upload_sim && self.simulate_error_on_deploy {
            return serde_json::json!({
                "latestLedger": 1001,
                "error": "HostError: Value(Obj(Map(...))) deploy simulation rejected by mock"
            });
        }

        // Valid simulation response for both upload and deploy ops.
        serde_json::json!({
            "latestLedger": 1000,
            "minResourceFee": "5000",
            "transactionData": minimal_soroban_transaction_data_xdr(),
            "results": [{"auth": [], "xdr": "AAAAAwAAAAQ="}],
            "events": []
        })
    }

    fn respond_send(&self, body: &serde_json::Value) -> serde_json::Value {
        // Classify the call by inspecting the tx XDR first.  The tx XDR is sent
        // via stellar-rpc-client in `params.transaction` as a base64-encoded XDR string.
        //
        // Fallback to state-based ordering when XDR decoding fails (e.g. mismatched
        // XDR major version between the encoder and this test decoder): the upload
        // `sendTransaction` is always the FIRST call (`wasm_uploaded = false` at
        // call time); the deploy `sendTransaction` is always the SECOND call
        // (`wasm_uploaded = true` after the upload is confirmed).
        let kind = host_function_kind_from_request(body);
        let is_upload = match kind {
            InvokeHostFunctionKind::UploadContractWasm => true,
            InvokeHostFunctionKind::CreateContractV2 => false,
            // XDR decode failed or op type unrecognised: fall back to state.
            InvokeHostFunctionKind::Other => !self.wasm_uploaded.load(Ordering::Acquire),
        };

        if is_upload {
            self.upload_send_count.fetch_add(1, Ordering::AcqRel);

            if self.typed_malformed_on_upload_send {
                return serde_json::json!({
                    "status": "ERROR",
                    "hash": UPLOAD_TX_HASH,
                    "latestLedger": 1000,
                    "latestLedgerCloseTime": "1234567890",
                    "errorResultXdr": TX_MALFORMED_RESULT_XDR,
                    "diagnosticEventsXdr": []
                });
            }

            // Successful upload: flip the wasm_uploaded flag.
            self.wasm_uploaded.store(true, Ordering::Release);
            serde_json::json!({
                "status": "PENDING",
                "hash": UPLOAD_TX_HASH,
                "latestLedger": 1000,
                "latestLedgerCloseTime": "1234567890"
            })
        } else {
            // Deploy tx.
            self.deploy_send_count.fetch_add(1, Ordering::AcqRel);

            if self.send_error_on_deploy {
                return serde_json::json!({
                    "status": "ERROR",
                    "hash": DEPLOY_TX_HASH,
                    "latestLedger": 1001,
                    "latestLedgerCloseTime": "1234567891",
                    "errorResultXdr": TX_MALFORMED_RESULT_XDR,
                    "diagnosticEventsXdr": []
                });
            }

            serde_json::json!({
                "status": "PENDING",
                "hash": DEPLOY_TX_HASH,
                "latestLedger": 1001,
                "latestLedgerCloseTime": "1234567891"
            })
        }
    }

    fn respond_get_transaction(&self, body: &serde_json::Value) -> serde_json::Value {
        let hash = request_transaction_hash(body).unwrap_or_default();
        if self.upload_get_tx_pending_forever {
            self.upload_get_tx_count.fetch_add(1, Ordering::AcqRel);
            return serde_json::json!({
                "status": "NOT_FOUND",
                "latestLedger": 1001,
                "latestLedgerCloseTime": "1234567890",
                "oldestLedger": 1,
                "oldestLedgerCloseTime": "1234000000"
            });
        }

        let is_upload_hash = hash == UPLOAD_TX_HASH;
        if is_upload_hash {
            self.upload_get_tx_count.fetch_add(1, Ordering::AcqRel);
        }

        serde_json::json!({
            "status": "SUCCESS",
            "latestLedger": 1001,
            "latestLedgerCloseTime": "1234567890",
            "oldestLedger": 1,
            "oldestLedgerCloseTime": "1234000000",
            "createdAt": "1234567890",
            "ledger": if is_upload_hash { 1000 } else { 1001 }
        })
    }
}

// ── Stateful responder tests ──────────────────────────────────────────────────

fn stateful_deploy_args(
    seed: Zeroizing<[u8; 32]>,
    var_name: &str,
    rpc_url: String,
    salt: [u8; 32],
    timeout: Duration,
) -> DeploymentArgs {
    let signer: Box<dyn stellar_agent_network::Signer + Send + Sync> =
        Box::new(SoftwareSigningKey::new_from_zeroizing(seed));
    let deployer = DeployerKeypair::SecretEnv {
        var_name: var_name.to_owned(),
        signer,
    };

    DeploymentArgs {
        deployer,
        initial_signer: INITIAL_SIGNER_G.to_owned(),
        salt,
        network_passphrase: TESTNET_PASSPHRASE.to_owned(),
        rpc_url,
        timeout,
        fee: ResolvedFeePerOp {
            stroops: 100,
            percentile_label: "profile_default".to_owned(),
        },
        dry_run: false,
    }
}

fn stateful_deploy_args_with_failing_signer(
    fail_on_sign_call: usize,
    var_name: &str,
    rpc_url: String,
    salt: [u8; 32],
    timeout: Duration,
) -> (String, DeploymentArgs, Arc<AtomicUsize>) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let deployer_g = format!(
        "{}",
        stellar_strkey::ed25519::PublicKey(signing_key.verifying_key().to_bytes())
    );
    let signing_seed = Zeroizing::new(signing_key.to_bytes());
    let sign_calls = Arc::new(AtomicUsize::new(0));
    let signer: Box<dyn stellar_agent_network::Signer + Send + Sync> = Box::new(FailingSigner {
        signing_key: SoftwareSigningKey::new_from_zeroizing(signing_seed),
        fail_on_sign_call,
        sign_calls: Arc::clone(&sign_calls),
    });
    let deployer = DeployerKeypair::SecretEnv {
        var_name: var_name.to_owned(),
        signer,
    };

    (
        deployer_g,
        DeploymentArgs {
            deployer,
            initial_signer: INITIAL_SIGNER_G.to_owned(),
            salt,
            network_passphrase: TESTNET_PASSPHRASE.to_owned(),
            rpc_url,
            timeout,
            fee: ResolvedFeePerOp {
                stroops: 100,
                percentile_label: "profile_default".to_owned(),
            },
            dry_run: false,
        },
        sign_calls,
    )
}

fn tmp_audit_writer() -> (AuditWriter, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tmp dir");
    let path = dir.path().join("audit.jsonl");
    let writer = AuditWriter::open(path, None).expect("AuditWriter::open");
    (writer, dir)
}

fn read_audit_entries(dir: &tempfile::TempDir) -> Vec<serde_json::Value> {
    let path = dir.path().join("audit.jsonl");
    let content = std::fs::read_to_string(path).expect("audit.jsonl must be readable");
    content
        .lines()
        .map(|line| serde_json::from_str(line).expect("audit line must be valid JSON"))
        .collect()
}

/// Happy-path upload+deploy: WASM absent on first check; responder uploads, deploys, and verifies.
#[tokio::test]
async fn wasm_absent_uploads_then_deploys() {
    let server = MockServer::start().await;
    let (deployer_g, seed) = fresh_keypair();

    let responder = StatefulSorobanRpcResponder::new(&deployer_g, 100)
        .with_post_deploy_contract_instance(multisig_wasm_hash_bytes());
    let wasm_uploaded = responder.wasm_uploaded_handle();
    let upload_count = responder.upload_send_count_handle();
    let deploy_count = responder.deploy_send_count_handle();

    Mock::given(method("POST"))
        .respond_with(responder)
        .mount(&server)
        .await;

    let args = stateful_deploy_args(
        seed,
        "test-upload-happy",
        server.uri(),
        [0x55u8; 32],
        Duration::from_secs(10),
    );

    let result = deploy_smart_account(args, None)
        .await
        .expect("upload, deploy, and post-deploy verification must succeed");

    assert_eq!(
        upload_count.load(Ordering::Acquire),
        1,
        "exactly one upload sendTransaction must have been issued; got {}",
        upload_count.load(Ordering::Acquire)
    );
    assert_eq!(
        deploy_count.load(Ordering::Acquire),
        1,
        "exactly one deploy sendTransaction must have been issued; got {}",
        deploy_count.load(Ordering::Acquire)
    );
    assert!(
        wasm_uploaded.load(Ordering::Acquire),
        "successful upload must flip responder wasm_uploaded state"
    );
    assert!(
        result.smart_account.starts_with('C'),
        "smart_account must be a C-strkey: {}",
        result.smart_account
    );
    assert_eq!(
        result.smart_account.len(),
        56,
        "smart_account must be 56 chars: {}",
        result.smart_account
    );
    stellar_strkey::Contract::from_string(&result.smart_account)
        .expect("smart_account must decode as a valid C-strkey");
    assert_eq!(
        result.salt_hex,
        "55".repeat(32),
        "salt_hex must match the deployment salt"
    );
    assert_eq!(
        result.deployer_pubkey, deployer_g,
        "deployer_pubkey must match the deployer"
    );
    assert_eq!(
        result.wasm_hash, MULTISIG_ACCOUNT_WASM_SHA256,
        "wasm_hash must match the pinned multisig WASM hash"
    );
    assert_redacted_tx_hash_eq!(result.upload_tx_hash.as_deref(), UPLOAD_TX_HASH);
    assert_redacted_tx_hash_eq!(result.tx_hash.as_deref(), DEPLOY_TX_HASH);
    assert_eq!(result.ledger, Some(1001));
    assert!(
        result.wasm_uploaded,
        "result must report an upload occurred"
    );
    assert_eq!(result.initial_signer, INITIAL_SIGNER_G);
    assert_eq!(result.selected_fee_per_op_stroops, 100);
    assert_eq!(result.selected_fee_percentile, "profile_default");
}

#[tokio::test]
async fn upload_get_transaction_timeout_returns_upload_phase() {
    let server = MockServer::start().await;
    let (deployer_g, seed) = fresh_keypair();

    let responder =
        StatefulSorobanRpcResponder::new(&deployer_g, 100).with_upload_get_tx_pending_forever();
    let upload_get_tx_count = responder.upload_get_tx_count_handle();
    let upload_count = responder.upload_send_count_handle();
    let deploy_count = responder.deploy_send_count_handle();

    Mock::given(method("POST"))
        .respond_with(responder)
        .mount(&server)
        .await;

    let args = stateful_deploy_args(
        seed,
        "test-upload-poll-timeout",
        server.uri(),
        [0x56u8; 32],
        Duration::from_secs(3),
    );

    let err = deploy_smart_account(args, None)
        .await
        .expect_err("upload getTransaction timeout must cause an upload-phase error");

    assert!(
        matches!(
            err,
            SaError::DeploymentFailed {
                phase: "upload",
                ..
            }
        ),
        "upload polling timeout must map to DeploymentFailed {{ phase: \"upload\" }}; got: {err:?}"
    );
    assert!(
        upload_get_tx_count.load(Ordering::Acquire) >= 1,
        "upload hash must be polled at least once; count = {}; err = {err:?}",
        upload_get_tx_count.load(Ordering::Acquire)
    );
    assert_eq!(
        upload_count.load(Ordering::Acquire),
        1,
        "upload sendTransaction must be issued once before polling timeout"
    );
    assert_eq!(
        deploy_count.load(Ordering::Acquire),
        0,
        "no deploy sendTransaction must be issued after upload polling timeout"
    );
}

#[tokio::test]
async fn wasm_preflight_rpc_error_returns_build_phase_and_pre_submission_refused() {
    let server = MockServer::start().await;
    let (deployer_g, seed) = fresh_keypair();

    let responder =
        StatefulSorobanRpcResponder::new(&deployer_g, 100).with_wasm_preflight_rpc_error();
    let upload_count = responder.upload_send_count_handle();
    let deploy_count = responder.deploy_send_count_handle();

    Mock::given(method("POST"))
        .respond_with(responder)
        .mount(&server)
        .await;

    let args = stateful_deploy_args(
        seed,
        "test-wasm-preflight-rpc-error",
        server.uri(),
        [0x57u8; 32],
        Duration::from_secs(10),
    );
    let (mut writer, dir) = tmp_audit_writer();

    let err = deploy_smart_account(args, Some(&mut writer))
        .await
        .expect_err("WASM pre-flight RPC error must cause a build-phase error");
    drop(writer);

    assert!(
        matches!(err, SaError::DeploymentFailed { phase: "build", .. }),
        "WASM pre-flight RPC error must map to DeploymentFailed {{ phase: \"build\" }}; got: {err:?}"
    );
    assert_eq!(
        upload_count.load(Ordering::Acquire),
        0,
        "no upload sendTransaction must be issued after WASM pre-flight failure"
    );
    assert_eq!(
        deploy_count.load(Ordering::Acquire),
        0,
        "no deploy sendTransaction must be issued after WASM pre-flight failure"
    );

    let entries = read_audit_entries(&dir);
    assert_eq!(
        entries.len(),
        1,
        "WASM pre-flight failure must emit exactly one audit entry: {entries:#?}"
    );
    assert_eq!(
        entries[0]["kind"], "sa_raw_invocation",
        "WASM pre-flight failure must emit sa_raw_invocation: {}",
        entries[0]
    );
    assert_eq!(
        entries[0]["result"], "pre_submission_refused",
        "WASM pre-flight build-phase failure must map to PreSubmissionRefused: {}",
        entries[0]
    );
}

#[tokio::test]
async fn upload_signing_failure_returns_build_phase_and_pre_submission_refused() {
    let server = MockServer::start().await;
    let (deployer_g, args, sign_calls) = stateful_deploy_args_with_failing_signer(
        1,
        "test-upload-signing-failure",
        server.uri(),
        [0x58u8; 32],
        Duration::from_secs(10),
    );

    let responder = StatefulSorobanRpcResponder::new(&deployer_g, 100);
    let upload_count = responder.upload_send_count_handle();
    let deploy_count = responder.deploy_send_count_handle();

    Mock::given(method("POST"))
        .respond_with(responder)
        .mount(&server)
        .await;

    let (mut writer, dir) = tmp_audit_writer();
    let err = deploy_smart_account(args, Some(&mut writer))
        .await
        .expect_err("upload signing failure must cause a build-phase error");
    drop(writer);

    assert!(
        matches!(err, SaError::DeploymentFailed { phase: "build", .. }),
        "upload signing failure must map to DeploymentFailed {{ phase: \"build\" }}; got: {err:?}"
    );
    assert_eq!(sign_calls.load(Ordering::Acquire), 1);
    assert_eq!(upload_count.load(Ordering::Acquire), 0);
    assert_eq!(deploy_count.load(Ordering::Acquire), 0);

    let entries = read_audit_entries(&dir);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["kind"], "sa_raw_invocation");
    assert_eq!(entries[0]["result"], "pre_submission_refused");
}

#[tokio::test]
async fn deploy_signing_failure_returns_build_phase_and_pre_submission_refused() {
    let server = MockServer::start().await;
    let (deployer_g, args, sign_calls) = stateful_deploy_args_with_failing_signer(
        2,
        "test-deploy-signing-failure",
        server.uri(),
        [0x59u8; 32],
        Duration::from_secs(10),
    );

    let responder = StatefulSorobanRpcResponder::new(&deployer_g, 100);
    let wasm_uploaded = responder.wasm_uploaded_handle();
    let upload_count = responder.upload_send_count_handle();
    let deploy_count = responder.deploy_send_count_handle();

    Mock::given(method("POST"))
        .respond_with(responder)
        .mount(&server)
        .await;

    let (mut writer, dir) = tmp_audit_writer();
    let err = deploy_smart_account(args, Some(&mut writer))
        .await
        .expect_err("deploy signing failure must cause a build-phase error");
    drop(writer);

    assert!(
        matches!(err, SaError::DeploymentFailed { phase: "build", .. }),
        "deploy signing failure must map to DeploymentFailed {{ phase: \"build\" }}; got: {err:?}"
    );
    assert_eq!(sign_calls.load(Ordering::Acquire), 2);
    assert!(
        wasm_uploaded.load(Ordering::Acquire),
        "upload must complete before deploy signing fails"
    );
    assert_eq!(upload_count.load(Ordering::Acquire), 1);
    assert_eq!(deploy_count.load(Ordering::Acquire), 0);

    let entries = read_audit_entries(&dir);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["kind"], "sa_raw_invocation");
    assert_eq!(entries[0]["result"], "pre_submission_refused");
}

/// Simulate error on upload: `simulateTransaction` for the `UploadContractWasm` op
/// returns an `error` field.
///
/// Verifies that the panic-insulation pre-check in `deploy.rs` catches the
/// `simulate.error` field and surfaces `DeploymentFailed { phase: "simulate", .. }`
/// before any `sendTransaction` is issued.
///
/// Asserts:
/// - `upload_send_count = 0` (no `sendTransaction` issued).
/// - `deploy_send_count = 0` (no deploy attempted).
/// - Error is `DeploymentFailed { phase: "simulate", .. }`.
#[tokio::test]
async fn upload_simulation_error_returns_simulate_phase() {
    let server = MockServer::start().await;
    let (deployer_g, seed) = fresh_keypair();

    let responder =
        StatefulSorobanRpcResponder::new(&deployer_g, 100).with_simulate_error_on_upload();
    let upload_count = responder.upload_send_count_handle();
    let deploy_count = responder.deploy_send_count_handle();

    Mock::given(method("POST"))
        .respond_with(responder)
        .mount(&server)
        .await;

    let args = stateful_deploy_args(
        seed,
        "test-upload-sim-error",
        server.uri(),
        [0x66u8; 32],
        Duration::from_secs(10),
    );

    let err = deploy_smart_account(args, None)
        .await
        .expect_err("upload simulate error must cause an error");

    assert_eq!(
        upload_count.load(Ordering::Acquire),
        0,
        "no upload sendTransaction must be issued when simulate fails; count = {}",
        upload_count.load(Ordering::Acquire)
    );
    assert_eq!(
        deploy_count.load(Ordering::Acquire),
        0,
        "no deploy sendTransaction must be issued when upload simulate fails; count = {}",
        deploy_count.load(Ordering::Acquire)
    );

    assert!(
        matches!(
            err,
            SaError::DeploymentFailed {
                phase: "simulate",
                ..
            }
        ),
        "upload simulate error must map to DeploymentFailed {{ phase: \"simulate\" }}; got: {err:?}"
    );
}

/// Send error on upload: `simulateTransaction` succeeds but `sendTransaction`
/// for the `UploadContractWasm` op returns a JSON-RPC error.
///
/// Verifies that `submit_transaction_and_wait` surfaces the send failure as a
/// `SubmissionError::TxMalformed` envelope rejection, mapping to
/// `DeploymentFailed { phase: "submit", .. }`, and that no deploy tx is attempted.
///
/// Asserts:
/// - `upload_send_count = 1` (the upload `sendTransaction` was issued).
/// - `deploy_send_count = 0` (no deploy attempted after upload failure).
/// - Error is `DeploymentFailed { phase: "submit", .. }`.
#[tokio::test]
async fn upload_jsonrpc_envelope_error_returns_submit_phase() {
    let server = MockServer::start().await;
    let (deployer_g, seed) = fresh_keypair();

    let responder = StatefulSorobanRpcResponder::new(&deployer_g, 100).with_send_error_on_upload();
    let upload_count = responder.upload_send_count_handle();
    let deploy_count = responder.deploy_send_count_handle();

    Mock::given(method("POST"))
        .respond_with(responder)
        .mount(&server)
        .await;

    let args = stateful_deploy_args(
        seed,
        "test-upload-send-error",
        server.uri(),
        [0x77u8; 32],
        Duration::from_secs(10),
    );

    let err = deploy_smart_account(args, None)
        .await
        .expect_err("upload send error must cause an error");

    assert_eq!(
        upload_count.load(Ordering::Acquire),
        1,
        "exactly one upload sendTransaction must have been issued; count = {}",
        upload_count.load(Ordering::Acquire)
    );
    assert_eq!(
        deploy_count.load(Ordering::Acquire),
        0,
        "no deploy sendTransaction must be issued after upload send failure; count = {}",
        deploy_count.load(Ordering::Acquire)
    );

    assert!(
        matches!(
            err,
            SaError::DeploymentFailed {
                phase: "submit",
                ..
            }
        ),
        "upload send error must map to DeploymentFailed {{ phase: \"submit\" }}; got: {err:?}"
    );
}

#[tokio::test]
async fn upload_status_error_with_tx_malformed_xdr_returns_submit_phase() {
    let server = MockServer::start().await;
    let (deployer_g, seed) = fresh_keypair();

    let responder =
        StatefulSorobanRpcResponder::new(&deployer_g, 100).with_upload_send_error_typed_malformed();
    let upload_count = responder.upload_send_count_handle();
    let deploy_count = responder.deploy_send_count_handle();

    Mock::given(method("POST"))
        .respond_with(responder)
        .mount(&server)
        .await;

    let args = stateful_deploy_args(
        seed,
        "test-upload-send-typed-malformed",
        server.uri(),
        [0x7Bu8; 32],
        Duration::from_secs(10),
    );

    let err = deploy_smart_account(args, None)
        .await
        .expect_err("upload txMalformed send error must cause a submit-phase error");

    assert_eq!(
        upload_count.load(Ordering::Acquire),
        1,
        "exactly one upload sendTransaction must have been issued; count = {}",
        upload_count.load(Ordering::Acquire)
    );
    assert_eq!(
        deploy_count.load(Ordering::Acquire),
        0,
        "no deploy sendTransaction must be issued after upload send failure; count = {}",
        deploy_count.load(Ordering::Acquire)
    );
    assert!(
        matches!(
            err,
            SaError::DeploymentFailed {
                phase: "submit",
                ..
            }
        ),
        "upload txMalformed send error must map to DeploymentFailed {{ phase: \"submit\" }}; got: {err:?}"
    );
}

#[tokio::test]
async fn deploy_simulation_error_after_successful_upload_returns_simulate_phase() {
    let server = MockServer::start().await;
    let (deployer_g, seed) = fresh_keypair();

    let responder = StatefulSorobanRpcResponder::new(&deployer_g, 100).with_deploy_simulate_error();
    let wasm_uploaded = responder.wasm_uploaded_handle();
    let upload_count = responder.upload_send_count_handle();
    let deploy_count = responder.deploy_send_count_handle();

    Mock::given(method("POST"))
        .respond_with(responder)
        .mount(&server)
        .await;

    let args = stateful_deploy_args(
        seed,
        "test-deploy-sim-error",
        server.uri(),
        [0x78u8; 32],
        Duration::from_secs(10),
    );

    let err = deploy_smart_account(args, None)
        .await
        .expect_err("deploy simulate error must cause a simulate-phase error");

    assert!(
        wasm_uploaded.load(Ordering::Acquire),
        "upload must have completed before deploy simulation fails"
    );
    assert_eq!(
        upload_count.load(Ordering::Acquire),
        1,
        "upload sendTransaction must be issued once"
    );
    assert_eq!(
        deploy_count.load(Ordering::Acquire),
        0,
        "deploy sendTransaction must not be issued when deploy simulation fails"
    );
    assert!(
        matches!(
            err,
            SaError::DeploymentFailed {
                phase: "simulate",
                ..
            }
        ),
        "deploy simulate error must map to DeploymentFailed {{ phase: \"simulate\" }}; got: {err:?}"
    );
}

#[tokio::test]
async fn deploy_send_error_after_successful_upload_returns_submit_phase() {
    let server = MockServer::start().await;
    let (deployer_g, seed) = fresh_keypair();

    let responder = StatefulSorobanRpcResponder::new(&deployer_g, 100).with_deploy_send_error();
    let wasm_uploaded = responder.wasm_uploaded_handle();
    let upload_count = responder.upload_send_count_handle();
    let deploy_count = responder.deploy_send_count_handle();

    Mock::given(method("POST"))
        .respond_with(responder)
        .mount(&server)
        .await;

    let args = stateful_deploy_args(
        seed,
        "test-deploy-send-error",
        server.uri(),
        [0x79u8; 32],
        Duration::from_secs(10),
    );

    let err = deploy_smart_account(args, None)
        .await
        .expect_err("deploy send error must cause a submit-phase error");

    assert!(
        wasm_uploaded.load(Ordering::Acquire),
        "upload must have completed before deploy send fails"
    );
    assert_eq!(
        upload_count.load(Ordering::Acquire),
        1,
        "upload sendTransaction must be issued once"
    );
    assert_eq!(
        deploy_count.load(Ordering::Acquire),
        1,
        "deploy sendTransaction must be issued exactly once"
    );
    assert!(
        matches!(
            err,
            SaError::DeploymentFailed {
                phase: "submit",
                ..
            }
        ),
        "deploy send error must map to DeploymentFailed {{ phase: \"submit\" }}; got: {err:?}"
    );
}

#[tokio::test]
async fn sequence_refetch_failure_between_txs_returns_build_phase() {
    let server = MockServer::start().await;
    let (deployer_g, seed) = fresh_keypair();

    let responder =
        StatefulSorobanRpcResponder::new(&deployer_g, 100).with_post_upload_account_fetch_failure();
    let wasm_uploaded = responder.wasm_uploaded_handle();
    let upload_count = responder.upload_send_count_handle();
    let deploy_count = responder.deploy_send_count_handle();

    Mock::given(method("POST"))
        .respond_with(responder)
        .mount(&server)
        .await;

    let args = stateful_deploy_args(
        seed,
        "test-sequence-refetch-failure",
        server.uri(),
        [0x7Au8; 32],
        Duration::from_secs(10),
    );

    let err = deploy_smart_account(args, None)
        .await
        .expect_err("post-upload deployer account re-fetch failure must cause an error");

    assert!(
        wasm_uploaded.load(Ordering::Acquire),
        "upload must have completed before sequence re-fetch fails"
    );
    assert_eq!(
        upload_count.load(Ordering::Acquire),
        1,
        "upload sendTransaction must be issued once"
    );
    assert_eq!(
        deploy_count.load(Ordering::Acquire),
        0,
        "deploy sendTransaction must not be issued when sequence re-fetch fails"
    );
    assert!(
        matches!(err, SaError::DeploymentFailed { phase: "build", .. }),
        "post-upload sequence re-fetch error must map to DeploymentFailed {{ phase: \"build\" }}; got: {err:?}"
    );
}
