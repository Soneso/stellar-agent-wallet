//! Testnet acceptance: `stellar-agent pay` under an owner-signed V1 policy
//! `per_tx_cap` rule — over-cap denies (no submission), under-cap submits.
//!
//! This is the live, on-chain proof that a `PolicyEngineV1` document actually
//! governs the `pay` subcommand end to end: signature verification, scope
//! resolution, `per_tx_cap` evaluation, and (on allow) the real
//! build-sign-submit pipeline, all driven as a subprocess against the real
//! `stellar-agent` binary (the CLI crate has no `[lib]` target, so it cannot
//! be exercised in-process — the `claim_testnet_acceptance.rs` precedent).
//!
//! # Fixture setup
//!
//! A fresh temp directory stands in for `STELLAR_AGENT_HOME` (only ever set on
//! the CHILD process's environment, never the test-process environment):
//!
//! 1. An ed25519 owner keypair is generated in-process (never touches the OS
//!    keyring).
//! 2. A signed V1 policy document — one `per_tx_cap` rule matching
//!    `stellar_pay` on `stellar:testnet`, cap 100 XLM — is built with the
//!    REAL primitives `sign_policy.rs` uses:
//!    `canonical_bytes` -> `digest` -> `sign`, and written to
//!    `<home>/policies/<profile>.toml` with a `[signature]` table
//!    (`owner_id` = owner G-strkey, `sig` = hex signature), mirroring exactly
//!    what `stellar_agent_core::policy::v1::loader::load_signed_policy`
//!    expects (verified against the loader's own test fixtures in
//!    `stellar-agent-core/src/policy/v1/loader.rs`).
//! 3. A profile TOML with `policy.engine = "v1"` and
//!    `policy_owner_key_id.service = "stellar-agent-owner-<profile>"` (the
//!    prefix `build_v1_policy_engine` strips to recover the profile name) is
//!    written to `<home>/profiles/<profile>.toml`.
//! 4. The owner PUBLIC key (base64 URL-safe-no-pad) is written to a file; the
//!    child process's `STELLAR_AGENT_TEST_OWNER_PUBKEY_FILE` env var points at
//!    it, routing `commands::policy_engine::owner_pubkey_b64`'s gated
//!    test-only file source instead of the OS keyring.
//! 5. A source and a destination account are generated and Friendbot-funded
//!    (native `pay` requires an existing destination).
//!
//! # Scenarios
//!
//! - **Over-cap** (150 XLM > 100 XLM cap): the CLI exits `1`; stdout is a
//!   single JSON envelope with `error.code ==
//!   "policy.deny.per_tx_cap_exceeded"` and no `data` key at all (so no
//!   `tx_hash`); on-chain, the source account's sequence number and balance
//!   are unchanged — nothing was submitted.
//! - **Under-cap** (10 XLM <= 100 XLM cap): the CLI exits `0`; stdout carries
//!   a `data.tx_hash` (64-hex) and `data.ledger`; on-chain, the destination's
//!   native balance strictly increased.
//!
//! Both invocations reuse the same source/destination pair (the over-cap
//! refusal happens before signing, so it does not consume a sequence number).
//!
//! Gated behind `testnet-acceptance`:
//!
//! ```text
//! cargo test -p stellar-agent-cli --features testnet-acceptance \
//!   --test pay_policy_v1_testnet_acceptance
//! ```

#![cfg(feature = "testnet-acceptance")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics and unwraps are acceptable in testnet acceptance tests"
)]

use std::process::Command;
use std::time::Duration;

use base64::Engine as _;
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use stellar_agent_network::{StellarRpcClient, fetch_account};
use zeroize::Zeroizing;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";
const TESTNET_FRIENDBOT_URL: &str = "https://friendbot.stellar.org";

/// Must match `crates/stellar-agent-cli/src/commands/policy_engine.rs`'s
/// `OWNER_KEY_SERVICE_PREFIX`. The service field of a profile's
/// `policy_owner_key_id` is `"{OWNER_KEY_SERVICE_PREFIX}{profile_name}"`;
/// `build_v1_policy_engine` strips this prefix to recover the profile name it
/// uses for both the owner-key lookup and the policy-file path.
const OWNER_KEY_SERVICE_PREFIX: &str = "stellar-agent-owner-";

/// Profile / policy scope name used throughout this test.
const PROFILE_NAME: &str = "pay-v1-acceptance";

/// The `per_tx_cap` rule's cap: 100 XLM, in stroops.
const CAP_STROOPS: i64 = 1_000_000_000;

/// Name of the env var the spawned `stellar-agent pay` process reads the
/// source account's S-strkey secret from. Set only on the child process.
const PAY_SECRET_ENV_VAR: &str = "PAY_POLICY_V1_ACCEPTANCE_SECRET";

/// Name of the env var pointing the child process's gated owner-PUBLIC-key
/// file source (`commands::policy_engine::owner_pubkey_b64`) at the fixture
/// file. Must match the constant of the same name in `policy_engine.rs`.
const OWNER_PUBKEY_FILE_ENV_VAR: &str = "STELLAR_AGENT_TEST_OWNER_PUBKEY_FILE";

// ─────────────────────────────────────────────────────────────────────────────
// Keypair / funding helpers (mirrors `claim_testnet_acceptance.rs`)
// ─────────────────────────────────────────────────────────────────────────────

fn fresh_keypair() -> (String, Zeroizing<[u8; 32]>) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let g_strkey = stellar_strkey::ed25519::PublicKey(signing_key.verifying_key().to_bytes())
        .to_string()
        .to_string();
    (g_strkey, Zeroizing::new(signing_key.to_bytes()))
}

async fn fund_via_friendbot(g_strkey: &str) {
    let url = format!("{TESTNET_FRIENDBOT_URL}?addr={g_strkey}");
    let resp = reqwest::get(&url)
        .await
        .expect("Friendbot HTTP request must succeed");
    assert!(
        resp.status().is_success(),
        "Friendbot must return 2xx for {g_strkey}; got {}",
        resp.status()
    );
}

/// Polls RPC until the freshly-funded account is queryable, tolerating
/// Friendbot/RPC eventual consistency.
async fn wait_until_account_queryable(client: &StellarRpcClient, g_strkey: &str) {
    for _ in 0..30 {
        if fetch_account(client, g_strkey, &[]).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("funded account {g_strkey} did not become RPC-queryable in time");
}

/// Returns `(sequence_number, native_balance_stroops)` for `g_strkey`.
async fn account_state(client: &StellarRpcClient, g_strkey: &str) -> (i64, i64) {
    let account = fetch_account(client, g_strkey, &[])
        .await
        .expect("account fetch must succeed");
    let balance = account
        .balances
        .first()
        .and_then(|b| b.balance_stroops().ok())
        .expect("account must hold a native balance");
    (account.sequence_number, balance)
}

// ─────────────────────────────────────────────────────────────────────────────
// Policy / profile fixture construction
// ─────────────────────────────────────────────────────────────────────────────

/// Writes a minimal, valid v2 profile TOML with `policy.engine = "v1"` and
/// `policy_owner_key_id.service = "<OWNER_KEY_SERVICE_PREFIX><profile>"` to
/// `<home>/profiles/<profile>.toml`.
///
/// Mirrors the minimal profile shape the loader's own `load_minimal_valid_profile`
/// test fixture uses (`stellar-agent-core/src/profile/loader.rs`).
fn write_profile_toml(home: &std::path::Path, profile: &str) {
    let dir = home.join("profiles");
    std::fs::create_dir_all(&dir).expect("create profiles dir");
    let toml = format!(
        "version = 2\n\
         chain_id = \"stellar:testnet\"\n\n\
         [mcp_signer_default]\n\
         service = \"stellar-agent-signer\"\n\
         account = \"default\"\n\n\
         [mcp_nonce_key_alias]\n\
         service = \"stellar-agent-nonce\"\n\
         account = \"default\"\n\n\
         [audit_log_hash_chain_key_id]\n\
         service = \"stellar-agent-audit-{profile}\"\n\
         account = \"default\"\n\n\
         [policy_owner_key_id]\n\
         service = \"{OWNER_KEY_SERVICE_PREFIX}{profile}\"\n\
         account = \"default\"\n\n\
         [attestation_key_id]\n\
         service = \"stellar-agent-attestation-{profile}\"\n\
         account = \"default\"\n\n\
         [counterparty_cache_key_id]\n\
         service = \"stellar-agent-counterparty-{profile}\"\n\
         account = \"default\"\n\n\
         [policy]\n\
         engine = \"v1\"\n"
    );
    std::fs::write(dir.join(format!("{profile}.toml")), toml).expect("write profile toml");
}

/// Builds, signs (with the REAL `canonical_bytes` -> `digest` -> `sign`
/// primitives `profile sign-policy` uses), and writes a V1 policy document
/// with a single `per_tx_cap` rule (`stellar_pay`, `native`, `CAP_STROOPS`) to
/// `<home>/policies/<profile>.toml`.
///
/// Returns the owner's 32-byte public key.
fn write_signed_policy_toml(
    home: &std::path::Path,
    profile: &str,
    owner_signing_key: &SigningKey,
) -> [u8; 32] {
    let owner_pubkey = owner_signing_key.verifying_key().to_bytes();

    let policy_body = format!(
        "version = 1\n\
         scope = \"profile:{profile}\"\n\n\
         [[rules]]\n\
         match = {{ tool = \"stellar_pay\", chain = \"*\" }}\n\
         criteria = [{{ kind = \"per_tx_cap\", asset = \"native\", max_stroops = {CAP_STROOPS} }}]\n\
         decision = \"allow\"\n"
    );

    let canon = stellar_agent_core::policy::v1::canonical::canonical_bytes(&policy_body)
        .expect("canonical_bytes must succeed for well-formed policy");
    let policy_digest = stellar_agent_core::policy::v1::signature::digest(&canon);
    let sig: [u8; 64] =
        stellar_agent_core::policy::v1::signature::sign(&policy_digest, owner_signing_key);
    let sig_hex: String = sig.iter().map(|b| format!("{b:02x}")).collect();
    let owner_g = stellar_strkey::ed25519::PublicKey(owner_pubkey)
        .to_string()
        .to_string();

    let signed =
        format!("{policy_body}\n[signature]\nowner_id = \"{owner_g}\"\nsig = \"{sig_hex}\"\n");

    let dir = home.join("policies");
    std::fs::create_dir_all(&dir).expect("create policies dir");
    std::fs::write(dir.join(format!("{profile}.toml")), signed).expect("write policy toml");

    owner_pubkey
}

/// Writes the owner public key (base64 URL-safe-no-pad) to
/// `<home>/owner_pubkey.txt` and returns the path.
fn write_owner_pubkey_file(home: &std::path::Path, owner_pubkey: &[u8; 32]) -> std::path::PathBuf {
    let path = home.join("owner_pubkey.txt");
    std::fs::write(
        &path,
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(owner_pubkey),
    )
    .expect("write owner pubkey file");
    path
}

// ─────────────────────────────────────────────────────────────────────────────
// Subprocess invocation helper
// ─────────────────────────────────────────────────────────────────────────────

/// Spawns `stellar-agent pay <destination> <amount>` with `STELLAR_AGENT_HOME`
/// and the owner-pubkey-file override set on the CHILD process only, and
/// returns `(exit_code, stdout_json_envelope)`.
fn run_pay(
    home: &std::path::Path,
    owner_pubkey_file: &std::path::Path,
    source_g: &str,
    source_secret: &str,
    destination_g: &str,
    amount: &str,
) -> (i32, serde_json::Value) {
    let bin_path = env!("CARGO_BIN_EXE_stellar-agent");
    let output = Command::new(bin_path)
        .args([
            "pay",
            destination_g,
            amount,
            "--source",
            source_g,
            "--secret-env",
            PAY_SECRET_ENV_VAR,
            "--profile",
            PROFILE_NAME,
            "--network",
            "testnet",
            "--rpc-url",
            TESTNET_RPC_URL,
        ])
        .env(PAY_SECRET_ENV_VAR, source_secret)
        .env("STELLAR_AGENT_HOME", home)
        .env(OWNER_PUBKEY_FILE_ENV_VAR, owner_pubkey_file)
        .output()
        .expect("stellar-agent pay subprocess must spawn");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

    let lines: Vec<&str> = stdout.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(
        lines.len(),
        1,
        "expected exactly one JSON envelope line on stdout; got {}: stdout={stdout} stderr={stderr}",
        lines.len()
    );
    let envelope: serde_json::Value = serde_json::from_str(lines[0])
        .unwrap_or_else(|e| panic!("stdout line must be valid JSON ({e}): {}", lines[0]));

    let exit_code = output
        .status
        .code()
        .unwrap_or_else(|| panic!("process must exit with a status code; stderr={stderr}"));
    (exit_code, envelope)
}

// ─────────────────────────────────────────────────────────────────────────────
// Test
// ─────────────────────────────────────────────────────────────────────────────

/// `stellar-agent pay` under a V1 operator policy with a `per_tx_cap` rule:
/// an over-cap payment is refused pre-signing (no on-chain effect); an
/// under-cap payment runs the full build-sign-submit pipeline and reaches
/// ledger inclusion.
#[tokio::test]
async fn pay_v1_per_tx_cap_denies_over_cap_and_submits_under_cap() {
    let home = tempfile::TempDir::new().expect("tempdir");

    // ── Fixture: owner keypair, signed policy, profile, pubkey file ──────────
    let owner_signing_key = SigningKey::generate(&mut OsRng);
    let owner_pubkey = write_signed_policy_toml(home.path(), PROFILE_NAME, &owner_signing_key);
    write_profile_toml(home.path(), PROFILE_NAME);
    let owner_pubkey_file = write_owner_pubkey_file(home.path(), &owner_pubkey);

    // ── Fixture: source + destination accounts ────────────────────────────────
    let (source_g, source_seed) = fresh_keypair();
    let (dest_g, _dest_seed) = fresh_keypair();
    fund_via_friendbot(&source_g).await;
    fund_via_friendbot(&dest_g).await;

    let client = StellarRpcClient::new(TESTNET_RPC_URL).expect("RPC client");
    wait_until_account_queryable(&client, &source_g).await;
    wait_until_account_queryable(&client, &dest_g).await;

    let source_s_strkey: String =
        stellar_strkey::ed25519::PrivateKey::from_payload(source_seed.as_ref())
            .expect("32-byte seed encodes as S-strkey")
            .as_unredacted()
            .to_string()
            .as_str()
            .to_owned();

    // ── Scenario 1: OVER-CAP (150 XLM > 100 XLM cap) ──────────────────────────
    let (source_seq_before, source_balance_before) = account_state(&client, &source_g).await;

    let (exit_code, envelope) = run_pay(
        home.path(),
        &owner_pubkey_file,
        &source_g,
        &source_s_strkey,
        &dest_g,
        "150 XLM",
    );

    assert_eq!(
        exit_code, 1,
        "an over-cap payment must exit 1; envelope={envelope}"
    );
    assert_eq!(
        envelope["ok"].as_bool(),
        Some(false),
        "envelope must be ok=false: {envelope}"
    );
    assert_eq!(
        envelope["error"]["code"].as_str(),
        Some("policy.deny.per_tx_cap_exceeded"),
        "over-cap denial must carry the per_tx_cap_exceeded wire code: {envelope}"
    );
    assert!(
        envelope.get("data").is_none(),
        "a refused payment must carry no `data` (and therefore no tx_hash): {envelope}"
    );

    let (source_seq_after, source_balance_after) = account_state(&client, &source_g).await;
    assert_eq!(
        source_seq_after, source_seq_before,
        "the source account's sequence number must be unchanged: nothing was submitted"
    );
    assert_eq!(
        source_balance_after, source_balance_before,
        "the source account's native balance must be unchanged: nothing was submitted"
    );

    // ── Scenario 2: UNDER-CAP (10 XLM <= 100 XLM cap) ─────────────────────────
    let (_dest_seq_before, dest_balance_before) = account_state(&client, &dest_g).await;

    let (exit_code, envelope) = run_pay(
        home.path(),
        &owner_pubkey_file,
        &source_g,
        &source_s_strkey,
        &dest_g,
        "10 XLM",
    );

    assert_eq!(
        exit_code, 0,
        "an under-cap payment must exit 0; envelope={envelope}"
    );
    assert_eq!(
        envelope["ok"].as_bool(),
        Some(true),
        "envelope must be ok=true: {envelope}"
    );
    let tx_hash = envelope["data"]["tx_hash"]
        .as_str()
        .expect("under-cap payment result must carry a tx_hash");
    assert_eq!(tx_hash.len(), 64, "tx_hash must be a 32-byte hex digest");
    assert!(
        envelope["data"]["ledger"].as_u64().is_some(),
        "under-cap payment result must carry a ledger sequence: {envelope}"
    );

    // ── On-chain effect: destination balance strictly increased ──────────────
    let (_dest_seq_after, dest_balance_after) = account_state(&client, &dest_g).await;
    assert!(
        dest_balance_after > dest_balance_before,
        "destination native balance must strictly increase after the under-cap payment \
         (before={dest_balance_before}, after={dest_balance_after})"
    );
}
