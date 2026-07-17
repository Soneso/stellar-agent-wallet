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
//! the CHILD process's environment, never the test-process environment). The
//! profile name is unique per test run (`pay-v1-acceptance-<pid>-<unix_secs>`)
//! so the OS keyring coordinate it drives (below) never collides with a
//! concurrent or prior local run.
//!
//! 1. An ed25519 owner keypair is generated in-process.
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
//! 4. The owner **PUBLIC** key is enrolled into the REAL OS keyring by
//!    spawning `stellar-agent profile enroll-owner-key --secret-env <VAR>
//!    --expected-address <owner_g>` as its own subprocess (the owner seed is
//!    set only on that subprocess's environment) — the production write path
//!    `enroll_owner_key.rs` drives, at the exact coordinate
//!    `commands::policy_engine::owner_pubkey_b64`'s production (non-test)
//!    branch reads from at gate time. No test-only file override is used
//!    anywhere in this suite.
//! 5. A source and a destination account are generated and Friendbot-funded
//!    (native `pay` requires an existing destination).
//!
//! # Cleanup
//!
//! The enrolled owner-key keyring entry is deleted by an RAII guard that runs
//! on every exit path (success, assertion failure, or early return) so a
//! panicking assertion never leaks a keyring entry — belt-and-suspenders on
//! top of the per-run unique profile name.
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
//! # Coverage: the full production owner-key read path
//!
//! This suite covers the FULL production path for the owner coordinate:
//! profile load -> `enroll-owner-key` keyring registration (subprocess) ->
//! `pay`'s V1 gate reading the owner public key from that SAME OS keyring
//! entry -> signature verification -> `per_tx_cap` evaluation -> (on allow)
//! sign -> submit -> confirm. The window-state HMAC key and generation
//! counter already round-trip the real keyring in this same suite (via
//! `PersistedWindowStore`, unconditionally, no test-only override exists for
//! that coordinate); the owner coordinate now exercises the identical
//! keyring backend end to end.
//!
//! # Platform keyring precondition
//!
//! The v1 policy path registers the platform keyring store before the gate
//! and refuses when registration fails, so this suite requires a functioning
//! platform keyring (macOS Keychain in local dev; a headless Secret Service,
//! provisioned by the CI workflow via gnome-keyring, in CI). Keyring init
//! failure fails this test — it is not an infrastructure precondition to be
//! skipped.
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

/// The `per_tx_cap` rule's cap: 100 XLM, in stroops.
const CAP_STROOPS: i64 = 1_000_000_000;

/// Name of the env var the spawned `stellar-agent pay` process reads the
/// source account's S-strkey secret from. Set only on the child process.
const PAY_SECRET_ENV_VAR: &str = "PAY_POLICY_V1_ACCEPTANCE_SECRET";

/// Name of the env var the spawned `stellar-agent profile enroll-owner-key`
/// process reads the owner account's S-strkey secret from. Set only on that
/// subprocess's environment, never the test-process environment.
const OWNER_SECRET_ENV_VAR: &str = "PAY_POLICY_V1_ACCEPTANCE_OWNER_SECRET";

/// Builds a profile name unique to this test run: `pay-v1-acceptance-<pid>-<unix_secs>`.
///
/// The profile TOML and policy TOML live inside the test's own fresh
/// tempdir and so cannot collide across runs on their own, but the OS
/// keyring coordinate `enroll-owner-key` writes to
/// (`{OWNER_KEY_SERVICE_PREFIX}<profile>` / `"default"`) is OS-global, not
/// tempdir-scoped — the profile name must be unique per run so repeated
/// local runs (or a concurrent CI matrix) never collide on that entry.
fn unique_profile_name() -> String {
    let unix_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock must work")
        .as_secs();
    format!("pay-v1-acceptance-{}-{unix_secs}", std::process::id())
}

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

/// Mints the profile's audit chain-root key by spawning
/// `stellar-agent profile rotate-audit-key` as its own subprocess — the exact
/// production mint path. Returns an [`OwnerKeyringGuard`] (the guard is
/// coordinate-generic) that removes the entry when dropped.
fn rotate_audit_key_via_cli(home: &std::path::Path, profile: &str) -> OwnerKeyringGuard {
    let bin_path = env!("CARGO_BIN_EXE_stellar-agent");
    let output = Command::new(bin_path)
        .args(["profile", "rotate-audit-key", profile])
        .env("STELLAR_AGENT_HOME", home)
        .output()
        .expect("spawn rotate-audit-key");
    assert!(
        output.status.success(),
        "rotate-audit-key must succeed: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    OwnerKeyringGuard {
        coord: stellar_agent_core::profile::schema::KeyringEntryRef::new(
            format!("stellar-agent-audit-{profile}"),
            "default",
        ),
    }
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
    let owner_g = stellar_strkey::ed25519::PublicKey(owner_pubkey).to_string();

    let signed =
        format!("{policy_body}\n[signature]\nowner_id = \"{owner_g}\"\nsig = \"{sig_hex}\"\n");

    let dir = home.join("policies");
    std::fs::create_dir_all(&dir).expect("create policies dir");
    std::fs::write(dir.join(format!("{profile}.toml")), signed).expect("write policy toml");

    owner_pubkey
}

// ─────────────────────────────────────────────────────────────────────────────
// Owner-key enrollment (real keyring) + cleanup guard
// ─────────────────────────────────────────────────────────────────────────────

/// RAII guard that deletes the enrolled owner-key keyring entry on drop
/// (success, assertion panic, or early return alike), so a failed test run
/// never leaks an entry into the OS keyring — belt-and-suspenders on top of
/// [`unique_profile_name`]'s per-run namespacing.
struct OwnerKeyringGuard {
    coord: stellar_agent_core::profile::schema::KeyringEntryRef,
}

impl Drop for OwnerKeyringGuard {
    fn drop(&mut self) {
        if let Ok(entry) = keyring_core::Entry::new(&self.coord.service, &self.coord.account) {
            // Best-effort: a delete failure here must not mask the test's own
            // pass/fail outcome (Drop cannot propagate an error), and a
            // leftover entry from a rare delete failure is harmless — the
            // per-run unique profile name means it will never collide with a
            // future run's own coordinate.
            let _ = entry.delete_credential();
        }
    }
}

/// Enrolls `owner_s_strkey`'s derived public key into the REAL OS keyring for
/// `profile`, by spawning `stellar-agent profile enroll-owner-key` as its own
/// subprocess — the exact production write path `enroll_owner_key.rs` drives.
///
/// The owner secret is set ONLY on the enrollment subprocess's environment,
/// never the test-process environment nor (afterwards) the `pay` subprocess's
/// environment: the owner key is a signing key the online agent must never
/// hold, only its enrolled public counterpart.
///
/// Returns an [`OwnerKeyringGuard`] that removes the entry when dropped.
fn enroll_owner_key_via_cli(
    home: &std::path::Path,
    profile: &str,
    owner_s_strkey: &str,
    owner_g_strkey: &str,
) -> OwnerKeyringGuard {
    let bin_path = env!("CARGO_BIN_EXE_stellar-agent");
    let output = Command::new(bin_path)
        .args([
            "profile",
            "enroll-owner-key",
            "--profile",
            profile,
            "--secret-env",
            OWNER_SECRET_ENV_VAR,
            "--expected-address",
            owner_g_strkey,
        ])
        .env(OWNER_SECRET_ENV_VAR, owner_s_strkey)
        .env("STELLAR_AGENT_HOME", home)
        .output()
        .expect("stellar-agent profile enroll-owner-key subprocess must spawn");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let exit_code = output.status.code().unwrap_or_else(|| {
        panic!("enroll-owner-key must exit with a status code; stderr={stderr}")
    });
    assert_eq!(
        exit_code, 0,
        "enroll-owner-key must succeed against a clean owner coordinate; stdout={stdout} stderr={stderr}"
    );
    let envelope: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("enroll-owner-key stdout must be valid JSON ({e}): {stdout}"));
    assert_eq!(
        envelope["ok"].as_bool(),
        Some(true),
        "enroll-owner-key envelope must be ok=true: {envelope}"
    );
    assert_eq!(
        envelope["data"]["enrolled"].as_bool(),
        Some(true),
        "enroll-owner-key envelope must report enrolled=true: {envelope}"
    );

    OwnerKeyringGuard {
        coord: stellar_agent_core::profile::schema::KeyringEntryRef::default_owner_key(profile),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Subprocess invocation helper
// ─────────────────────────────────────────────────────────────────────────────

/// Spawns `stellar-agent pay <destination> <amount>` with `STELLAR_AGENT_HOME`
/// and the owner-pubkey-file override set on the CHILD process only, and
/// returns `(exit_code, stdout_json_envelope)`.
fn run_pay(
    home: &std::path::Path,
    profile: &str,
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
            profile,
            "--network",
            "testnet",
            "--rpc-url",
            TESTNET_RPC_URL,
        ])
        .env(PAY_SECRET_ENV_VAR, source_secret)
        .env("STELLAR_AGENT_HOME", home)
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
    // The v1 policy path registers the platform keyring store before the gate
    // and refuses when registration fails, so this suite needs a functioning
    // platform keyring (macOS Keychain locally; a headless Secret Service,
    // provisioned by the CI workflow, on Linux CI runners).
    stellar_agent_network::init_platform_keyring_store()
        .expect("platform keyring store must initialise on this host");

    let home = tempfile::TempDir::new().expect("tempdir");
    let profile_name = unique_profile_name();

    // ── Fixture: owner keypair, signed policy, profile, real-keyring enrollment ─
    let owner_signing_key = SigningKey::generate(&mut OsRng);
    let owner_pubkey = write_signed_policy_toml(home.path(), &profile_name, &owner_signing_key);
    write_profile_toml(home.path(), &profile_name);

    let owner_g_strkey = stellar_strkey::ed25519::PublicKey(owner_pubkey).to_string();
    // `Unredacted::to_string` yields a stack-allocated heapless string (the
    // secret never touches an intermediate heap buffer); `as_str().to_owned()`
    // converts it to the owned String the env-var API needs.
    let owner_s_strkey: String = stellar_strkey::ed25519::PrivateKey(owner_signing_key.to_bytes())
        .as_unredacted()
        .to_string()
        .as_str()
        .to_owned();
    // Enroll the owner PUBLIC key through the REAL OS keyring via the
    // production `enroll-owner-key` subprocess; `_owner_keyring_guard` deletes
    // the entry when it drops at the end of this function (every exit path).
    let _owner_keyring_guard =
        enroll_owner_key_via_cli(home.path(), &profile_name, &owner_s_strkey, &owner_g_strkey);

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
        &profile_name,
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

    // ── Mint the audit chain-root key ─────────────────────────────────────────
    // Scenario 1 above ran WITHOUT a minted key on purpose: a policy denial
    // is a clean refusal that signs nothing and must not require audit
    // setup. The ALLOW path below is fail-closed on a persisted profile —
    // the submit must not proceed unaudited — so the key is minted here,
    // through the production rotate-audit-key subprocess.
    let _audit_key_guard = rotate_audit_key_via_cli(home.path(), &profile_name);

    // ── Scenario 2: UNDER-CAP (10 XLM <= 100 XLM cap) ─────────────────────────
    let (_dest_seq_before, dest_balance_before) = account_state(&client, &dest_g).await;

    let (exit_code, envelope) = run_pay(
        home.path(),
        &profile_name,
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
