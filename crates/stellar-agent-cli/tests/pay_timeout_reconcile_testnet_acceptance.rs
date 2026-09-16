//! Testnet acceptance: a payment whose confirmation does not arrive in time is
//! recorded, and `tx status` settles it against the chain.
//!
//! # What this proves on-chain
//!
//! A submission timeout is not a failure: the transaction was accepted for
//! inclusion and confirms a few seconds later. The wallet records it before it
//! is sent and resolves it afterwards by asking the chain, never by rebuilding
//! and re-submitting.
//!
//! Whether a submission's confirmation arrives inside the timeout depends on
//! where in the ledger cycle the send lands: the confirmation poll decides at
//! a point fixed by its own interval, and a ledger that closes before that
//! point confirms the transaction. The suite therefore issues payments at
//! offsets that sweep the cycle and runs its assertions against the first one
//! that times out. Every attempt is a real payment; a sweep in which none
//! times out fails the suite.
//!
//! # Scenario
//!
//! 1. `stellar-agent pay` under a signed V1 policy with a `per_period_cap`
//!    rule, so the submission takes a spending-window reservation.
//! 2. The CLI exits 1 with `error.code == "submission.tx_timeout"`, and
//!    `error.details` carries the full transaction hash, the envelope hash,
//!    and the verb that resolves it.
//! 3. `stellar-agent tx status <HASH>` reconciles the submission: the chain
//!    reports `SUCCESS`, the receipt becomes `success`, and the reservation
//!    becomes recorded spend.
//! 4. The audit log holds the pending row written before the send and the
//!    submitted row reconciliation wrote after.
//!
//! # Fixture setup
//!
//! Mirrors `pay_policy_v1_testnet_acceptance.rs`: a per-run unique profile
//! name, an owner keypair enrolled into the real OS keyring through
//! `profile enroll-owner-key`, a signed V1 policy document, and a
//! Friendbot-funded source and destination. Every keyring entry the fixture
//! writes is removed by an RAII guard.
//!
//! Gated behind `testnet-acceptance`:
//!
//! ```text
//! cargo test -p stellar-agent-cli --features testnet-acceptance \
//!   --test pay_timeout_reconcile_testnet_acceptance
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

const TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";
const TESTNET_FRIENDBOT_URL: &str = "https://friendbot.stellar.org";

/// Deadline on every HTTP request this suite makes.
const HTTP_TIMEOUT: Duration = Duration::from_secs(20);

/// Must match `commands::policy_engine`'s `OWNER_KEY_SERVICE_PREFIX`.
const OWNER_KEY_SERVICE_PREFIX: &str = "stellar-agent-owner-";

/// The `per_period_cap` rule's cap: 100 XLM, in stroops. The payment below is
/// far under it; the rule is there to make the submission take a
/// spending-window reservation.
const CAP_STROOPS: i64 = 1_000_000_000;

/// Submission timeout, in seconds. Below testnet's ledger-close interval, so
/// the confirmation poll can expire on a transaction that then lands, and
/// above the round trips the submit layer makes before the send, so the send
/// itself is never cut off.
const SUBMIT_TIMEOUT_SECONDS: &str = "3";

/// Delays, in milliseconds, applied after an observed ledger close before a
/// payment is issued.
///
/// They sweep one ledger cycle, so at least one attempt sends early enough in
/// the cycle for the confirmation poll to reach its decision point before the
/// next close.
const PHASE_OFFSETS_MS: [u64; 7] = [0, 600, 1_200, 1_800, 2_400, 3_000, 3_600];

/// The payment the suite makes. The unit label is part of the grammar the
/// CLI parses.
const PAY_AMOUNT: &str = "1 XLM";

const PAY_SECRET_ENV_VAR: &str = "PAY_TIMEOUT_ACCEPTANCE_SECRET";
const OWNER_SECRET_ENV_VAR: &str = "PAY_TIMEOUT_ACCEPTANCE_OWNER_SECRET";

fn unique_profile_name() -> String {
    let unix_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock must work")
        .as_secs();
    format!("pay-timeout-acceptance-{}-{unix_secs}", std::process::id())
}

fn fresh_keypair() -> (String, Zeroizing<[u8; 32]>) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let g_strkey = stellar_strkey::ed25519::PublicKey(signing_key.verifying_key().to_bytes())
        .to_string()
        .to_string();
    (g_strkey, Zeroizing::new(signing_key.to_bytes()))
}

/// An HTTP client whose requests cannot hang.
///
/// Every request this suite makes is to a public endpoint it does not control.
/// A request with no deadline turns a stalled connection into a test that
/// never finishes and never reports, which is worse than a failure: the suite
/// has to say what it found either way.
fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .build()
        .expect("HTTP client must build")
}

async fn fund_via_friendbot(g_strkey: &str) {
    let url = format!("{TESTNET_FRIENDBOT_URL}?addr={g_strkey}");
    let resp = http_client()
        .get(&url)
        .send()
        .await
        .expect("Friendbot HTTP request must succeed");
    assert!(
        resp.status().is_success(),
        "Friendbot must return 2xx for {g_strkey}; got {}",
        resp.status()
    );
}

async fn wait_until_account_queryable(client: &StellarRpcClient, g_strkey: &str) {
    for _ in 0..30 {
        if fetch_account(client, g_strkey, &[]).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("funded account {g_strkey} did not become RPC-queryable in time");
}

/// The ledger sequence the endpoint currently reports.
async fn latest_ledger_sequence(http: &reqwest::Client) -> u64 {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getLatestLedger",
    });
    let response: serde_json::Value = http
        .post(TESTNET_RPC_URL)
        .json(&body)
        .send()
        .await
        .expect("getLatestLedger request must succeed")
        .json()
        .await
        .expect("getLatestLedger must return JSON");
    response["result"]["sequence"]
        .as_u64()
        .unwrap_or_else(|| panic!("getLatestLedger must report a sequence: {response}"))
}

/// Blocks until the endpoint closes a ledger, which is the phase reference the
/// offsets are measured from.
async fn wait_for_a_fresh_ledger_close(http: &reqwest::Client) {
    let before = latest_ledger_sequence(http).await;
    for _ in 0..150 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        if latest_ledger_sequence(http).await > before {
            return;
        }
    }
    panic!("the endpoint closed no ledger within 30 seconds");
}

/// The rows of `kind` that name `envelope_hash`.
fn rows_for<'a>(
    rows: &'a [serde_json::Value],
    kind: &str,
    envelope_hash: &str,
) -> Vec<&'a serde_json::Value> {
    rows.iter()
        .filter(|r| r["kind"] == kind && r["envelope_hash"] == envelope_hash)
        .collect()
}

/// RAII guard that removes one keyring entry on drop.
struct KeyringGuard {
    coord: stellar_agent_core::profile::schema::KeyringEntryRef,
}

impl Drop for KeyringGuard {
    fn drop(&mut self) {
        if let Ok(entry) = keyring_core::Entry::new(&self.coord.service, &self.coord.account) {
            let _ = entry.delete_credential();
        }
    }
}

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

fn write_signed_policy_toml(home: &std::path::Path, profile: &str, owner: &SigningKey) {
    let policy_body = format!(
        "version = 1\n\
         scope = \"profile:{profile}\"\n\n\
         [[rules]]\n\
         match = {{ tool = \"*\", chain = \"*\" }}\n\
         criteria = [{{ kind = \"per_period_cap\", asset = \"native\", window = \"1d\", \
         max_stroops = {CAP_STROOPS} }}]\n\
         decision = \"allow\"\n"
    );

    let canon = stellar_agent_core::policy::v1::canonical::canonical_bytes(&policy_body)
        .expect("canonical_bytes must succeed for well-formed policy");
    let policy_digest = stellar_agent_core::policy::v1::signature::digest(&canon);
    let sig: [u8; 64] = stellar_agent_core::policy::v1::signature::sign(&policy_digest, owner);
    let sig_hex: String = sig.iter().map(|b| format!("{b:02x}")).collect();
    let owner_g = stellar_strkey::ed25519::PublicKey(owner.verifying_key().to_bytes()).to_string();

    let signed =
        format!("{policy_body}\n[signature]\nowner_id = \"{owner_g}\"\nsig = \"{sig_hex}\"\n");
    let dir = home.join("policies");
    std::fs::create_dir_all(&dir).expect("create policies dir");
    std::fs::write(dir.join(format!("{profile}.toml")), signed).expect("write policy toml");
}

fn rotate_audit_key_via_cli(home: &std::path::Path, profile: &str) -> KeyringGuard {
    let output = Command::new(env!("CARGO_BIN_EXE_stellar-agent"))
        .args(["profile", "rotate-audit-key", profile])
        .env("STELLAR_AGENT_HOME", home)
        .output()
        .expect("spawn rotate-audit-key");
    assert!(
        output.status.success(),
        "rotate-audit-key must succeed: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    KeyringGuard {
        coord: stellar_agent_core::profile::schema::KeyringEntryRef::new(
            format!("stellar-agent-audit-{profile}"),
            "default",
        ),
    }
}

fn enroll_owner_key_via_cli(
    home: &std::path::Path,
    profile: &str,
    owner_s_strkey: &str,
    owner_g_strkey: &str,
) -> KeyringGuard {
    let output = Command::new(env!("CARGO_BIN_EXE_stellar-agent"))
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
        .expect("spawn enroll-owner-key");
    assert!(
        output.status.success(),
        "enroll-owner-key must succeed: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    KeyringGuard {
        coord: stellar_agent_core::profile::schema::KeyringEntryRef::default_owner_key(profile),
    }
}

/// Removes the profile's window-state HMAC key and its generation counter,
/// both of which the first recorded submission mints in the real keyring.
fn window_state_guards(profile: &str) -> Vec<KeyringGuard> {
    let base =
        stellar_agent_core::profile::schema::KeyringEntryRef::default_policy_window_state_key(
            profile,
        );
    let generation = stellar_agent_core::profile::schema::KeyringEntryRef::new(
        base.service.clone(),
        format!("{}-generation", base.account),
    );
    vec![
        KeyringGuard { coord: base },
        KeyringGuard { coord: generation },
    ]
}

/// Runs one `stellar-agent` invocation and returns `(exit_code, envelope)`.
fn run_cli(
    home: &std::path::Path,
    args: &[&str],
    env: &[(&str, &str)],
) -> (i32, serde_json::Value) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_stellar-agent"));
    command.args(args).env("STELLAR_AGENT_HOME", home);
    for (key, value) in env {
        command.env(key, value);
    }
    let output = command
        .output()
        .expect("stellar-agent subprocess must spawn");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(
        lines.len(),
        1,
        "expected exactly one JSON envelope line; got {}: stdout={stdout} stderr={stderr}",
        lines.len()
    );
    let envelope: serde_json::Value = serde_json::from_str(lines[0])
        .unwrap_or_else(|e| panic!("stdout must be valid JSON ({e}): {}", lines[0]));
    let exit_code = output
        .status
        .code()
        .unwrap_or_else(|| panic!("process must exit with a status code; stderr={stderr}"));
    (exit_code, envelope)
}

/// The profile's audit log file.
fn audit_log_path(home: &std::path::Path, profile: &str) -> std::path::PathBuf {
    home.join("audit").join(format!("{profile}.jsonl"))
}

/// Every audit row the profile's log holds.
fn audit_rows(home: &std::path::Path, profile: &str) -> Vec<serde_json::Value> {
    let raw = std::fs::read_to_string(audit_log_path(home, profile)).unwrap_or_default();
    raw.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("each audit row must be JSON"))
        .collect()
}

/// A timed-out payment is recorded, reported with its hash, and settled by
/// `tx status` once the chain has it.
#[tokio::test]
async fn pay_timeout_is_recorded_and_tx_status_reconciles_it() {
    stellar_agent_network::init_platform_keyring_store()
        .expect("platform keyring store must initialise on this host");

    let home = tempfile::TempDir::new().expect("tempdir");
    let profile_name = unique_profile_name();

    let owner_signing_key = SigningKey::generate(&mut OsRng);
    let owner_g = stellar_strkey::ed25519::PublicKey(owner_signing_key.verifying_key().to_bytes())
        .to_string();
    let owner_s = stellar_strkey::ed25519::PrivateKey(owner_signing_key.to_bytes())
        .as_unredacted()
        .to_string();
    write_signed_policy_toml(home.path(), &profile_name, &owner_signing_key);
    write_profile_toml(home.path(), &profile_name);
    let _owner_guard = enroll_owner_key_via_cli(home.path(), &profile_name, &owner_s, &owner_g);
    let _audit_guard = rotate_audit_key_via_cli(home.path(), &profile_name);
    let _window_guards = window_state_guards(&profile_name);

    let (source_g, source_seed) = fresh_keypair();
    let (dest_g, _dest_seed) = fresh_keypair();
    let source_s = stellar_strkey::ed25519::PrivateKey(*source_seed)
        .as_unredacted()
        .to_string();
    fund_via_friendbot(&source_g).await;
    fund_via_friendbot(&dest_g).await;
    let client = StellarRpcClient::new(TESTNET_RPC_URL).expect("rpc client");
    wait_until_account_queryable(&client, &source_g).await;
    wait_until_account_queryable(&client, &dest_g).await;

    // ── The payment: accepted for inclusion, not confirmed in the window ──
    let http = http_client();
    let mut timed_out = None;
    for offset in PHASE_OFFSETS_MS {
        wait_for_a_fresh_ledger_close(&http).await;
        tokio::time::sleep(Duration::from_millis(offset)).await;
        let (exit_code, envelope) = run_cli(
            home.path(),
            &[
                "pay",
                &dest_g,
                PAY_AMOUNT,
                "--source",
                &source_g,
                "--secret-env",
                PAY_SECRET_ENV_VAR,
                "--profile",
                &profile_name,
                "--network",
                "testnet",
                "--rpc-url",
                TESTNET_RPC_URL,
                "--timeout-seconds",
                SUBMIT_TIMEOUT_SECONDS,
            ],
            &[(PAY_SECRET_ENV_VAR, source_s.as_str())],
        );

        if exit_code == 1 {
            assert_eq!(
                envelope["error"]["code"].as_str(),
                Some("submission.tx_timeout"),
                "a payment either confirms or times out: {envelope}"
            );
            timed_out = Some(envelope);
            break;
        }
        assert_eq!(
            exit_code, 0,
            "a payment either confirms or times out: {envelope}"
        );
    }
    let envelope = timed_out.unwrap_or_else(|| {
        panic!(
            "no payment timed out across a sweep of the ledger cycle; every attempt confirmed              inside {SUBMIT_TIMEOUT_SECONDS}s"
        )
    });

    let details = &envelope["error"]["details"];
    let tx_hash = details["tx_hash"]
        .as_str()
        .unwrap_or_else(|| panic!("the timeout must carry the transaction hash: {envelope}"))
        .to_owned();
    assert_eq!(
        tx_hash.len(),
        64,
        "the full hash travels as data: {envelope}"
    );
    let envelope_hash = details["envelope_hash"]
        .as_str()
        .unwrap_or_else(|| panic!("the timeout must carry the envelope hash: {envelope}"))
        .to_owned();
    assert_eq!(details["outcome"].as_str(), Some("unknown"));
    assert_eq!(
        details["reconcile_with"].as_str(),
        Some("stellar-agent tx status"),
        "the response names the way out: {envelope}"
    );
    assert!(
        !envelope["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains(&tx_hash),
        "the message stays redacted: {envelope}"
    );

    // The pending row is in the log before anything is reconciled, and the
    // submission that has not been accounted for has written no submitted row.
    let rows = audit_rows(home.path(), &profile_name);
    assert_eq!(
        rows_for(&rows, "value_action_pending", &envelope_hash).len(),
        1,
        "exactly one pending row is written before the send: {rows:?}"
    );
    assert!(
        rows_for(&rows, "value_action_submitted", &envelope_hash).is_empty(),
        "an unconfirmed submission writes no submitted row: {rows:?}"
    );

    // ── Reconciliation: the chain had it a ledger later ────────────────────
    let mut settled = None;
    for _ in 0..30 {
        let (status_exit, status_envelope) = run_cli(
            home.path(),
            &["tx", "status", &tx_hash, "--profile", &profile_name],
            &[],
        );
        assert_eq!(status_exit, 0, "tx status must complete: {status_envelope}");
        if status_envelope["data"]["chain_status"] == "SUCCESS" {
            settled = Some(status_envelope);
            break;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    let settled = settled.expect("the transaction must confirm on testnet within the poll window");

    assert_eq!(
        settled["data"]["record"]["status"].as_str(),
        Some("success"),
        "reconciliation settles the receipt: {settled}"
    );
    assert_eq!(
        settled["data"]["record"]["envelope_hash"].as_str(),
        Some(envelope_hash.as_str())
    );
    assert_eq!(
        settled["data"]["record"]["reservation_open"].as_bool(),
        Some(false),
        "a confirmed reservation becomes recorded spend: {settled}"
    );

    // The submitted row the submission never got to write is now in the log.
    let rows = audit_rows(home.path(), &profile_name);
    assert_eq!(
        rows_for(&rows, "value_action_submitted", &envelope_hash).len(),
        1,
        "reconciliation writes the submitted row: {rows:?}"
    );

    // The audit log's own chain still verifies after both rows.
    let log_path = audit_log_path(home.path(), &profile_name);
    let log_path_arg = log_path.to_str().expect("the log path must be UTF-8");
    let (verify_exit, verify_envelope) = run_cli(
        home.path(),
        &["audit", "verify", log_path_arg, "--profile", &profile_name],
        &[],
    );
    assert_eq!(
        verify_exit, 0,
        "the audit chain must verify after reconciliation: {verify_envelope}"
    );
}
