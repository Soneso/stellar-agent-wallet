//! Testnet acceptance: `stellar-agent profile init` -> `profile enroll-signer`
//! -> a real signing operation.
//!
//! This is the live, on-chain proof that the round trip issue #80 requires is
//! actually completable: a profile minted by `init` (whose
//! `mcp_signer_default.account` starts as the placeholder `"default"`, not a
//! G-strkey) can enroll a signer via `enroll-signer` and then sign and submit
//! a real transaction — driven as a subprocess against the real
//! `stellar-agent` binary (the CLI crate has no `[lib]` target, so it cannot
//! be exercised in-process — the `claim_testnet_acceptance.rs` precedent,
//! mirrored here per `pay_policy_v1_testnet_acceptance.rs`).
//!
//! # Fixture setup
//!
//! A fresh temp directory stands in for `STELLAR_AGENT_HOME` (only ever set on
//! the CHILD processes' environments, never the test-process environment).
//! The profile name is unique per test run
//! (`profile-init-acceptance-<pid>-<unix_secs>`) so the OS keyring coordinate
//! `enroll-signer` writes to (below) never collides with a concurrent or
//! prior local run.
//!
//! 1. A signer ed25519 keypair is generated in-process and Friendbot-funded
//!    (an existing, funded source account; the classic `ChangeTrust`
//!    operation used as the proof-of-signing step requires one).
//! 2. `stellar-agent profile init --profile <name> --network testnet --engine
//!    noop` is spawned. `noop` is used so the round trip does not also need
//!    the unrelated V1 owner-key/attestation-key ceremony —
//!    `enroll-signer` (the command under test) is engine-agnostic. The audit
//!    chain-root key IS required on every engine, so this test exercises
//!    `rotate-audit-key` regardless of the `noop` choice.
//! 3. The written profile TOML is asserted to hold the placeholder
//!    `mcp_signer_default.account = "default"` — the exact value an
//!    `init`-minted profile carries before any signer is enrolled. The
//!    TOML's `audit_log_path` field is then rewritten in place to a path
//!    inside this test's own tempdir (see "Audit-log isolation" below).
//! 4. `stellar-agent profile enroll-signer --profile <name> --secret-env
//!    <VAR>` is spawned with the signer's `S...` seed set only on that
//!    subprocess's environment. The production write path (`enroll_signer.rs`)
//!    both writes the seed to the OS keyring AND rewrites the profile TOML's
//!    `mcp_signer_default.account` from the placeholder to the derived
//!    G-strkey — the completeness fix under test.
//! 5. Negative proof of the fail-closed audit-pre-flight gate: `stellar-agent
//!    trustline` is spawned against a never-funded, freshly-generated issuer
//!    — BEFORE `rotate-audit-key` runs, the profile's audit chain-root key is
//!    still unminted. The command must refuse `audit.chain_key_unavailable`.
//!    Because the pre-flight fires before any RPC call in `trustline.rs`, an
//!    issuer that could never resolve on-chain proves no RPC round-trip was
//!    needed to reach this refusal (a real fetch against it would surface a
//!    different, RPC-shaped error instead).
//! 6. `stellar-agent profile rotate-audit-key <name>` is spawned to mint the
//!    audit chain-root key. The audit key's keyring entry is added to the
//!    cleanup guard once its coordinate is known (deterministic from the
//!    profile name, so it is known up front).
//! 7. `stellar-agent trustline --profile <name> --from <signer_g> --asset
//!    <code>:<issuer_g>` is spawned with NO secret-env flag, this time
//!    against a real Friendbot-funded issuer: it resolves the signer purely
//!    through the profile + OS keyring coordinate `enroll-signer` populated,
//!    and now proceeds past the audit pre-flight. A cheap classic
//!    `ChangeTrust` is used as the "tiny funded testnet signing operation".
//! 8. The profile's (tempdir-scoped) audit log file is read back and asserted
//!    to contain a `value_action_submitted` row for this trustline's redacted
//!    transaction hash — on-chain proof that the post-confirm audit row the
//!    fail-closed pre-flight guards was actually emitted.
//!
//! # Audit-log isolation
//!
//! An unset `audit_log_path` resolves to the per-profile
//! `default_audit_log_path_for(name)` under the canonical data root — for a
//! release-shaped subprocess that is still a real host location. Step 3
//! above rewrites the persisted `audit_log_path` field to a path inside this
//! test's own tempdir before any subprocess reads it, pinning the exact file
//! the final row assertion reads and keeping every step hermetic regardless
//! of how the subprocess binary resolves its data root.
//!
//! # Cleanup
//!
//! The enrolled signer keyring entry AND the rotated audit-key keyring entry
//! are deleted by an RAII guard that runs on every exit path (success,
//! assertion failure, or early return) so a panicking assertion never leaks a
//! keyring entry — belt-and-suspenders on top of the per-run unique profile
//! name. The profile TOML and the redirected audit log both live inside the
//! test's own `tempfile::TempDir`, which is removed on drop.
//!
//! # Platform keyring precondition
//!
//! `enroll-signer` and `trustline` both register the platform keyring store
//! before touching it, so this suite requires a functioning platform keyring
//! (macOS Keychain in local dev; a headless Secret Service, provisioned by the
//! CI workflow via gnome-keyring, in CI). Keyring init failure fails this
//! test — it is not an infrastructure precondition to be skipped.
//!
//! Gated behind `testnet-acceptance`:
//!
//! ```text
//! cargo test -p stellar-agent-cli --features testnet-acceptance \
//!   --test profile_init_enroll_signer_testnet_acceptance
//! ```

#![cfg(feature = "testnet-acceptance")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics and unwraps are acceptable in testnet acceptance tests"
)]

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use stellar_agent_network::{Asset, StellarRpcClient, fetch_account};
use zeroize::Zeroizing;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";
const TESTNET_FRIENDBOT_URL: &str = "https://friendbot.stellar.org";

/// Name of the env var the spawned `stellar-agent profile enroll-signer`
/// process reads the signer's S-strkey secret from. Set only on that
/// subprocess's environment, never the test-process environment.
const SIGNER_SECRET_ENV_VAR: &str = "PROFILE_INIT_ACCEPTANCE_SIGNER_SECRET";

/// The arbitrary, non-pinned, non-denylisted asset code used for the proof
/// ChangeTrust operation. 1-12 ASCII alphanumeric per the trustline resolver's
/// `validate_and_upper_code`; already uppercase so the raw-TOML/JSON
/// assertions below compare byte-for-byte against the resolver's canonical
/// output.
const PROOF_ASSET_CODE: &str = "ACCTPROOF";

/// Builds a profile name unique to this test run:
/// `profile-init-acceptance-<pid>-<unix_secs>`.
///
/// The profile TOML lives inside the test's own fresh tempdir and so cannot
/// collide across runs on its own, but the OS keyring coordinate
/// `enroll-signer` writes to (`stellar-agent-signer-<profile>` /
/// `<derived_g>`) is OS-global, not tempdir-scoped — the profile name must be
/// unique per run so repeated local runs (or a concurrent CI matrix) never
/// collide on the signer-service half of that coordinate.
fn unique_profile_name() -> String {
    let unix_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock must work")
        .as_secs();
    format!("profile-init-acceptance-{}-{unix_secs}", std::process::id())
}

// ─────────────────────────────────────────────────────────────────────────────
// Keypair / funding helpers (mirrors `pay_policy_v1_testnet_acceptance.rs`)
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

// ─────────────────────────────────────────────────────────────────────────────
// Signer keyring cleanup guard
// ─────────────────────────────────────────────────────────────────────────────

/// RAII guard that deletes every keyring entry this test mints, on drop
/// (success, assertion panic, or early return alike), so a failed test run
/// never leaks an entry into the OS keyring — belt-and-suspenders on top of
/// [`unique_profile_name`]'s per-run namespacing.
///
/// Holds the signer coordinate `enroll-signer` writes AND the audit
/// chain-root coordinate `rotate-audit-key` writes. Both are deterministic
/// from the profile name (`KeyringEntryRef::default_audit_key`), so both are
/// known up front and the guard can be constructed once, before either
/// subprocess has actually minted anything — deleting a not-yet-existing
/// entry is a harmless no-op.
struct KeyringCleanupGuard {
    signer_service: String,
    signer_account: String,
    audit_service: String,
    audit_account: String,
}

impl Drop for KeyringCleanupGuard {
    fn drop(&mut self) {
        // Best-effort: a delete failure here must not mask the test's own
        // pass/fail outcome (Drop cannot propagate an error), and a leftover
        // entry from a rare delete failure is harmless — the per-run unique
        // profile name means it will never collide with a future run's own
        // coordinate.
        if let Ok(entry) = keyring_core::Entry::new(&self.signer_service, &self.signer_account) {
            let _ = entry.delete_credential();
        }
        if let Ok(entry) = keyring_core::Entry::new(&self.audit_service, &self.audit_account) {
            let _ = entry.delete_credential();
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Subprocess invocation helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Spawns `stellar-agent profile init` with `STELLAR_AGENT_HOME` set on the
/// child process only, and returns the parsed JSON envelope.
fn run_profile_init(home: &Path, profile: &str) -> serde_json::Value {
    let bin_path = env!("CARGO_BIN_EXE_stellar-agent");
    let output = Command::new(bin_path)
        .args([
            "profile",
            "init",
            "--profile",
            profile,
            "--network",
            "testnet",
            "--engine",
            "noop",
        ])
        .env("STELLAR_AGENT_HOME", home)
        .output()
        .expect("stellar-agent profile init subprocess must spawn");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let exit_code = output
        .status
        .code()
        .unwrap_or_else(|| panic!("profile init must exit with a status code; stderr={stderr}"));
    assert_eq!(
        exit_code, 0,
        "profile init must succeed on a clean directory; stdout={stdout} stderr={stderr}"
    );
    serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("profile init stdout must be valid JSON ({e}): {stdout}"))
}

/// Spawns `stellar-agent profile enroll-signer` with the signer's S-strkey set
/// only on the child process's environment, and returns the parsed JSON
/// envelope.
fn run_enroll_signer(home: &Path, profile: &str, s_strkey: &str) -> serde_json::Value {
    let bin_path = env!("CARGO_BIN_EXE_stellar-agent");
    let output = Command::new(bin_path)
        .args([
            "profile",
            "enroll-signer",
            "--profile",
            profile,
            "--secret-env",
            SIGNER_SECRET_ENV_VAR,
        ])
        .env(SIGNER_SECRET_ENV_VAR, s_strkey)
        .env("STELLAR_AGENT_HOME", home)
        .output()
        .expect("stellar-agent profile enroll-signer subprocess must spawn");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let exit_code = output.status.code().unwrap_or_else(|| {
        panic!("profile enroll-signer must exit with a status code; stderr={stderr}")
    });
    assert_eq!(
        exit_code, 0,
        "enroll-signer must succeed against a placeholder account; stdout={stdout} stderr={stderr}"
    );
    serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("profile enroll-signer stdout must be valid JSON ({e}): {stdout}")
    })
}

/// Spawns `stellar-agent profile rotate-audit-key <profile>` and returns the
/// parsed JSON envelope.
fn run_rotate_audit_key(home: &Path, profile: &str) -> serde_json::Value {
    let bin_path = env!("CARGO_BIN_EXE_stellar-agent");
    let output = Command::new(bin_path)
        .args(["profile", "rotate-audit-key", profile])
        .env("STELLAR_AGENT_HOME", home)
        .output()
        .expect("stellar-agent profile rotate-audit-key subprocess must spawn");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let exit_code = output.status.code().unwrap_or_else(|| {
        panic!("profile rotate-audit-key must exit with a status code; stderr={stderr}")
    });
    assert_eq!(
        exit_code, 0,
        "rotate-audit-key must succeed; stdout={stdout} stderr={stderr}"
    );
    serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("profile rotate-audit-key stdout must be valid JSON ({e}): {stdout}")
    })
}

/// Spawns `stellar-agent trustline` with NO secret-env flag — it must resolve
/// its signer purely through the profile's (just-enrolled) keyring
/// coordinate — and returns `(exit_code, final_stdout_json_envelope)`.
///
/// The trustline submit path emits TWO JSON envelopes on stdout: the
/// clawback-gate preview envelope (`stage: "preview"`) followed by the submit
/// result envelope (`status: "submitted"`). Every stdout line must be valid
/// JSON; the LAST line is the submit outcome this test asserts on.
fn run_trustline(
    home: &Path,
    profile: &str,
    from_g: &str,
    asset: &str,
) -> (i32, serde_json::Value) {
    let bin_path = env!("CARGO_BIN_EXE_stellar-agent");
    let output = Command::new(bin_path)
        .args([
            "trustline",
            "--profile",
            profile,
            "--from",
            from_g,
            "--asset",
            asset,
        ])
        .env("STELLAR_AGENT_HOME", home)
        .output()
        .expect("stellar-agent trustline subprocess must spawn");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

    let lines: Vec<&str> = stdout.lines().filter(|l| !l.trim().is_empty()).collect();
    assert!(
        !lines.is_empty(),
        "expected at least one JSON envelope line on stdout; stderr={stderr}"
    );
    let envelopes: Vec<serde_json::Value> = lines
        .iter()
        .map(|line| {
            serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("every stdout line must be valid JSON ({e}): {line}"))
        })
        .collect();
    let envelope = envelopes
        .last()
        .expect("non-empty by the assertion above")
        .clone();

    let exit_code = output
        .status
        .code()
        .unwrap_or_else(|| panic!("process must exit with a status code; stderr={stderr}"));
    (exit_code, envelope)
}

// ─────────────────────────────────────────────────────────────────────────────
// Test
// ─────────────────────────────────────────────────────────────────────────────

/// `profile init` -> `profile enroll-signer` -> a real signing operation: the
/// full round trip an `init`-minted profile must support end to end.
#[tokio::test]
async fn profile_init_then_enroll_signer_enables_a_real_signing_operation() {
    // `enroll-signer` and `trustline` both register the platform keyring
    // store before touching it, so this suite needs a functioning platform
    // keyring (macOS Keychain locally; a headless Secret Service, provisioned
    // by the CI workflow, on Linux CI runners). The test process also needs
    // it initialised directly for `KeyringCleanupGuard`'s cleanup delete.
    stellar_agent_network::init_platform_keyring_store()
        .expect("platform keyring store must initialise on this host");

    let home = tempfile::TempDir::new().expect("tempdir");
    let profile_name = unique_profile_name();

    // ── Fixture: a funded testnet signer account ──────────────────────────────
    let (signer_g, signer_seed) = fresh_keypair();
    fund_via_friendbot(&signer_g).await;
    let client = StellarRpcClient::new(TESTNET_RPC_URL).expect("RPC client");
    wait_until_account_queryable(&client, &signer_g).await;

    let signer_s_strkey: String =
        stellar_strkey::ed25519::PrivateKey::from_payload(signer_seed.as_ref())
            .expect("32-byte seed encodes as S-strkey")
            .as_unredacted()
            .to_string()
            .as_str()
            .to_owned();

    // ── Step 1: `profile init` via the production binary ─────────────────────
    let init_envelope = run_profile_init(home.path(), &profile_name);
    assert_eq!(
        init_envelope["ok"].as_bool(),
        Some(true),
        "profile init envelope must be ok=true: {init_envelope}"
    );
    assert_eq!(
        init_envelope["data"]["engine"].as_str(),
        Some("noop"),
        "profile init must honour --engine noop: {init_envelope}"
    );

    let profile_path = home
        .path()
        .join("profiles")
        .join(format!("{profile_name}.toml"));
    assert!(
        profile_path.exists(),
        "profile init must write the profile file under STELLAR_AGENT_HOME"
    );
    let raw_before_enroll = std::fs::read_to_string(&profile_path).unwrap();
    let mut doc_before: toml::Value =
        toml::from_str(&raw_before_enroll).expect("the init-minted profile must be parseable TOML");
    assert_eq!(
        doc_before["mcp_signer_default"]["account"].as_str(),
        Some("default"),
        "an init-minted profile's mcp_signer_default.account must start as the \
         placeholder \"default\": {raw_before_enroll}"
    );

    // Redirect `audit_log_path` to a path inside this test's own tempdir
    // before any subprocess reads the profile — see the module doc's
    // "Audit-log isolation" section for why: the unset default is a SINGLE
    // file shared by every profile on the host, not a per-profile path.
    let audit_log_path = home.path().join(format!("{profile_name}-audit.jsonl"));
    doc_before["audit_log_path"] = toml::Value::String(audit_log_path.display().to_string());
    std::fs::write(
        &profile_path,
        toml::to_string_pretty(&doc_before).expect("re-serialise the patched profile TOML"),
    )
    .expect("write the patched profile TOML back");

    let signer_service = format!("stellar-agent-signer-{profile_name}");
    let audit_service = format!("stellar-agent-audit-{profile_name}");
    let _keyring_cleanup_guard = KeyringCleanupGuard {
        signer_service: signer_service.clone(),
        signer_account: signer_g.clone(),
        audit_service,
        audit_account: "default".to_owned(),
    };

    // ── Step 2: `profile enroll-signer` via the production binary ────────────
    let enroll_envelope = run_enroll_signer(home.path(), &profile_name, &signer_s_strkey);
    assert_eq!(
        enroll_envelope["ok"].as_bool(),
        Some(true),
        "enroll-signer envelope must be ok=true: {enroll_envelope}"
    );
    assert_eq!(
        enroll_envelope["data"]["account_populated"].as_bool(),
        Some(true),
        "enroll-signer must report it populated the placeholder account: {enroll_envelope}"
    );
    assert_eq!(
        enroll_envelope["data"]["public_address"].as_str(),
        Some(signer_g.as_str()),
        "enroll-signer must report the derived signer address: {enroll_envelope}"
    );

    // The completeness fix under test: enroll-signer rewrote the profile TOML
    // from the placeholder to the derived G-strkey.
    let raw_after_enroll = std::fs::read_to_string(&profile_path).unwrap();
    assert!(
        raw_after_enroll.contains(&format!("account = \"{signer_g}\"")),
        "enroll-signer must persist the derived G-strkey into the profile TOML: \
         {raw_after_enroll}"
    );

    // ── Step 3 (negative proof): refuse BEFORE the audit key is minted ───────
    // The signer is enrolled but `rotate-audit-key` has not run yet, so the
    // profile's audit chain-root key is still unminted. A never-funded
    // issuer proves this refuses before any RPC round-trip: reaching the
    // issuer-flags fetch with an issuer that cannot resolve on-chain would
    // surface a different, RPC-shaped error, not `audit.chain_key_unavailable`.
    let (never_funded_issuer_g, _unused_seed) = fresh_keypair();
    let unminted_asset_arg = format!("{PROOF_ASSET_CODE}:{never_funded_issuer_g}");
    let (preflight_exit_code, preflight_envelope) =
        run_trustline(home.path(), &profile_name, &signer_g, &unminted_asset_arg);
    assert_eq!(
        preflight_exit_code, 1,
        "trustline must refuse before the audit key is minted: {preflight_envelope}"
    );
    assert_eq!(
        preflight_envelope["ok"].as_bool(),
        Some(false),
        "the pre-flight refusal envelope must be ok=false: {preflight_envelope}"
    );
    assert_eq!(
        preflight_envelope["error"]["code"].as_str(),
        Some("audit.chain_key_unavailable"),
        "trustline must refuse audit.chain_key_unavailable before the audit key is \
         minted: {preflight_envelope}"
    );

    // ── Step 4: `profile rotate-audit-key` mints the audit chain-root key ────
    let rotate_envelope = run_rotate_audit_key(home.path(), &profile_name);
    assert_eq!(
        rotate_envelope["ok"].as_bool(),
        Some(true),
        "rotate-audit-key envelope must be ok=true: {rotate_envelope}"
    );
    assert_eq!(
        rotate_envelope["data"]["rotated"].as_bool(),
        Some(true),
        "rotate-audit-key must report rotated=true: {rotate_envelope}"
    );

    // ── Step 5: prove the enrolled signer resolves — a real signing operation ─
    // The issuer account must exist on-chain: the trustline command's
    // fail-closed clawback gate fetches the issuer's account flags and
    // refuses when the fetch fails, so an unfunded issuer cannot be used.
    let (issuer_g, _issuer_seed_unused) = fresh_keypair();
    fund_via_friendbot(&issuer_g).await;
    wait_until_account_queryable(&client, &issuer_g).await;
    let asset_arg = format!("{PROOF_ASSET_CODE}:{issuer_g}");

    let (exit_code, trustline_envelope) =
        run_trustline(home.path(), &profile_name, &signer_g, &asset_arg);
    assert_eq!(
        exit_code, 0,
        "trustline must succeed once the signer is enrolled and the audit key is \
         minted: {trustline_envelope}"
    );
    assert_eq!(
        trustline_envelope["ok"].as_bool(),
        Some(true),
        "trustline envelope must be ok=true: {trustline_envelope}"
    );
    let tx_hash = trustline_envelope["data"]["tx_hash"]
        .as_str()
        .expect("trustline result must carry a tx_hash");
    assert_eq!(tx_hash.len(), 64, "tx_hash must be a 32-byte hex digest");

    // ── On-chain proof: the trustline now appears in the account's balances ──
    let asset = Asset::from_code_and_issuer(PROOF_ASSET_CODE, &issuer_g)
        .expect("valid code+issuer must build an Asset");
    let account_after = fetch_account(&client, &signer_g, std::slice::from_ref(&asset))
        .await
        .expect("account fetch (with the trustline asset) must succeed after ChangeTrust");
    assert!(
        account_after
            .balances
            .iter()
            .any(|b| b.asset.asset_type == PROOF_ASSET_CODE
                && b.asset.issuer.as_deref() == Some(issuer_g.as_str())),
        "the account must now carry a trustline balance for {PROOF_ASSET_CODE}:{issuer_g}: {:?}",
        account_after.balances
    );

    // ── Audit-log proof: the confirmed submit recorded a value_action_submitted
    // row (the fail-closed pre-flight guards exactly this row) ───────────────
    let audit_log_raw = std::fs::read_to_string(&audit_log_path).unwrap_or_else(|e| {
        panic!(
            "audit log must exist at the profile's (redirected) audit_log_path \
             {}: {e}",
            audit_log_path.display()
        )
    });
    let redacted_tx_hash = stellar_agent_network::submit::redact_tx_hash(tx_hash);
    let found_row = audit_log_raw.lines().any(|line| {
        let Ok(row) = serde_json::from_str::<serde_json::Value>(line) else {
            return false;
        };
        row["kind"].as_str() == Some("value_action_submitted")
            && row["tool"].as_str() == Some("stellar_trustline")
            && row["transaction_hash_redacted"].as_str() == Some(redacted_tx_hash.as_str())
    });
    assert!(
        found_row,
        "the audit log at {} must contain a value_action_submitted row for \
         stellar_trustline with transaction_hash_redacted {redacted_tx_hash}: {audit_log_raw}",
        audit_log_path.display()
    );
}
