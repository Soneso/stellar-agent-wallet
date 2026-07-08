//! Testnet acceptance: `stellar-agent claim` as a single-shot subprocess.
//!
//! The `claim` subcommand has no `--build-only` / `--sign-only` step in this
//! test — the default invocation runs the full build-sign-submit pipeline in
//! one call and is driven as a real child process (the CLI crate has no
//! `[lib]` target, so it cannot be exercised in-process).
//!
//! Flow:
//! 1. Fund a fresh creator and a fresh claimant via Friendbot and wait until
//!    both are RPC-queryable.
//! 2. The creator submits a `CreateClaimableBalance` transaction (native XLM,
//!    unconditional predicate, single claimant) built directly with
//!    `stellar-baselib`, mirroring the MCP acceptance test's approach.
//! 3. Derive the created balance's canonical 72-hex id per CAP-23 and poll
//!    until it is fetchable.
//! 4. Spawn `stellar-agent claim <balance_id> --source <claimant_G>
//!    --secret-env CLAIM_TEST_SECRET --network testnet --rpc-url <testnet>`,
//!    with the claimant's S-strkey secret set only on the child process's
//!    environment.
//! 5. Assert a zero exit status, parse stdout as the `Envelope<ClaimResult>`
//!    JSON wire shape, and verify the on-chain effects directly: the
//!    claimant's native balance increased and the balance entry is gone.
//!
//! `claim` reads its secret straight from the named environment variable
//! (`std::env::var`) and never touches the wallet keyring system, so no
//! keyring seeding is needed here. The `--profile` flag defaults to
//! `"default"`; with no `default.toml` file present, the command synthesizes
//! an in-memory `Noop`-engine testnet profile for its policy gate (see
//! `crate::commands::policy_engine::load_profile_or_synthesize_testnet`), so
//! no profile setup is needed either — the gate is a permissive no-op here.
//!
//! Gated behind the `testnet-acceptance` feature flag:
//!
//! ```text
//! cargo test -p stellar-agent-cli --features testnet-acceptance \
//!   --test claim_testnet_acceptance
//! ```

#![cfg(feature = "testnet-acceptance")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics and unwraps are acceptable in testnet acceptance tests"
)]

use std::error::Error;
use std::process::Command;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use stellar_agent_claimable::entry::fetch_claimable_balance_entry;
use stellar_agent_claimable::id::BalanceId;
use stellar_agent_network::signing::SoftwareSigningKey;
use stellar_agent_network::signing::envelope_signing::attach_signature;
use stellar_agent_network::submit::SubmissionSignerKind;
use stellar_agent_network::{StellarRpcClient, fetch_account, submit_transaction_and_wait};
use stellar_agent_test_support::testnet_helpers::create_claimable_balance;
use zeroize::Zeroizing;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";
const TESTNET_FRIENDBOT_URL: &str = "https://friendbot.stellar.org";
const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";

/// Per-operation fee, in stroops, for the creator's `CreateClaimableBalance` tx.
const CREATE_FEE_STROOPS_PER_OP: u32 = 100_000;

/// Amount locked in the claimable balance: 25 XLM.
const CLAIM_AMOUNT_STROOPS: i64 = 250_000_000;

/// Name of the environment variable the spawned `stellar-agent claim` process
/// reads the claimant's S-strkey secret from. Set only on the child process,
/// never on the parent test process.
const CLAIM_SECRET_ENV_VAR: &str = "CLAIM_TEST_SECRET";

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn fresh_keypair() -> (String, Zeroizing<[u8; 32]>) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let g_strkey = stellar_strkey::ed25519::PublicKey(signing_key.verifying_key().to_bytes())
        .to_string()
        .as_str()
        .to_owned();
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
async fn wait_until_account_queryable(g_strkey: &str) {
    let client = StellarRpcClient::new(TESTNET_RPC_URL).expect("RPC client");
    for _ in 0..30 {
        if fetch_account(&client, g_strkey, &[]).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("funded account {g_strkey} did not become RPC-queryable in time");
}

/// Polls RPC until the given claimable-balance id is fetchable, tolerating
/// ledger-close / RPC propagation delay after the create tx is confirmed.
async fn wait_until_balance_queryable(client: &StellarRpcClient, id: &BalanceId) {
    for _ in 0..30 {
        if fetch_claimable_balance_entry(client, id).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!(
        "claimable balance {} did not become RPC-queryable in time",
        id.to_hex72()
    );
}

/// Fetches `account_id`'s current sequence number over `client`.
///
/// Takes an owned `account_id` (rather than `&str`) so the closure at the
/// call site produces a future with no lifetime tied to the per-call
/// argument — required for the `Fn(&str) -> FFut` trait bound in
/// [`create_claimable_balance`]'s dependency-injected `fetch_sequence`.
async fn fetch_testnet_sequence(
    client: &StellarRpcClient,
    account_id: String,
) -> Result<i64, Box<dyn Error + Send + Sync>> {
    Ok(fetch_account(client, &account_id, &[])
        .await?
        .sequence_number)
}

/// Signs `unsigned_b64` with a fresh [`SoftwareSigningKey`] built from `seed`.
async fn sign_testnet_envelope(
    unsigned_b64: String,
    seed: Zeroizing<[u8; 32]>,
    network_passphrase: String,
) -> Result<String, Box<dyn Error + Send + Sync>> {
    let signer = SoftwareSigningKey::new_from_bytes(*seed);
    Ok(attach_signature(&unsigned_b64, &signer, &network_passphrase).await?)
}

/// Submits `signed_b64` over `client` and waits for ledger confirmation.
async fn submit_testnet_signed_xdr(
    client: &StellarRpcClient,
    signed_b64: String,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    submit_transaction_and_wait(
        client,
        &signed_b64,
        Duration::from_secs(60),
        TESTNET_PASSPHRASE,
        Some(SubmissionSignerKind::Software),
    )
    .await?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Test
// ─────────────────────────────────────────────────────────────────────────────

/// `stellar-agent claim` runs the full build-sign-submit pipeline in a single
/// subprocess invocation and reaches ledger inclusion on testnet.
#[tokio::test]
async fn t3_cli_single_shot_happy_path() {
    let (creator_g, creator_seed) = fresh_keypair();
    let (claimant_g, claimant_seed) = fresh_keypair();
    fund_via_friendbot(&creator_g).await;
    fund_via_friendbot(&claimant_g).await;
    wait_until_account_queryable(&creator_g).await;
    wait_until_account_queryable(&claimant_g).await;

    let client = StellarRpcClient::new(TESTNET_RPC_URL).expect("RPC client");

    let balance_id_hex72 = create_claimable_balance(
        &creator_g,
        &creator_seed,
        &claimant_g,
        CLAIM_AMOUNT_STROOPS,
        None,
        TESTNET_PASSPHRASE,
        CREATE_FEE_STROOPS_PER_OP,
        |account_id| fetch_testnet_sequence(&client, account_id.to_owned()),
        |unsigned_b64, seed, network_passphrase| {
            sign_testnet_envelope(unsigned_b64, seed, network_passphrase.to_owned())
        },
        |signed_b64| submit_testnet_signed_xdr(&client, signed_b64),
    )
    .await
    .expect("create_claimable_balance");
    let balance_id = BalanceId::parse(&balance_id_hex72).expect("balance id parses");
    wait_until_balance_queryable(&client, &balance_id).await;

    let claimant_balance_before = fetch_account(&client, &claimant_g, &[])
        .await
        .expect("claimant account fetch (pre-claim)")
        .balances
        .first()
        .and_then(|b| b.balance_stroops().ok())
        .expect("claimant must hold a native balance after Friendbot funding");

    let claimant_s_strkey: String =
        stellar_strkey::ed25519::PrivateKey::from_payload(claimant_seed.as_ref())
            .expect("32-byte seed encodes as S-strkey")
            .as_unredacted()
            .to_string()
            .as_str()
            .to_owned();

    let bin_path = env!("CARGO_BIN_EXE_stellar-agent");
    let output = Command::new(bin_path)
        .args([
            "claim",
            &balance_id_hex72,
            "--source",
            &claimant_g,
            "--secret-env",
            CLAIM_SECRET_ENV_VAR,
            "--network",
            "testnet",
            "--rpc-url",
            TESTNET_RPC_URL,
        ])
        .env(CLAIM_SECRET_ENV_VAR, &claimant_s_strkey)
        .output()
        .expect("stellar-agent claim subprocess must spawn");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        output.status.success(),
        "stellar-agent claim must exit 0; stdout={stdout} stderr={stderr}"
    );

    // In `--output json` mode the CLI emits one compact envelope per stage
    // (the trustline verb's stream convention): a `stage: "preview"` envelope
    // first, then the final result envelope. Every stdout line must be valid
    // JSON, and the LAST line carries the claim result.
    let envelopes: Vec<serde_json::Value> = stdout
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            serde_json::from_str(l)
                .unwrap_or_else(|e| panic!("every stdout line must be valid JSON ({e}): {l}"))
        })
        .collect();
    assert!(
        envelopes.len() >= 2,
        "expected a preview envelope and a result envelope; got {} line(s): {stdout}",
        envelopes.len()
    );
    let preview = &envelopes[0];
    assert_eq!(
        preview["data"]["stage"].as_str(),
        Some("preview"),
        "first envelope must be the typed preview: {preview}"
    );
    assert_eq!(
        preview["data"]["is_claimant"].as_bool(),
        Some(true),
        "preview must confirm the source is a claimant: {preview}"
    );
    let envelope = envelopes.last().expect("at least one stdout envelope");
    assert_eq!(
        envelope["ok"].as_bool(),
        Some(true),
        "claim envelope must be ok: {envelope}"
    );
    let tx_hash = envelope["data"]["tx_hash"]
        .as_str()
        .expect("claim result must carry a tx_hash");
    assert!(!tx_hash.is_empty(), "tx_hash must be non-empty: {envelope}");
    assert_eq!(tx_hash.len(), 64, "tx_hash must be a 32-byte hex digest");

    // ── On-chain effects: claimant credited, entry gone ────────────────────────
    let claimant_balance_after = fetch_account(&client, &claimant_g, &[])
        .await
        .expect("claimant account fetch (post-claim)")
        .balances
        .first()
        .and_then(|b| b.balance_stroops().ok())
        .expect("claimant must still hold a native balance after claiming");
    assert!(
        claimant_balance_after > claimant_balance_before,
        "claimant native balance must strictly increase after claiming \
         (before={claimant_balance_before}, after={claimant_balance_after})"
    );

    let refetch = fetch_claimable_balance_entry(&client, &balance_id).await;
    let err = refetch.expect_err("claimed balance must no longer exist");
    assert_eq!(
        err.code(),
        "claim.balance_not_found",
        "a claimed balance must be gone from the ledger: {err}"
    );
}
