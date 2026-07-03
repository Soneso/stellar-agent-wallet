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
//! (`std::env::var`) and does not touch the wallet profile/keyring system, so
//! no profile setup or keyring seeding is needed here.
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

use std::process::Command;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use sha2::{Digest as _, Sha256};
use stellar_agent_claimable::entry::fetch_claimable_balance_entry;
use stellar_agent_claimable::id::BalanceId;
use stellar_agent_network::signing::SoftwareSigningKey;
use stellar_agent_network::signing::envelope_signing::attach_signature;
use stellar_agent_network::submit::{SubmissionResult, SubmissionSignerKind};
use stellar_agent_network::{StellarRpcClient, fetch_account, submit_transaction_and_wait};
use stellar_baselib::account::{Account, AccountBehavior};
use stellar_baselib::asset::{Asset as BaselibAsset, AssetBehavior};
use stellar_baselib::claimant::{Claimant, ClaimantBehavior};
use stellar_baselib::operation::Operation as BaselibOperation;
use stellar_baselib::transaction::{Transaction, TransactionBehavior};
use stellar_baselib::transaction_builder::{TransactionBuilder, TransactionBuilderBehavior};
use stellar_xdr::{
    AccountId, HashIdPreimage, HashIdPreimageOperationId, Limits, PublicKey, SequenceNumber,
    Uint256, WriteXdr as _,
};
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

/// Builds, signs, and submits a `CreateClaimableBalance` transaction for the
/// native asset with a single unconditional claimant, then derives the
/// created balance's canonical 72-hex id per CAP-23
/// (`HashIdPreimage::OpId`).
///
/// Production code has no balance-creation path (`ClassicOpBuilder` only
/// builds `ClaimClaimableBalance`, by design), so the envelope here is built
/// directly with `stellar-baselib`.
async fn create_claimable_balance(
    client: &StellarRpcClient,
    creator_g: &str,
    creator_seed: &Zeroizing<[u8; 32]>,
    claimant_g: &str,
    amount_stroops: i64,
) -> String {
    let creator_account_view = fetch_account(client, creator_g, &[])
        .await
        .expect("creator account fetch");
    let creator_sequence = creator_account_view.sequence_number;

    let seq_str = creator_sequence.to_string();
    let mut account = Account::new(creator_g, &seq_str).expect("baselib Account::new");
    let mut tx_builder = TransactionBuilder::new(&mut account, TESTNET_PASSPHRASE, None);
    tx_builder.fee(CREATE_FEE_STROOPS_PER_OP);

    let claimant = Claimant::new(Some(claimant_g), None).expect("Claimant::new (unconditional)");
    let op = BaselibOperation::new()
        .create_claimable_balance(&BaselibAsset::native(), amount_stroops, vec![claimant])
        .expect("create_claimable_balance op construction");
    tx_builder.add_operation(op);

    let tx: Transaction = tx_builder.build();
    let envelope = tx.to_envelope().expect("baselib to_envelope");
    let unsigned_b64 = envelope
        .to_xdr_base64(Limits::none())
        .expect("unsigned envelope XDR encode");

    let creator_signer = SoftwareSigningKey::new_from_bytes(**creator_seed);
    let signed_b64 = attach_signature(&unsigned_b64, &creator_signer, TESTNET_PASSPHRASE)
        .await
        .expect("creator envelope signing");

    let _submission: SubmissionResult = submit_transaction_and_wait(
        client,
        &signed_b64,
        Duration::from_secs(60),
        TESTNET_PASSPHRASE,
        Some(SubmissionSignerKind::Software),
    )
    .await
    .expect("CreateClaimableBalance submit-and-confirm");

    // CAP-23 balance-id derivation: SHA-256 of the HashIdPreimage::OpId
    // preimage built from the creator's account id, the tx's seq_num (the
    // fetched sequence + 1 — `TransactionBuilder::build` increments the
    // in-memory `Account` before rendering XDR), and the operation index
    // (0 — a single-operation transaction).
    let creator_pubkey = stellar_strkey::ed25519::PublicKey::from_string(creator_g)
        .expect("creator g-strkey parses")
        .0;
    let creator_account_id = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(creator_pubkey)));
    let tx_seq_num = creator_sequence.saturating_add(1);
    let preimage = HashIdPreimage::OpId(HashIdPreimageOperationId {
        source_account: creator_account_id,
        seq_num: SequenceNumber(tx_seq_num),
        op_num: 0,
    });
    let preimage_xdr = preimage
        .to_xdr(Limits::none())
        .expect("HashIdPreimage XDR encode");
    let balance_hash: [u8; 32] = Sha256::digest(&preimage_xdr).into();
    format!(
        "00000000{}",
        balance_hash
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    )
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
        &client,
        &creator_g,
        &creator_seed,
        &claimant_g,
        CLAIM_AMOUNT_STROOPS,
    )
    .await;
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
