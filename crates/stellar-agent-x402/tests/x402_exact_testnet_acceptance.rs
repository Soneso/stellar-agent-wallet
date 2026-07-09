//! Testnet acceptance tests for the x402 Exact Stellar scheme.
//!
//! These tests require a live testnet RPC endpoint and Friendbot access. They
//! are gated behind the `testnet-acceptance` feature flag:
//!
//! ```text
//! cargo test -p stellar-agent-x402 --features testnet-acceptance \
//!   --test x402_exact_testnet_acceptance
//! ```
//!
//! Under default `cargo test` (no `--features testnet-acceptance`), this file
//! compiles but all tests are compiled-out via `#[cfg(feature = "testnet-acceptance")]`.
//! Offline request-validation cases (bad scheme/network/asset/amount/fees) live
//! in `tests/exact_validation.rs` and run without the network.
//!
//! # Asset choice
//!
//! The legs here transfer the native asset through its Stellar Asset Contract
//! (SAC). A Friendbot-funded account always holds native balance, so the submit
//! leg reaches real ledger inclusion rather than skipping on a missing
//! trustline. The construct/sign path is asset-agnostic; the same flow applies
//! to any SEP-41 token (e.g. a USDC SAC) once the payer holds it.
//!
//! # Acceptance criteria
//!
//! - **Construct + sign.** `create_payment` returns a `PaymentPayload` whose
//!   `transaction` base64-decodes to a valid `TransactionEnvelope` with a
//!   signed `SorobanAuthorizationEntry` (non-empty signature).
//! - **Submit + confirm.** The signed envelope is submitted to testnet RPC and
//!   reaches ledger inclusion, proving the re-simulated footprint and the
//!   simulated nonce auth entry are accepted on-chain.
//!
//! # Coverage note
//!
//! `create_payment`'s simulate -> sign -> re-simulate -> build orchestration is a
//! live-RPC flow that cannot be exercised by offline unit tests, so it does not
//! appear in offline `cargo llvm-cov`. These on-chain legs are its coverage:
//! the submit/confirm leg reaching a ledger proves the whole orchestration
//! end-to-end.
//!
//! # Test isolation
//!
//! A fresh ed25519 keypair is generated per test run using `rand_core::OsRng`.
//! The keypair is funded via Friendbot before use. No pre-committed secret key
//! material appears in source.
//!
//! # Serial execution
//!
//! Tests are serialised via `#[serial]` so concurrent runs do not contend on
//! shared process-global state.

#![cfg(feature = "testnet-acceptance")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    reason = "test-only; panics, unwraps, and eprintln are acceptable in testnet acceptance tests"
)]

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use serial_test::serial;
use stellar_agent_network::signing::SoftwareSigningKey;
use stellar_agent_network::signing::envelope_signing::attach_signature;
use stellar_agent_network::{
    StellarRpcClient, fetch_account, redact_tx_hash, submit_transaction_and_wait,
};
use stellar_agent_x402::X402Error;
use stellar_agent_x402::constants::X402_STELLAR_TESTNET;
use stellar_agent_x402::exact::create_payment;
use stellar_agent_x402::wire::PaymentRequirements;
use stellar_xdr::{
    Limits, MuxedAccount, ReadXdr, SequenceNumber, SorobanAuthorizationEntry, SorobanCredentials,
    TransactionEnvelope, Uint256, WriteXdr,
};
use zeroize::Zeroizing;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";
const TESTNET_FRIENDBOT_URL: &str = "https://friendbot.stellar.org";
const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";

/// Native-asset Stellar Asset Contract address on testnet.
///
/// Derived from the testnet network passphrase via the native-asset SAC ID
/// scheme; a Friendbot-funded account always holds native balance here, so a
/// SAC `transfer` of native is submittable without a trustline.
const NATIVE_SAC_TESTNET: &str = "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC";

/// Atomic transfer amount: 0.1 native units (1 unit = 10_000_000 stroops).
const TRANSFER_AMOUNT_ATOMIC: &str = "1000000";

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Generates a fresh ed25519 keypair from OS entropy.
///
/// Returns `(g_strkey, seed_zeroizing)`. No seed is committed to source.
fn fresh_keypair() -> (String, Zeroizing<[u8; 32]>) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    // stellar_strkey::to_string() returns heapless::String<56>; convert to std::String.
    let g_strkey: String = stellar_strkey::ed25519::PublicKey(verifying_key.to_bytes())
        .to_string()
        .as_str()
        .to_owned();
    let seed = Zeroizing::new(signing_key.to_bytes());
    (g_strkey, seed)
}

/// Funds a testnet account via Friendbot.
///
/// Returns the tx hash on success, or panics on failure.
async fn fund_via_friendbot(g_strkey: &str) -> String {
    let url = format!("{TESTNET_FRIENDBOT_URL}?addr={g_strkey}");
    let resp = reqwest::get(&url)
        .await
        .expect("Friendbot GET request failed");
    assert!(
        resp.status().is_success(),
        "Friendbot returned non-2xx for {g_strkey}: {}",
        resp.status()
    );
    let body: serde_json::Value = resp.json().await.expect("Friendbot response is not JSON");
    body.get("hash")
        .and_then(|v| v.as_str())
        .expect("Friendbot response missing 'hash' field")
        .to_owned()
}

/// Checks whether the testnet RPC endpoint is reachable.
///
/// Only probes the RPC URL — does not check SAC deployment or balances.
async fn testnet_rpc_is_reachable() -> bool {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap();
    client.get(TESTNET_RPC_URL).send().await.is_ok()
}

/// Builds a `SoftwareSigningKey` from a 32-byte seed.
fn signer_from_seed(seed: &Zeroizing<[u8; 32]>) -> SoftwareSigningKey {
    SoftwareSigningKey::new_from_zeroizing(seed.clone())
}

/// Builds `PaymentRequirements` for a native-SAC transfer on testnet.
fn native_testnet_requirements(pay_to: &str, amount: &str) -> PaymentRequirements {
    PaymentRequirements {
        scheme: "exact".to_owned(),
        network: X402_STELLAR_TESTNET.to_owned(),
        asset: NATIVE_SAC_TESTNET.to_owned(),
        amount: amount.to_owned(),
        pay_to: pay_to.to_owned(),
        max_timeout_seconds: 300,
        extra: serde_json::json!({ "areFeesSponsored": true }),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Construct + sign + re-simulate (happy path)
// ─────────────────────────────────────────────────────────────────────────────

/// Construct + sign: `create_payment` returns a well-formed `PaymentPayload`
/// with a signed `SorobanAuthorizationEntry`.
///
/// Funds a fresh ephemeral account, calls `create_payment`, and asserts:
/// 1. The call succeeds.
/// 2. The returned `transaction` decodes to a valid `TransactionEnvelope`.
/// 3. The envelope contains an `InvokeHostFunction` operation with a
///    `SorobanAuthorizationEntry` whose `Address` credentials carry a non-empty
///    `signature` ScVal.
#[tokio::test]
#[serial]
async fn construct_sign_resimulate_happy_path() {
    let (g_strkey, seed) = fresh_keypair();

    // Fund via Friendbot so the account exists on testnet.
    fund_via_friendbot(&g_strkey).await;

    // Brief pause to let the Friendbot tx settle.
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    let signer = signer_from_seed(&seed);
    let requirements = native_testnet_requirements(&g_strkey, TRANSFER_AMOUNT_ATOMIC);

    let result = create_payment(&requirements, &signer, TESTNET_RPC_URL, TESTNET_PASSPHRASE).await;

    match result {
        Ok(payload) => {
            assert_eq!(payload.x402_version, 2, "x402Version must be 2");
            assert_eq!(payload.accepted.scheme, "exact");
            assert_eq!(payload.accepted.network, X402_STELLAR_TESTNET);

            let envelope =
                TransactionEnvelope::from_xdr_base64(&payload.payload.transaction, Limits::none())
                    .expect("transaction does not decode to TransactionEnvelope");

            let auth_entries = extract_auth_entries(&envelope);
            assert!(
                !auth_entries.is_empty(),
                "TransactionEnvelope must contain at least one SorobanAuthorizationEntry"
            );

            let has_signed_entry = auth_entries.iter().any(|entry| {
                matches!(&entry.credentials, SorobanCredentials::Address(c)
                    if !matches!(&c.signature, stellar_xdr::ScVal::Void))
            });
            assert!(
                has_signed_entry,
                "at least one SorobanAuthorizationEntry must have a non-void signature"
            );

            // Cryptographically verify the signature against the payer's key
            // over the reconstructed authorization preimage — not merely that it
            // is non-void.
            let payer_pubkey = stellar_strkey::ed25519::PublicKey::from_string(&g_strkey)
                .expect("payer g-strkey parses")
                .0;
            let any_valid = auth_entries
                .iter()
                .any(|entry| verify_auth_entry_signature(entry, &payer_pubkey, TESTNET_PASSPHRASE));
            assert!(
                any_valid,
                "at least one auth entry must carry a cryptographically valid signature"
            );

            eprintln!(
                "[construct/sign PASS] create_payment succeeded; envelope has {} auth entries with a verified signature",
                auth_entries.len()
            );
        }
        Err(X402Error::RpcSimulateFailed { ref detail }) if !testnet_rpc_is_reachable().await => {
            // Only an unreachable RPC is an acceptable skip; the native SAC is
            // always deployed and the funded account always holds native balance.
            eprintln!("[construct/sign SKIP-WITH-REASON] testnet RPC unreachable: {detail}");
        }
        Err(other) => {
            panic!("[construct/sign FAIL] create_payment returned unexpected error: {other}");
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Submit + confirm: direct submit to testnet (on-chain submit-and-confirm)
// ─────────────────────────────────────────────────────────────────────────────

/// Submit + confirm: the signed native-SAC `transfer` payment reaches ledger
/// inclusion.
///
/// `create_payment` produces a payload whose transaction carries a placeholder
/// source — the settling facilitator re-sources it. This test plays the
/// facilitator: it re-points the transaction source to a funded account, signs
/// the envelope, and submits. The payer's `Address` auth entry is signed over a
/// preimage that excludes the transaction source, so re-sourcing keeps it valid.
/// Reaching a ledger proves the simulated-nonce auth entry and the re-simulated
/// footprint are accepted on-chain. The only acceptable skip is an unreachable
/// RPC; any other failure is a real defect.
#[tokio::test]
#[serial]
async fn submit_to_testnet_reaches_ledger() {
    if !testnet_rpc_is_reachable().await {
        eprintln!("[submit/confirm SKIP-WITH-REASON] testnet RPC unreachable; skipping submit leg");
        return;
    }

    let (g_strkey, seed) = fresh_keypair();
    fund_via_friendbot(&g_strkey).await;
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    let signer = signer_from_seed(&seed);
    let requirements = native_testnet_requirements(&g_strkey, TRANSFER_AMOUNT_ATOMIC);

    let payload = create_payment(&requirements, &signer, TESTNET_RPC_URL, TESTNET_PASSPHRASE)
        .await
        .expect(
            "[submit/confirm FAIL] create_payment must succeed for a funded native-SAC transfer",
        );

    let rpc = StellarRpcClient::new(TESTNET_RPC_URL).expect("RPC client construction failed");

    // Facilitator step: re-source the placeholder transaction to a funded
    // account before submitting. Here the payer settles its own payment.
    let mut envelope =
        TransactionEnvelope::from_xdr_base64(&payload.payload.transaction, Limits::none())
            .expect("payment transaction decodes to a TransactionEnvelope");
    let payer_pubkey = stellar_strkey::ed25519::PublicKey::from_string(&g_strkey)
        .expect("payer g-strkey parses")
        .0;
    let account_view = fetch_account(&rpc, &g_strkey, &[])
        .await
        .expect("payer account fetch");
    match &mut envelope {
        TransactionEnvelope::Tx(e) => {
            e.tx.source_account = MuxedAccount::Ed25519(Uint256(payer_pubkey));
            e.tx.seq_num = SequenceNumber(account_view.sequence_number + 1);
        }
        _ => panic!("[submit/confirm FAIL] expected a V1 transaction envelope"),
    }
    let unsigned_xdr = envelope
        .to_xdr_base64(Limits::none())
        .expect("re-sourced envelope encodes");

    let signed_xdr = attach_signature(&unsigned_xdr, &signer, TESTNET_PASSPHRASE)
        .await
        .expect("[submit/confirm FAIL] envelope signing must succeed");

    let submission = submit_transaction_and_wait(
        &rpc,
        &signed_xdr,
        std::time::Duration::from_secs(60),
        TESTNET_PASSPHRASE,
        None,
    )
    .await
    .expect("[submit/confirm FAIL] submit-and-confirm must reach ledger inclusion for a funded transfer");

    assert!(
        submission.ledger > 0,
        "submission.ledger must be > 0, got {}",
        submission.ledger
    );
    eprintln!(
        "[submit/confirm PASS] re-sourced submit reached ledger {}; tx_hash prefix = {}",
        submission.ledger,
        redact_tx_hash(&submission.tx_hash),
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Extracts all `SorobanAuthorizationEntry` entries from a `TransactionEnvelope`.
fn extract_auth_entries(envelope: &TransactionEnvelope) -> Vec<SorobanAuthorizationEntry> {
    use stellar_xdr::{OperationBody, TransactionEnvelope as TE};
    let ops = match envelope {
        TE::Tx(tx_v1) => &tx_v1.tx.operations,
        TE::TxV0(tx_v0) => &tx_v0.tx.operations,
        _ => return vec![],
    };
    ops.iter()
        .filter_map(|op| {
            if let OperationBody::InvokeHostFunction(ref ihf) = op.body {
                Some(ihf.auth.iter().cloned().collect::<Vec<_>>())
            } else {
                None
            }
        })
        .flatten()
        .collect()
}

/// Verifies that an `Address`-credentialled auth entry carries a valid ed25519
/// signature over its reconstructed `HashIdPreimage::SorobanAuthorization`.
fn verify_auth_entry_signature(
    entry: &SorobanAuthorizationEntry,
    payer_pubkey: &[u8; 32],
    passphrase: &str,
) -> bool {
    use sha2::{Digest, Sha256};
    use stellar_xdr::{Hash, HashIdPreimage, HashIdPreimageSorobanAuthorization, WriteXdr};

    let SorobanCredentials::Address(creds) = &entry.credentials else {
        return false;
    };
    let network_id = Hash(Sha256::digest(passphrase.as_bytes()).into());
    let preimage = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
        network_id,
        nonce: creds.nonce,
        signature_expiration_ledger: creds.signature_expiration_ledger,
        invocation: entry.root_invocation.clone(),
    });
    let Ok(preimage_bytes) = preimage.to_xdr(Limits::none()) else {
        return false;
    };
    let digest: [u8; 32] = Sha256::digest(&preimage_bytes).into();

    let Some(sig_bytes) = extract_signature_bytes(&creds.signature) else {
        return false;
    };
    let Ok(verifying_key) = ed25519_dalek::VerifyingKey::from_bytes(payer_pubkey) else {
        return false;
    };
    let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    verifying_key.verify_strict(&digest, &signature).is_ok()
}

/// Extracts the 64-byte ed25519 signature from the classic-account signature
/// ScVal `Vec([Map{public_key, signature}])`.
fn extract_signature_bytes(sig: &stellar_xdr::ScVal) -> Option<[u8; 64]> {
    use stellar_xdr::ScVal;
    let ScVal::Vec(Some(outer)) = sig else {
        return None;
    };
    let ScVal::Map(Some(map)) = outer.first()? else {
        return None;
    };
    for entry in map.iter() {
        if let ScVal::Symbol(key) = &entry.key
            && key.0.to_utf8_string_lossy() == "signature"
            && let ScVal::Bytes(bytes) = &entry.val
        {
            return bytes.0.as_slice().try_into().ok();
        }
    }
    None
}
