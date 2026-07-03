//! Auth-digest byte-parity gate: wallet substrate vs on-chain OZ canonical.
//!
//! Asserts that `stellar_agent_core::smart_account::auth_digest::compute_auth_digest`
//! produces the same 32-byte SHA-256 digest as the on-chain OZ `stellar-accounts`
//! v0.7.1 `do_check_auth` recompute, exercised here via `soroban_sdk::Vec::to_xdr`.
//!
//! # Why this is not a tautology
//!
//! The wallet substrate (`encode_context_rule_ids`) uses `stellar-xdr 27`
//! to encode `ScVal::Vec(...)`. The on-chain canonical uses `soroban-sdk 25.3.0`'s
//! `Vec::to_xdr` (which pulls `stellar-xdr 25.0.0` — the two crates coexist in
//! the same binary via Cargo's semver deduplication). Both SHOULD produce the same bytes because
//! `Vec<u32>` ScVal serialisation is stable across this version boundary;
//! this test asserts it empirically.
//!
//! A future protocol bump that breaks this stability will surface here, not in
//! production (regression-detection gate).
//!
//! # Fixture
//!
//! `signature_payload = [0x42; 32]`, `rule_ids = [0u32, 1, 5, 42]`.
//!
//! # OZ parity
//!
//! - stellar-accounts OZ parity integration test.

#![allow(
    clippy::expect_used,
    reason = "integration test — panics are the correct failure mode"
)]
#![allow(
    clippy::needless_borrows_for_generic_args,
    reason = "clarity: explicit borrows show the sha2 update contract"
)]

use sha2::{Digest as _, Sha256};
use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{Env, Vec as SorobanVec};
use stellar_agent_core::{ContextRuleId, compute_auth_digest, encode_context_rule_ids};

/// Asserts byte-equality between the wallet substrate's auth-digest and the
/// soroban-sdk `Vec<u32>::to_xdr`-based on-chain canonical computation.
///
/// Fixture: `signature_payload = [0x42; 32]`, `rule_ids = [0u32, 1, 5, 42]`.
#[test]
fn auth_digest_parity_with_onchain_canonical() {
    // ── Fixture ──────────────────────────────────────────────────────────────
    let signature_payload: [u8; 32] = [0x42; 32];
    let rule_ids_typed: Vec<ContextRuleId> = [0u32, 1, 5, 42]
        .iter()
        .map(|&n| ContextRuleId::new(n))
        .collect();

    // ── Wallet-substrate computation ──────────────────────────────────────────
    // encode_context_rule_ids uses stellar-xdr 27 to build
    // ScVal::Vec(Some(ScVec([ScVal::U32(id), ...]))) and serialise to XDR.
    let rule_ids_xdr = encode_context_rule_ids(&rule_ids_typed)
        .expect("encode_context_rule_ids must not fail for a bounded Vec<u32>");

    let wallet_digest = compute_auth_digest(&signature_payload, &rule_ids_xdr);

    // ── On-chain canonical computation ────────────────────────────────────────
    // Use soroban-sdk 25.3.0's Vec::to_xdr — this is the EXACT method the
    // on-chain contract calls at storage.rs:494
    // (`signatures.context_rule_ids.clone().to_xdr(e)`).
    // The native Env exercises the same serialisation path without requiring
    // a deployed WASM or live RPC connection.
    let env = Env::default();
    let onchain_rule_ids = SorobanVec::from_array(&env, [0u32, 1u32, 5u32, 42u32]);
    // to_xdr returns soroban_sdk::Bytes; extract via copy_into_slice.
    let onchain_xdr_soroban = onchain_rule_ids.to_xdr(&env);
    let mut onchain_xdr_bytes = vec![0u8; onchain_xdr_soroban.len() as usize];
    onchain_xdr_soroban.copy_into_slice(&mut onchain_xdr_bytes);

    // Replicate the on-chain sha256(signature_payload || context_rule_ids.to_xdr(e))
    // from storage.rs:492-495 (OZ stellar-contracts v0.7.1 SHA 3f81125).
    let mut hasher = Sha256::new();
    hasher.update(&signature_payload);
    hasher.update(&onchain_xdr_bytes);
    let onchain_digest: [u8; 32] = hasher.finalize().into();

    // ── Parity assertion ──────────────────────────────────────────────────────
    // Byte-equality is the load-bearing invariant: the on-chain contract at
    // storage.rs:495 computes exactly this digest and rejects signatures over
    // any other value at __check_auth time.
    assert_eq!(
        wallet_digest.as_bytes(),
        &onchain_digest,
        "wallet substrate and on-chain canonical produced different auth digests.\n\
         wallet:   {}\n\
         onchain:  {}\n\
         This indicates an XDR serialisation drift between stellar-xdr 27 \
         (wallet substrate) and soroban-sdk 25.x Vec::to_xdr (on-chain canonical).",
        wallet_digest
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        onchain_digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
    );
}

/// Asserts that encoding an empty rule-ID vector produces a parity digest.
///
/// Edge case: no context rules attached (the on-chain contract encodes
/// `Vec::<u32>::new()` as `ScVal::Vec(Some(ScVec([])))` — an empty ScVec,
/// not `ScVal::Vec(None)`.
#[test]
fn auth_digest_parity_empty_rule_ids() {
    let signature_payload: [u8; 32] = [0x00; 32];
    let rule_ids_typed: Vec<ContextRuleId> = vec![];

    let rule_ids_xdr = encode_context_rule_ids(&rule_ids_typed)
        .expect("encode_context_rule_ids must not fail for empty slice");

    let wallet_digest = compute_auth_digest(&signature_payload, &rule_ids_xdr);

    let env = Env::default();
    let onchain_rule_ids: SorobanVec<u32> = SorobanVec::new(&env);
    let onchain_xdr_soroban = onchain_rule_ids.to_xdr(&env);
    let mut onchain_xdr_bytes = vec![0u8; onchain_xdr_soroban.len() as usize];
    onchain_xdr_soroban.copy_into_slice(&mut onchain_xdr_bytes);

    let mut hasher = Sha256::new();
    hasher.update(&signature_payload);
    hasher.update(&onchain_xdr_bytes);
    let onchain_digest: [u8; 32] = hasher.finalize().into();

    assert_eq!(
        wallet_digest.as_bytes(),
        &onchain_digest,
        "empty rule-ID parity check failed.\n\
         wallet:  {}\n\
         onchain: {}",
        wallet_digest
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        onchain_digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
    );
}
