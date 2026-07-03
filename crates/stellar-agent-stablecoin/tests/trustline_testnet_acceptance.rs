//! Testnet acceptance tests for the stablecoin `trustline` verb.
//!
//! Gated behind the `testnet-acceptance` feature flag:
//!
//! ```text
//! cargo test -p stellar-agent-stablecoin --features testnet-acceptance \
//!   --test trustline_testnet_acceptance -- --nocapture
//! ```
//!
//! # Test flows
//!
//! - (a) Happy-path USDC trustline — Friendbot-funded G-account, resolve USDC
//!   via bare-code pin table, fetch live issuer flags (revocable, not clawback),
//!   gate proceeds, build + sign + submit `ChangeTrust`, assert balance line.
//!
//! - (b) Full on-chain clawback flow with real attested opt-in round-trip —
//!   Friendbot-fund a fresh ephemeral ISSUER G-account, set
//!   `AUTH_REVOCABLE | AUTH_CLAWBACK_ENABLED` on-chain, assert live flags,
//!   run the gate (no opt-in → `RefuseWithWarning`), record + HMAC-attest the
//!   opt-in via `new_trustline_clawback_opt_in_pending` + `compute_attestation`
//!   + `record_trustline_clawback_opt_in_attestation`, verify with
//!     `verify_attested_trustline_clawback_opt_in` (HMAC key required; presence-
//!     only `has_attested_trustline_clawback_opt_in` is insufficient), submit
//!     `ChangeTrust`, assert balance line on holder account.
//!
//! - (c) USDT refusal — `resolve_denomination("USDT", testnet_passphrase)`
//!   returns `UsdtRefused` before any RPC call.
//!
//! - (d) Bare unknown code refusal — `resolve_denomination("FOO", testnet_passphrase)`
//!   returns `UnpinnedBareCode` before any RPC call.
//!
//! # On-chain failure semantics
//!
//! If the live ChangeTrust submit in (a) or (b) returns an error the test
//! PANICS rather than silently passing.  RPC unavailability on the testnet endpoint
//! causes an early skip-with-reason message (not a silent pass).
//!
//! # No secrets required
//!
//! Tests (a) and (b) use ephemeral `ed25519-dalek` keypairs funded by Friendbot.
//! No repository secrets or pre-provisioned accounts are needed.

#![cfg(feature = "testnet-acceptance")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    reason = "test-only; panics, unwraps, and eprintln are acceptable in testnet acceptance tests"
)]

use std::path::PathBuf;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use stellar_agent_core::approval::{
    DEFAULT_TTL_MS, PendingApproval, PendingApprovalStore, compute_attestation,
    compute_trustline_clawback_opt_in_digest, process_uid_for_attestation,
};
use stellar_agent_network::{
    Asset, ClassicOpBuilder, SoftwareSigningKey, StellarRpcClient, SubmissionSignerKind,
    account::AccountFlagsView,
    fetch_account,
    signing::envelope_signing::attach_signature,
    submit::{SubmissionResult, submit_transaction_and_wait},
};
use stellar_agent_stablecoin::{
    flags::{GateDecision, clawback_gate},
    resolve::{DenominationInput, ResolveError, resolve_denomination},
};
use zeroize::Zeroizing;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";
const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";
const FRIENDBOT_URL: &str = "https://friendbot.stellar.org";

/// Pinned testnet USDC issuer (from the stablecoin pin table).
///
/// Source: `stellar-agent-stablecoin/src/pins.rs`.
const USDC_TESTNET_ISSUER: &str = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn testnet_rpc() -> StellarRpcClient {
    StellarRpcClient::new(TESTNET_RPC_URL).expect("testnet RPC URL must be valid")
}

/// Generates a fresh ephemeral ed25519 keypair and funds it via Friendbot.
///
/// Returns `(g_strkey, signer_handle)`.
///
/// # Panics
///
/// Panics if Friendbot fails (hard failure — testnet acceptance requires
/// live connectivity).
async fn fund_fresh_keypair() -> (String, SoftwareSigningKey) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let key_bytes = verifying_key.to_bytes();
    // stellar_strkey::ed25519::PublicKey::to_string() returns heapless::String<56>;
    // convert to std::string::String for use in async contexts and format strings.
    let g_strkey: String = stellar_strkey::ed25519::PublicKey(key_bytes)
        .to_string()
        .as_str()
        .to_owned();

    eprintln!(
        "Funding ephemeral account {} via Friendbot...",
        &g_strkey[..8]
    );

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("reqwest client build must succeed");
    let url = format!("{FRIENDBOT_URL}?addr={g_strkey}");
    let resp = client
        .get(&url)
        .send()
        .await
        .expect("Friendbot request must succeed");
    assert!(
        resp.status().is_success(),
        "Friendbot funding must succeed for account {g_strkey} (status: {})",
        resp.status()
    );

    eprintln!("Funded account {} via Friendbot", &g_strkey[..8]);

    let seed_bytes: Zeroizing<[u8; 32]> = Zeroizing::new(signing_key.to_bytes());
    let signer_handle = SoftwareSigningKey::new_from_zeroizing(seed_bytes);

    (g_strkey, signer_handle)
}

/// Wait up to `max_tries` for the account to appear on testnet.
async fn wait_for_account(rpc: &StellarRpcClient, g_strkey: &str, max_tries: u32) -> bool {
    for _ in 0..max_tries {
        if fetch_account(rpc, g_strkey, &[]).await.is_ok() {
            return true;
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
    false
}

// ─────────────────────────────────────────────────────────────────────────────
// Happy-path USDC trustline (live, testnet)
// ─────────────────────────────────────────────────────────────────────────────

/// Happy-path USDC trustline: deploy a Friendbot-funded G-account, resolve USDC
/// via bare-code pin table, fetch live USDC issuer flags, run the clawback gate,
/// build and submit a `ChangeTrust` transaction.
///
/// Acceptance criteria:
/// 1. `resolve_denomination("USDC", TESTNET_PASSPHRASE)` returns `USDC_TESTNET_ISSUER`.
/// 2. Live issuer-flag fetch succeeds.
/// 3. USDC testnet flags have `auth_clawback_enabled = false` (Circle safe).
/// 4. `clawback_gate(Some(&flags), false)` returns `Proceed`.
/// 5. `ChangeTrust` transaction submits and confirms on-chain.
#[tokio::test]
#[ignore = "live testnet acceptance; run with --ignored"]
async fn happy_path_usdc_trustline() {
    // ── Step 1: Resolve USDC via bare-code pin table ──────────────────────────
    let resolved = resolve_denomination(
        DenominationInput::BareCode("USDC".to_owned()),
        TESTNET_PASSPHRASE,
    )
    .expect("USDC bare code must resolve via testnet pin table");

    assert_eq!(resolved.code, "USDC", "resolved code must be USDC");
    assert_eq!(
        resolved.issuer, USDC_TESTNET_ISSUER,
        "resolved issuer must be the pinned testnet USDC issuer"
    );
    assert!(resolved.is_pinned, "USDC via bare code must be pinned");

    eprintln!(
        "USDC resolved to pinned issuer {}...",
        &resolved.issuer[..8]
    );

    // ── Step 2: Fund ephemeral account ────────────────────────────────────────
    let (g_strkey, signer_handle) = fund_fresh_keypair().await;

    // ── Step 3: Wait for account to appear on testnet ─────────────────────────
    let rpc = testnet_rpc();
    let account_appeared = wait_for_account(&rpc, &g_strkey, 15).await;
    if !account_appeared {
        eprintln!(
            "SKIP: account {} did not appear on testnet within timeout",
            &g_strkey[..8]
        );
        return;
    }

    // ── Step 4: Fetch live issuer flags for USDC_TESTNET_ISSUER ──────────────
    let issuer_account = match fetch_account(&rpc, USDC_TESTNET_ISSUER, &[]).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!(
                "SKIP: USDC issuer account fetch failed ({e}); \
                 testnet may be temporarily unreachable"
            );
            return;
        }
    };

    let flags = issuer_account
        .account_flags
        .as_ref()
        .expect("USDC issuer account must have account_flags");

    eprintln!(
        "USDC issuer flags: required={} revocable={} clawback={}",
        flags.auth_required, flags.auth_revocable, flags.auth_clawback_enabled
    );

    // Acceptance: USDC testnet issuer has clawback disabled (Circle safe).
    assert!(
        !flags.auth_clawback_enabled,
        "USDC testnet issuer MUST NOT have auth_clawback_enabled set; \
         got flags: {flags:?}"
    );

    // ── Step 5: Clawback gate must Proceed ────────────────────────────────────
    let gate = clawback_gate(Some(flags), false);
    assert_eq!(
        gate,
        GateDecision::Proceed,
        "clawback gate must Proceed for USDC (clawback disabled)"
    );

    // ── Step 6: Fetch source account for sequence number ──────────────────────
    let account_view = fetch_account(&rpc, &g_strkey, &[])
        .await
        .expect("funded account must be fetchable");
    let source_sequence = account_view.sequence_number;

    // ── Step 7: Build ChangeTrust envelope ───────────────────────────────────
    let asset = Asset::from_code_and_issuer(&resolved.code, &resolved.issuer)
        .expect("Asset::from_code_and_issuer must succeed for USDC");

    // 100 stroops fee per op (well above testnet base fee).
    let fee_per_op: u32 = 100;
    let mut builder =
        ClassicOpBuilder::new(&g_strkey, source_sequence, TESTNET_PASSPHRASE, fee_per_op);
    builder
        .change_trust(&asset, None)
        .expect("change_trust must succeed");
    let envelope_xdr = builder.build().expect("envelope build must succeed");

    // ── Step 8: Sign envelope ─────────────────────────────────────────────────
    let signed_xdr = attach_signature(&envelope_xdr, &signer_handle, TESTNET_PASSPHRASE)
        .await
        .expect("attach_signature must succeed");

    // ── Step 9: Submit and wait for confirmation ──────────────────────────────
    let timeout = Duration::from_secs(90);
    let SubmissionResult {
        tx_hash, ledger, ..
    } = submit_transaction_and_wait(
        &rpc,
        &signed_xdr,
        timeout,
        TESTNET_PASSPHRASE,
        Some(SubmissionSignerKind::Software),
    )
    .await
    .expect("ChangeTrust submit must succeed; on-chain auth failure is a hard failure");

    let tx_hash_redacted = format!(
        "{}...{}",
        &tx_hash[..8.min(tx_hash.len())],
        if tx_hash.len() > 8 {
            &tx_hash[tx_hash.len().saturating_sub(8)..]
        } else {
            ""
        }
    );
    // Assert the USDC trustline balance line exists on-chain.
    // `fetch_account` projects trustlines only when explicitly requested.
    let holder_after = fetch_account(&rpc, &g_strkey, std::slice::from_ref(&asset))
        .await
        .expect("holder account re-fetch must succeed after ChangeTrust");
    let trustline_exists = holder_after.balances.iter().any(|b| {
        b.asset.asset_type == resolved.code
            && b.asset.issuer.as_deref() == Some(resolved.issuer.as_str())
    });
    assert!(
        trustline_exists,
        "holder must have a {}:{} balance line after ChangeTrust",
        resolved.code,
        &resolved.issuer[..8]
    );

    eprintln!("PASS: ChangeTrust submitted; tx_hash={tx_hash_redacted} ledger={ledger:?}");
}

// ─────────────────────────────────────────────────────────────────────────────
// Clawback gate + opt-in round-trip (live issuer + real store)
// ─────────────────────────────────────────────────────────────────────────────

/// Full on-chain clawback flow with real attested opt-in round-trip.
///
/// # Steps
///
/// 1. Truth-table prelude — four offline gate decisions confirming the gate
///    semantics (guard; the real exercise is steps 2-6).
/// 2. Generate fresh ephemeral HOLDER + ISSUER keypairs; Friendbot-fund both.
/// 3. Set `AUTH_REVOCABLE | AUTH_CLAWBACK_ENABLED` on the issuer account via
///    `set_options_flags` → sign → submit-and-confirm on-chain → re-fetch and
///    assert `auth_clawback_enabled = true, auth_revocable = true`.
/// 4. Drive the live gate path for `TEST:<issuer G-address>` with the holder:
///    resolve via `CodeAndIssuer` → allowed, live flag fetch (clawback=true),
///    `clawback_gate` with `verify_attested_trustline_clawback_opt_in` against
///    a real `PendingApprovalStore` in a temp-dir → assert `RefuseWithWarning`.
///    Network key: `"stellar:testnet"` (CAIP-2 canonical form) used
///    at mint, digest, record, and lookup so all four sites agree.
/// 5. Record the opt-in through the real store write path:
///    `new_trustline_clawback_opt_in_pending` (network=`"stellar:testnet"`)
///    → `store.insert` → `compute_trustline_clawback_opt_in_digest` +
///    `compute_attestation` → `record_trustline_clawback_opt_in_attestation`.
/// 6. Re-run the gate with `store.verify_attested_trustline_clawback_opt_in`
///    (HMAC key required — the test key is `[0x42; 32]`, the same key used to
///    compute the blob in step 5; a wrong key would return false) → assert
///    `Proceed` → build + sign + submit `ChangeTrust TEST:<issuer>` on-chain →
///    re-fetch holder and assert the `TEST:<issuer>` balance line exists.
///
/// # Security notes
///
/// - The issuer seed is wrapped in `Zeroizing` and dropped after key extraction.
/// - The HMAC key used in step 5 is a test-local `Zeroizing<[u8; 32]>` with
///   test-only bytes; it never touches the platform keyring.
/// - No seeds appear in panic messages (panics name the step, not the key).
/// - Issuer G-strkey is truncated to 8 chars in all `eprintln!` calls.
#[tokio::test]
#[ignore = "live testnet acceptance; run with --ignored"]
async fn clawback_gate_opt_in_round_trip() {
    // ── Prelude: offline truth-table (gate semantics guard) ───────────────────
    let flags_with_clawback = AccountFlagsView::from_raw(0x0A); // revocable | clawback

    // clawback enabled, no opt-in → RefuseWithWarning.
    let decision_no_opt_in = clawback_gate(Some(&flags_with_clawback), false);
    assert!(
        matches!(decision_no_opt_in, GateDecision::RefuseWithWarning { .. }),
        "clawback + no opt-in must produce RefuseWithWarning; \
         got: {decision_no_opt_in:?}"
    );
    if let GateDecision::RefuseWithWarning { warning } = &decision_no_opt_in {
        assert!(
            warning.contains("issuer-clawback-enabled"),
            "clawback + no opt-in: warning must name issuer-clawback-enabled; got: {warning}"
        );
    }
    // clawback enabled, opt-in present → Proceed.
    assert_eq!(
        clawback_gate(Some(&flags_with_clawback), true),
        GateDecision::Proceed,
        "clawback + opt-in must Proceed"
    );
    // flags = None (fetch failed), no opt-in → fail-closed Refuse.
    assert!(
        matches!(clawback_gate(None, false), GateDecision::Refuse { .. }),
        "fetch failure must Refuse (fail-closed)"
    );
    // flags = None, opt-in present → Refuse (opt-in cannot override fail-closed gate).
    assert!(
        matches!(clawback_gate(None, true), GateDecision::Refuse { .. }),
        "fetch failure + opt-in must still Refuse"
    );
    eprintln!("gate truth-table prelude: 4 cases OK");

    // ── Step 1: Fund ephemeral HOLDER + ISSUER accounts ──────────────────────
    let (holder_g, holder_signer) = fund_fresh_keypair().await;
    let (issuer_g, issuer_signer) = fund_fresh_keypair().await;

    let rpc = testnet_rpc();

    // Wait for both accounts to appear on testnet.
    let holder_appeared = wait_for_account(&rpc, &holder_g, 15).await;
    if !holder_appeared {
        eprintln!(
            "SKIP: holder {} did not appear on testnet within timeout",
            &holder_g[..8]
        );
        return;
    }
    let issuer_appeared = wait_for_account(&rpc, &issuer_g, 15).await;
    if !issuer_appeared {
        eprintln!(
            "SKIP: issuer {} did not appear on testnet within timeout",
            &issuer_g[..8]
        );
        return;
    }

    // ── Step 2: Set AUTH_REVOCABLE | AUTH_CLAWBACK_ENABLED on issuer ─────────
    // AUTH_REVOCABLE_FLAG = 0x2, AUTH_CLAWBACK_ENABLED_FLAG = 0x8
    let set_flags: u32 = 0x2 | 0x8;

    let issuer_account = fetch_account(&rpc, &issuer_g, &[])
        .await
        .expect("issuer account must be fetchable after Friendbot");
    let issuer_seq = issuer_account.sequence_number;

    let fee_per_op: u32 = 100;
    let mut set_flags_builder =
        ClassicOpBuilder::new(&issuer_g, issuer_seq, TESTNET_PASSPHRASE, fee_per_op);
    set_flags_builder
        .set_options_flags(set_flags, None)
        .expect("set_options_flags op construction must succeed");
    let set_flags_xdr = set_flags_builder
        .build()
        .expect("set_options envelope build must succeed");

    let set_flags_signed = attach_signature(&set_flags_xdr, &issuer_signer, TESTNET_PASSPHRASE)
        .await
        .expect("attach_signature for set_options must succeed");

    let timeout = Duration::from_secs(90);
    let SubmissionResult {
        tx_hash: set_flags_hash,
        ..
    } = submit_transaction_and_wait(
        &rpc,
        &set_flags_signed,
        timeout,
        TESTNET_PASSPHRASE,
        Some(SubmissionSignerKind::Software),
    )
    .await
    .expect("SetOptions AUTH_REVOCABLE|AUTH_CLAWBACK_ENABLED must submit and confirm");
    eprintln!(
        "SetOptions submitted; tx={}...{}",
        &set_flags_hash[..8.min(set_flags_hash.len())],
        if set_flags_hash.len() > 8 {
            &set_flags_hash[set_flags_hash.len().saturating_sub(8)..]
        } else {
            ""
        }
    );

    // Re-fetch issuer and assert AUTH_CLAWBACK_ENABLED + AUTH_REVOCABLE are set.
    let issuer_after = fetch_account(&rpc, &issuer_g, &[])
        .await
        .expect("issuer account re-fetch must succeed after SetOptions");

    let issuer_flags = issuer_after
        .account_flags
        .as_ref()
        .expect("issuer account must have account_flags after SetOptions");

    assert!(
        issuer_flags.auth_clawback_enabled,
        "issuer {} must have auth_clawback_enabled=true after SetOptions; \
         got flags: auth_required={} auth_revocable={} auth_clawback_enabled={}",
        &issuer_g[..8],
        issuer_flags.auth_required,
        issuer_flags.auth_revocable,
        issuer_flags.auth_clawback_enabled,
    );
    assert!(
        issuer_flags.auth_revocable,
        "issuer {} must have auth_revocable=true after SetOptions",
        &issuer_g[..8]
    );
    eprintln!(
        "issuer {} flags verified: auth_revocable=true auth_clawback_enabled=true",
        &issuer_g[..8]
    );

    // ── Step 3: Live gate path — no opt-in → RefuseWithWarning ───────────────
    // Use explicit CodeAndIssuer for the test asset (not pinned; passes resolver).
    let resolved = resolve_denomination(
        DenominationInput::CodeAndIssuer {
            code: "TEST".to_owned(),
            issuer: issuer_g.clone(),
        },
        TESTNET_PASSPHRASE,
    )
    .expect("CodeAndIssuer TEST:<issuer> must resolve (not in denylist)");

    // Open a real PendingApprovalStore in a temp directory — same public API the
    // MCP tool uses; no internal state or test-helper bypass.
    let tmp_dir = tempfile::TempDir::new().expect("tempfile::TempDir::new must succeed");
    let store_path: PathBuf = tmp_dir.path().join("approvals").join("default.toml");

    let mut store = PendingApprovalStore::open(store_path.clone())
        .expect("PendingApprovalStore::open must succeed on fresh temp dir");

    // Query the store — no opt-in yet.
    // Use the caip2_str canonical network key ("stellar:testnet"), not the passphrase.
    let opt_in_absent = store.has_attested_trustline_clawback_opt_in(
        "stellar:testnet",
        &resolved.code,
        &resolved.issuer,
        0, // now_unix_ms=0 means nothing is expired
    );
    assert!(!opt_in_absent, "fresh store must have no opt-in; got true");

    // Gate check: no opt-in → RefuseWithWarning.
    // Pass the AccountFlagsView read from the re-fetched issuer account directly.
    let gate_no_opt_in = clawback_gate(Some(issuer_flags), opt_in_absent);
    assert!(
        matches!(gate_no_opt_in, GateDecision::RefuseWithWarning { .. }),
        "clawback gate with live flags + no opt-in must produce \
         RefuseWithWarning; got: {gate_no_opt_in:?}"
    );
    eprintln!("gate step 3: RefuseWithWarning confirmed (no opt-in)");

    // ── Step 4: Record opt-in via real store write path ───────────────────────
    // Uses the same public constructor + insert + attest path that the
    // `approve --id` CLI uses. Test-only HMAC key in Zeroizing guard — never
    // touches the platform keyring.
    let uid = process_uid_for_attestation().expect("process_uid_for_attestation must succeed");

    let pending_entry = PendingApproval::new_trustline_clawback_opt_in_pending(
        "stellar:testnet".to_owned(),
        resolved.code.clone(),
        resolved.issuer.clone(),
        uid.clone(),
        DEFAULT_TTL_MS,
    )
    .expect("new_trustline_clawback_opt_in_pending must succeed");

    let approval_nonce = pending_entry.approval_nonce.clone();

    store
        .insert(pending_entry, 1)
        .expect("store.insert must succeed");

    // The store query before attestation must still return false (unattested).
    let opt_in_unattested = store.has_attested_trustline_clawback_opt_in(
        "stellar:testnet",
        &resolved.code,
        &resolved.issuer,
        0,
    );
    assert!(
        !opt_in_unattested,
        "unattested entry must NOT satisfy has_attested check; \
         got true"
    );

    // Compute the HMAC blob — same path as attest_and_persist in approve/run.rs.
    // Test-only key: 32 bytes of 0x42.  The digest input uses the caip2_str
    // canonical network key ("stellar:testnet"), not the passphrase, matching
    // how the live `approve --id` flow computes it.  The blob is later verified
    // via verify_attested_trustline_clawback_opt_in using the same key.
    let test_hmac_key = Zeroizing::new([0x42u8; 32]);
    let digest = compute_trustline_clawback_opt_in_digest(
        "stellar:testnet",
        &resolved.code,
        &resolved.issuer,
    );
    let attestation_blob = compute_attestation(&test_hmac_key, &approval_nonce, &digest, &uid);

    store
        .record_trustline_clawback_opt_in_attestation(&approval_nonce, attestation_blob)
        .expect("record_trustline_clawback_opt_in_attestation must succeed");

    // Now the HMAC-verified lookup must return true.  This is the production-
    // grade check: verify_attested_trustline_clawback_opt_in recomputes the
    // HMAC-SHA256 blob and constant-time-compares it against the stored value.
    // A forged or absent blob returns false (fail-closed).
    let opt_in_present = store.verify_attested_trustline_clawback_opt_in(
        &test_hmac_key,
        "stellar:testnet",
        &resolved.code,
        &resolved.issuer,
        0,
    );
    assert!(
        opt_in_present,
        "after attestation, verify_attested_trustline_clawback_opt_in \
         must return true with correct key; got false"
    );
    eprintln!("gate step 4: opt-in attested; store lookup returns true");

    // ── Step 5: Re-run gate → Proceed → build + submit ChangeTrust ───────────
    let gate_with_opt_in = clawback_gate(Some(issuer_flags), opt_in_present);
    assert_eq!(
        gate_with_opt_in,
        GateDecision::Proceed,
        "clawback gate + attested opt-in must Proceed; \
         got: {gate_with_opt_in:?}"
    );
    eprintln!("gate step 5: Proceed confirmed (opt-in present)");

    // Build and submit ChangeTrust TEST:<issuer> from the HOLDER account.
    let holder_account = fetch_account(&rpc, &holder_g, &[])
        .await
        .expect("holder account fetch must succeed");
    let holder_seq = holder_account.sequence_number;

    let test_asset = Asset::from_code_and_issuer(&resolved.code, &resolved.issuer)
        .expect("Asset::from_code_and_issuer must succeed for TEST:<issuer>");

    let mut change_trust_builder =
        ClassicOpBuilder::new(&holder_g, holder_seq, TESTNET_PASSPHRASE, fee_per_op);
    change_trust_builder
        .change_trust(&test_asset, None)
        .expect("change_trust op construction must succeed");
    let change_trust_xdr = change_trust_builder
        .build()
        .expect("ChangeTrust envelope build must succeed");

    let change_trust_signed =
        attach_signature(&change_trust_xdr, &holder_signer, TESTNET_PASSPHRASE)
            .await
            .expect("attach_signature for ChangeTrust must succeed");

    let SubmissionResult {
        tx_hash: ct_hash, ..
    } = submit_transaction_and_wait(
        &rpc,
        &change_trust_signed,
        timeout,
        TESTNET_PASSPHRASE,
        Some(SubmissionSignerKind::Software),
    )
    .await
    .expect("ChangeTrust TEST:<issuer> must submit and confirm on-chain");

    eprintln!(
        "ChangeTrust submitted; tx={}...{}",
        &ct_hash[..8.min(ct_hash.len())],
        if ct_hash.len() > 8 {
            &ct_hash[ct_hash.len().saturating_sub(8)..]
        } else {
            ""
        }
    );

    // ── Step 6: Verify the TEST:<issuer> balance line exists on holder ────────
    // `fetch_account` is getLedgerEntries-based: trustlines are projected ONLY
    // when explicitly requested via `trustline_assets` (an empty slice projects
    // the native balance alone), so the re-fetch must name the asset.
    let holder_after = fetch_account(&rpc, &holder_g, std::slice::from_ref(&test_asset))
        .await
        .expect("holder account re-fetch must succeed after ChangeTrust");

    // BalanceView.asset is AssetView { asset_type: code, issuer: Some(g_strkey) }
    // for non-native trustlines.
    let trustline_exists = holder_after.balances.iter().any(|b| {
        b.asset.asset_type == resolved.code
            && b.asset.issuer.as_deref() == Some(resolved.issuer.as_str())
    });

    assert!(
        trustline_exists,
        "holder {} must have a {}:{} balance line after ChangeTrust; \
         balances: {:?}",
        &holder_g[..8],
        resolved.code,
        &resolved.issuer[..8],
        holder_after
            .balances
            .iter()
            .map(|b| format!(
                "{}:{}",
                b.asset.asset_type,
                b.asset.issuer.as_deref().unwrap_or("native")
            ))
            .collect::<Vec<_>>()
    );

    eprintln!(
        "PASS: holder {} has {}:{} trustline; opt-in round-trip verified",
        &holder_g[..8],
        resolved.code,
        &resolved.issuer[..8]
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// USDT refusal (offline, no RPC)
// ─────────────────────────────────────────────────────────────────────────────

/// USDT (any case) is refused unconditionally before any RPC call.
///
/// Acceptance criteria:
/// 1. `resolve_denomination("USDT", testnet)` → `UsdtRefused`.
/// 2. `resolve_denomination("usdt", testnet)` → `UsdtRefused`.
/// 3. `resolve_denomination("USDT:GANYISSUER...", testnet)` → `UsdtRefused`.
/// 4. Refusal happens before any network access.
#[test]
fn usdt_refusal() {
    let passphrase = TESTNET_PASSPHRASE;
    let unpinned_issuer = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY";

    // case 1: bare code USDT.
    let err = resolve_denomination(DenominationInput::BareCode("USDT".to_owned()), passphrase)
        .expect_err("USDT bare code must be refused");
    assert!(
        matches!(&err, ResolveError::UsdtRefused { code } if code == "USDT"),
        "expected UsdtRefused for USDT, got: {err:?}"
    );

    // case 2: lowercase usdt.
    let err = resolve_denomination(DenominationInput::BareCode("usdt".to_owned()), passphrase)
        .expect_err("USDT (lowercase) must be refused");
    assert!(
        matches!(err, ResolveError::UsdtRefused { .. }),
        "expected UsdtRefused for usdt, got: {err:?}"
    );

    // case 3: USDT with explicit non-pinned issuer.
    let err = resolve_denomination(
        DenominationInput::CodeAndIssuer {
            code: "USDT".to_owned(),
            issuer: unpinned_issuer.to_owned(),
        },
        passphrase,
    )
    .expect_err("USDT with explicit issuer must be refused");
    assert!(
        matches!(err, ResolveError::UsdtRefused { .. }),
        "expected UsdtRefused for USDT+issuer, got: {err:?}"
    );

    eprintln!("PASS: USDT refused in all 3 cases (bare, lowercase, explicit issuer)");
}

// ─────────────────────────────────────────────────────────────────────────────
// Bare unknown code refusal (offline, no RPC)
// ─────────────────────────────────────────────────────────────────────────────

/// A bare code with no pin row is refused as `UnpinnedBareCode` before any RPC call.
///
/// Acceptance criteria:
/// 1. `resolve_denomination("FOO", testnet)` → `UnpinnedBareCode { code="FOO" }`.
/// 2. `resolve_denomination("EURAU", testnet)` → `UnpinnedBareCode`.
///    EURAU is not pinnable — its live on-chain assets are lookalikes — so it
///    is refused as an unpinned bare code.
#[test]
fn bare_unknown_code_refusal() {
    let passphrase = TESTNET_PASSPHRASE;

    // case 1: completely unknown bare code FOO.
    let err = resolve_denomination(DenominationInput::BareCode("FOO".to_owned()), passphrase)
        .expect_err("bare unknown code FOO must be refused");
    assert!(
        matches!(&err, ResolveError::UnpinnedBareCode { code, .. } if code == "FOO"),
        "expected UnpinnedBareCode for FOO, got: {err:?}"
    );

    // EURAU bare code: not pinnable (its live on-chain assets are lookalikes); refused as UnpinnedBareCode.
    let err = resolve_denomination(DenominationInput::BareCode("EURAU".to_owned()), passphrase)
        .expect_err("bare EURAU (no pin row) must be refused");
    assert!(
        matches!(err, ResolveError::UnpinnedBareCode { .. }),
        "expected UnpinnedBareCode for EURAU, got: {err:?}"
    );

    eprintln!("PASS: bare unknown codes FOO and EURAU refused as unpinned");
}
