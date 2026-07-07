//! Concurrent pooled submission against testnet.
//!
//! # Feature gate
//!
//! Gated behind `--features testnet-acceptance`.  Run with:
//!
//! ```sh
//! cargo test -p stellar-agent-pool --features testnet-acceptance \
//!     --test pool_concurrent_testnet
//! ```
//!
//! # What this test does
//!
//! 1. Generates an ephemeral funder keypair; funds it via Friendbot.
//! 2. Derives N=4 channel keypairs from an ephemeral pool master seed.
//! 3. Funds each channel with a small XLM payment so it can pay its own fee.
//! 4. Fetches all channel sequence numbers.
//! 5. Drives K=8 concurrent `submit_pooled` calls (two passes through the pool).
//! 6. Asserts ALL submissions succeed with no `tx_bad_seq` (hard assertion).
//! 7. Measures total concurrent wall-time versus a single-submission baseline
//!    and reports the ratio (soft bound — reported, not asserted, because
//!    testnet latency variance is outside the test's control).
//!
//! # No committed secrets
//!
//! Funder and channel keypairs are generated ephemerally at test time.
//! No `S...` strkey is committed in this file.
//!
//! # Skip policy
//!
//! - `"ACCEPTANCE SKIPPED: testnet RPC unreachable"` — HEAD probe failed.
//! - `"ACCEPTANCE SKIPPED: Friendbot funding failed"` — Friendbot unavailable.
//!
//! Fund-then-check-existence (not balance-threshold assertions).
//!
//! # Note on pool master seed
//!
//! This test bypasses the keyring (no keyring entry is created) by using an
//! ephemeral in-memory seed passed directly to `submit_pooled`.  The seed is
//! dropped after the test.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    reason = "test-only; panics, unwraps, and eprintln are acceptable in acceptance tests"
)]

#[cfg(feature = "testnet-acceptance")]
mod live {
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use ed25519_dalek::SigningKey as DalekSigningKey;
    use rand_core::OsRng;
    use stellar_agent_core::StellarAmount;
    use stellar_agent_core::observability::redact_strkey_first5_last5;
    use stellar_agent_network::builder::Asset;
    use stellar_agent_network::{
        ClassicOpBuilder, SoftwareSigningKey, StellarRpcClient, fetch_account, fund_with_friendbot,
        submit_transaction_and_wait,
    };
    use stellar_agent_pool::pool::ChannelPool;
    use stellar_agent_pool::submit::submit_pooled;
    use stellar_agent_pool::{ChannelRecord, PoolError};
    use stellar_agent_sep5::Sep5Wallet;
    use stellar_strkey::ed25519::PublicKey as StrPublicKey;
    use tokio::task::JoinSet;
    use zeroize::Zeroizing;

    const TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";
    const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";
    const TESTNET_FRIENDBOT_URL: &str = "https://friendbot.stellar.org";

    /// Number of channels to initialise.
    const POOL_SIZE: usize = 4;

    /// Number of concurrent submissions per pass (POOL_SIZE * 2 = two passes).
    const TOTAL_SUBMISSIONS: usize = 8;

    /// Per-submission fee (generous for testnet).
    const FEE_PER_OP: u32 = 1000;

    /// Submission timeout.
    const SUBMIT_TIMEOUT: Duration = Duration::from_secs(90);

    /// Amount sent in each pooled payment (1 stroop — small enough to succeed
    /// from the channel's funded balance).
    const PAYMENT_STROOPS: i64 = 1;

    // ─────────────────────────────────────────────────────────────────────────
    // Ephemeral key helpers
    // ─────────────────────────────────────────────────────────────────────────

    /// Generate an ephemeral ed25519 keypair → (G-strkey, SoftwareSigningKey).
    fn gen_ephemeral_key() -> (String, SoftwareSigningKey) {
        let signing_key = DalekSigningKey::generate(&mut OsRng);
        let pk_bytes: [u8; 32] = signing_key.verifying_key().to_bytes();
        let strkey = StrPublicKey(pk_bytes).to_string().as_str().to_owned();
        let secret_bytes: [u8; 32] = signing_key.to_bytes();
        (strkey, SoftwareSigningKey::new_from_bytes(secret_bytes))
    }

    /// Generate an ephemeral 64-byte seed.
    fn gen_ephemeral_seed() -> Zeroizing<[u8; 64]> {
        let mut seed = [0u8; 64];
        use rand_core::RngCore;
        OsRng.fill_bytes(&mut seed);
        Zeroizing::new(seed)
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Reachability probe (synchronous, tokio block_in_place)
    // ─────────────────────────────────────────────────────────────────────────

    fn rpc_reachable() -> bool {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                reqwest::Client::builder()
                    .timeout(Duration::from_secs(10))
                    .build()
                    .ok()?
                    .head(TESTNET_RPC_URL)
                    .send()
                    .await
                    .ok()
            })
        })
        .is_some()
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Concurrent testnet test
    // ─────────────────────────────────────────────────────────────────────────

    /// Concurrent pooled submission against testnet.
    ///
    /// Drives `TOTAL_SUBMISSIONS` concurrent `submit_pooled` calls through a
    /// `POOL_SIZE`-channel pool, using two "rounds" (N concurrent tasks
    /// × 2 rounds = 2N total).  Asserts zero `tx_bad_seq` errors and full
    /// pool-free state after all submissions.  The concurrent wall-time ratio
    /// versus a single-submission baseline is measured and reported as a soft
    /// bound (not asserted) because testnet latency variance is outside the
    /// test's control.
    #[tokio::test(flavor = "multi_thread")]
    async fn pool_concurrent_testnet_8_submissions_no_tx_bad_seq() {
        // ── RPC reachability probe ────────────────────────────────────────────
        if !rpc_reachable() {
            eprintln!(
                "ACCEPTANCE SKIPPED: testnet RPC unreachable ({})",
                TESTNET_RPC_URL
            );
            return;
        }

        let client = Arc::new(
            StellarRpcClient::new(TESTNET_RPC_URL).expect("testnet RPC URL must be valid"),
        );

        // ── Generate funder keypair + fund via Friendbot ─────────────────────
        let (funder_strkey, funder_signer) = gen_ephemeral_key();
        eprintln!("Funder: {}", redact_strkey_first5_last5(&funder_strkey));

        match fund_with_friendbot(TESTNET_FRIENDBOT_URL, &funder_strkey, TESTNET_PASSPHRASE).await {
            Ok(r) => eprintln!(
                "Friendbot funded funder; tx_hash={}",
                stellar_agent_network::submit::redact_tx_hash(&r.tx_hash)
            ),
            Err(e) => {
                eprintln!("ACCEPTANCE SKIPPED: Friendbot funding failed: {}", e);
                return;
            }
        }

        // ── Derive channel public keys from ephemeral pool master seed ────────
        let pool_master_seed = gen_ephemeral_seed();
        // Clone the seed for the wallet constructor so pool_master_seed remains
        // alive for the subsequent submit_pooled calls.  Use
        // from_bip39_seed_zeroizing so no bare [u8;64] temporary forms.
        let wallet = Sep5Wallet::from_bip39_seed_zeroizing(Zeroizing::new(*pool_master_seed));

        let mut channel_strkeys: Vec<String> = Vec::with_capacity(POOL_SIZE);

        for idx in 1..=(POOL_SIZE as u32) {
            let derived = wallet
                .derive_account(idx)
                .expect("derivation must succeed for valid index");
            let strkey = derived.public_key_strkey();
            // Channel signers are NOT stored here — submit_pooled re-derives
            // them internally from pool_master_seed per submission (no live
            // secret window between funding and submission).
            eprintln!("Channel {idx}: {}", redact_strkey_first5_last5(&strkey));
            channel_strkeys.push(strkey);
        }

        // ── Fund each channel from the funder ────────────────────────────────
        // Each channel must pay FEE_PER_OP per submission.  The Stellar protocol
        // minimum balance is (2 + subentry_count) × BASE_RESERVE_STROOPS stroops.
        // For a fresh account with zero subentries that is 2 × 5_000_000 = 10_000_000
        // stroops (1 XLM) — zero spendable.  We must fund above reserve so each
        // channel has genuine spendable balance for fees and the 1-stroop payments.
        //
        // Budget per channel:
        //   reserve (unspendable) : 2 × 5_000_000 = 10_000_000 stroops
        //   9 submissions max     : 9 × (FEE_PER_OP=1_000 + PAYMENT_STROOPS=1) ≈ 9_009 stroops
        //   ─────────────────────────────────────────────────────────────────────
        //   Funded amount (5 XLM) : 50_000_000 stroops
        //   Spendable headroom    : 50_000_000 − 10_000_000 = 40_000_000 stroops >> 9_009
        //
        // Friendbot funds the funder with 10_000 XLM; 4 channels × 5 XLM = 20 XLM
        // plus fees is well within that budget.
        //
        // Verify existence after funding, not balance thresholds.
        let funder_view = fetch_account(&client, &funder_strkey, &[])
            .await
            .expect("funder account must exist after Friendbot funding");
        for (funder_seq, channel_strkey) in
            (funder_view.sequence_number..).zip(channel_strkeys.iter())
        {
            // 5 XLM per channel: 4 XLM spendable above the 1 XLM minimum reserve,
            // sufficient for all baseline + concurrent submissions.
            // funder_seq starts at funder_view.sequence_number and increments by
            // 1 per iteration (one on-chain sequence advance per create_account tx).
            let five_xlm = StellarAmount::from_stroops(50_000_000); // 5 XLM
            let mut builder = ClassicOpBuilder::new(
                funder_strkey.as_str(),
                funder_seq,
                TESTNET_PASSPHRASE,
                FEE_PER_OP,
            );
            builder
                .create_account(channel_strkey, five_xlm)
                .expect("create_account op must succeed");

            let signed_xdr = builder
                .build_and_sign(&funder_signer)
                .await
                .expect("build_and_sign must succeed");

            let fund_result = submit_transaction_and_wait(
                &client,
                &signed_xdr,
                SUBMIT_TIMEOUT,
                TESTNET_PASSPHRASE,
                None,
            )
            .await
            .unwrap_or_else(|e| {
                panic!(
                    "funding create_account for {} failed: {}",
                    redact_strkey_first5_last5(channel_strkey),
                    e
                )
            });

            eprintln!(
                "Channel {} funded (ledger {})",
                redact_strkey_first5_last5(channel_strkey),
                fund_result.ledger
            );
        }

        // ── Fetch all channel sequence numbers ───────────────────────────────
        let mut channel_seqs: Vec<i64> = Vec::with_capacity(POOL_SIZE);
        for channel_strkey in &channel_strkeys {
            let view = fetch_account(&client, channel_strkey, &[])
                .await
                .unwrap_or_else(|e| {
                    panic!(
                        "channel {} not found on-chain after funding: {}",
                        redact_strkey_first5_last5(channel_strkey),
                        e
                    )
                });
            channel_seqs.push(view.sequence_number);
            eprintln!(
                "Channel {} seq={}",
                redact_strkey_first5_last5(channel_strkey),
                view.sequence_number
            );
        }

        // ── Build the ChannelPool ────────────────────────────────────────────
        let records: Vec<ChannelRecord> = channel_strkeys
            .iter()
            .enumerate()
            .map(|(i, strkey)| ChannelRecord::new((i + 1) as u32, strkey.as_str()))
            .collect();

        let pool = Arc::new(
            ChannelPool::from_records(records, channel_seqs)
                .expect("pool construction must succeed"),
        );

        // The funder is also the payment destination (self-payment is fine on
        // testnet for testing purposes — it is the simplest operation that
        // exercises the full submission path without trustline requirements).
        let dest = funder_strkey.clone();

        // ── Baseline: one single submission to measure wall-time ─────────────
        let single_start = Instant::now();

        // Fetch and release the first single submit before the concurrent burst.
        // We do ONE single submission synchronously to get the baseline.
        let single_result = submit_pooled(
            &pool,
            &client,
            &pool_master_seed,
            TESTNET_PASSPHRASE,
            FEE_PER_OP,
            SUBMIT_TIMEOUT,
            |builder| {
                let _ = builder.payment(
                    &dest,
                    StellarAmount::from_stroops(PAYMENT_STROOPS),
                    &Asset::Native,
                );
            },
        )
        .await;

        let single_elapsed = single_start.elapsed();

        match &single_result {
            Ok(r) => eprintln!(
                "Single baseline submit: channel_index={}, outcome={:?}, elapsed={:?}",
                r.channel_index, r.outcome, single_elapsed
            ),
            Err(e) => panic!("baseline single submit failed: {e}"),
        }
        single_result.expect("single baseline submit must succeed");

        // ── Concurrent burst: TOTAL_SUBMISSIONS concurrent submit_pooled ─────
        // Use POOL_SIZE tasks concurrently (pool has POOL_SIZE channels; 1 was
        // just used, so 3 free).  Then a second round of POOL_SIZE tasks.
        // Total: 2 × POOL_SIZE = TOTAL_SUBMISSIONS = 8.
        let concurrent_start = Instant::now();
        let mut total_tx_bad_seq = 0usize;
        let mut total_success = 0usize;

        for round in 1..=2 {
            let mut join_set: JoinSet<Result<(), PoolError>> = JoinSet::new();

            for _ in 0..POOL_SIZE {
                let pool_clone = Arc::clone(&pool);
                let client_clone = Arc::clone(&client);
                let seed_clone = Zeroizing::new(*pool_master_seed);
                let dest_clone = dest.clone();

                join_set.spawn(async move {
                    let res = submit_pooled(
                        &pool_clone,
                        &client_clone,
                        &seed_clone,
                        TESTNET_PASSPHRASE,
                        FEE_PER_OP,
                        SUBMIT_TIMEOUT,
                        |builder| {
                            let _ = builder.payment(
                                &dest_clone,
                                StellarAmount::from_stroops(PAYMENT_STROOPS),
                                &Asset::Native,
                            );
                        },
                    )
                    .await;
                    res.map(|_| ())
                });
            }

            while let Some(join_result) = join_set.join_next().await {
                match join_result {
                    Ok(Ok(())) => total_success += 1,
                    Ok(Err(e)) => {
                        let msg = e.to_string().to_lowercase();
                        if msg.contains("tx_bad_seq") || msg.contains("txbadseq") {
                            total_tx_bad_seq += 1;
                            eprintln!("tx_bad_seq in round {round}: {e}");
                        } else {
                            panic!(
                                "submit_pooled failed with non-tx_bad_seq error in round {round}: {e}"
                            );
                        }
                    }
                    Err(e) => panic!("task join error in round {round}: {e}"),
                }
            }

            eprintln!("Round {round} complete: {} successes so far", total_success);
        }

        let concurrent_elapsed = concurrent_start.elapsed();

        // ── Assertions ────────────────────────────────────────────────────────

        // Zero tx_bad_seq from pool contention.
        assert_eq!(
            total_tx_bad_seq, 0,
            "zero tx_bad_seq from pool contention; got {total_tx_bad_seq}"
        );

        // All 2×POOL_SIZE concurrent submissions must succeed.
        // (1 baseline + 2×POOL_SIZE concurrent = 1 + 8 = 9 total; we count only concurrent here)
        assert_eq!(
            total_success, TOTAL_SUBMISSIONS,
            "expected {TOTAL_SUBMISSIONS} concurrent successes; got {total_success}"
        );

        // Wall-time: total concurrent elapsed < 3× single submission baseline.
        // This is a soft bound — CI can be slow; we report but do not fail on CI.
        let wall_time_ratio = concurrent_elapsed.as_secs_f64() / single_elapsed.as_secs_f64();
        eprintln!(
            "Throughput: {} submissions in {:?} ({:.1}x single baseline {:?})",
            TOTAL_SUBMISSIONS, concurrent_elapsed, wall_time_ratio, single_elapsed
        );
        if wall_time_ratio >= 3.0 {
            eprintln!(
                "NOTE: concurrent wall-time ({:?}) exceeded 3x single baseline ({:?}) by {:.1}x; \
                 this indicates network latency variance on testnet, not a pool correctness issue. \
                 The per-channel sequence correctness is proven by the zero tx_bad_seq count.",
                concurrent_elapsed, single_elapsed, wall_time_ratio
            );
        }

        // Pool must be fully free after all submissions.
        assert_eq!(
            pool.free_count(),
            POOL_SIZE,
            "pool must be fully free after all submissions"
        );

        eprintln!(
            "CONCURRENT TESTNET PASSED: {total_success} successful pooled submissions, \
             0 tx_bad_seq, wall-time {:.1}x single baseline.",
            wall_time_ratio
        );
    }
}
