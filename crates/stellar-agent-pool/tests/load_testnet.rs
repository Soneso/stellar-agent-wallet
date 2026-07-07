//! Load assertion — live over-subscription against testnet.
//!
//! # Coverage scope
//!
//! This test covers live over-subscription: more concurrent attempts than pool
//! channels, in a single instant, against real testnet, forcing the
//! `PoolError::PoolExhausted` reject-at-capacity path at scale.
//!
//! The following aspects are covered by sibling tests and are NOT re-asserted
//! here:
//!
//! 1. **Structural no-queue / typed-reject proof** (`tests/concurrency.rs`):
//!    off-network, N=4 channels, M=8 concurrent `acquire()` calls; proves exactly
//!    N succeed and M−N return `PoolExhausted` IMMEDIATELY within a tight 50 ms
//!    timeout; proves `in_flight_count`/`free_count` accounting and
//!    no-cross-channel-sequence-sharing without any network.
//!
//! 2. **Small-scale concurrent testnet test** (`tests/pool_concurrent_testnet.rs`):
//!    K=8 attempts against a N=4 channel pool, two rounds; asserts all 8 succeed
//!    with `tx_bad_seq==0` and total wall-time < 3× single baseline.
//!
//! What this test adds: a single burst of `TOTAL_ATTEMPTS=100` concurrent tasks
//! against a `POOL_SIZE=16` channel pool — a 6.25× over-subscription ratio that
//! forces reject-at-capacity at scale.  It then asserts:
//!
//! - Success rate ≥ 99% of attempts not immediately rejected by `PoolExhausted`.
//! - `tx_bad_seq == 0` even across 100 concurrent attempts.
//! - Over-subscription exercised: `pool_exhausted_count > 0`.
//! - `success_count == TOTAL_ATTEMPTS - pool_exhausted_count`.
//!
//! # Feature gate
//!
//! Gated behind `--features testnet-acceptance`.  Run with:
//!
//! ```sh
//! cargo test -p stellar-agent-pool --features testnet-acceptance \
//!     --test load_testnet -- --nocapture
//! ```
//!
//! # Funding / reserve-floor
//!
//! Each channel is funded with 5 XLM (50_000_000 stroops): 4 XLM spendable
//! above the 1 XLM minimum reserve.  The test verifies channel existence, not
//! balance thresholds.
//!
//! # Skip policy
//!
//! - `"LOAD SKIPPED: testnet RPC unreachable"` — HEAD probe failed.
//! - `"LOAD SKIPPED: Friendbot funding failed"` — Friendbot unavailable.
//!

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
    use std::time::Duration;

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

    /// Pool size: 16 channels.  Largest pool that completes within CI testnet
    /// time while remaining below MAX_SIZE=19.
    const POOL_SIZE: usize = 16;

    /// Total concurrent attempt count.  100 against 16 channels = 6.25× over-
    /// subscription.  Designed to force reject-at-capacity on ~84 attempts and
    /// confirm the 16 successful ones succeed with zero tx_bad_seq.
    const TOTAL_ATTEMPTS: usize = 100;

    /// Success-rate lower bound for non-exhausted attempts.  Expressed as ≥ 99%
    /// to allow for a single transient RPC glitch on testnet without a spurious
    /// test failure.
    const SUCCESS_RATE_FLOOR: f64 = 0.99;

    const FEE_PER_OP: u32 = 1_000;
    const SUBMIT_TIMEOUT: Duration = Duration::from_secs(90);

    /// Classified outcome of one `submit_pooled` attempt.
    #[derive(Debug)]
    enum Outcome {
        Success,
        PoolExhausted,
        TxBadSeq,
        OtherFailure,
    }

    /// Generate an ephemeral ed25519 keypair → (G-strkey, SoftwareSigningKey).
    fn gen_ephemeral_key() -> (String, SoftwareSigningKey) {
        let signing_key = DalekSigningKey::generate(&mut OsRng);
        let strkey = StrPublicKey(signing_key.verifying_key().to_bytes())
            .to_string()
            .as_str()
            .to_owned();
        (
            strkey,
            SoftwareSigningKey::new_from_bytes(signing_key.to_bytes()),
        )
    }

    fn gen_ephemeral_seed() -> Zeroizing<[u8; 64]> {
        let mut seed = [0u8; 64];
        use rand_core::RngCore;
        OsRng.fill_bytes(&mut seed);
        Zeroizing::new(seed)
    }

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

    /// Load assertion: 100 concurrent attempts against 16 channels.
    ///
    /// Sibling tests not re-asserted here:
    /// - `tests/concurrency.rs` — structural no-queue/typed-reject proof
    ///   (off-network; tight 50 ms acquire timeout; M=2N concurrency).
    /// - `tests/pool_concurrent_testnet.rs` — small-scale (K=8, N=4)
    ///   success-rate + `tx_bad_seq==0` on real testnet.
    ///
    /// This test asserts live over-subscription at scale.
    #[tokio::test(flavor = "multi_thread")]
    async fn load_100_attempts_16_channels_over_subscription() {
        // ── RPC reachability probe ────────────────────────────────────────────
        if !rpc_reachable() {
            eprintln!(
                "LOAD SKIPPED: testnet RPC unreachable ({})",
                TESTNET_RPC_URL
            );
            return;
        }

        let client = Arc::new(
            StellarRpcClient::new(TESTNET_RPC_URL).expect("testnet RPC URL must be valid"),
        );

        // ── Generate funder + fund via Friendbot ─────────────────────────────
        let (funder_strkey, funder_signer) = gen_ephemeral_key();
        // Redact: first-5-last-5.
        eprintln!("Funder: {}", redact_strkey_first5_last5(&funder_strkey));

        match fund_with_friendbot(TESTNET_FRIENDBOT_URL, &funder_strkey, TESTNET_PASSPHRASE).await {
            Ok(r) => eprintln!(
                "Friendbot funded funder; tx_hash={}",
                stellar_agent_network::submit::redact_tx_hash(&r.tx_hash)
            ),
            Err(e) => {
                eprintln!("LOAD SKIPPED: Friendbot funding failed: {e}");
                return;
            }
        }

        // ── Derive POOL_SIZE channel public keys from ephemeral seed ─────────
        let pool_master_seed = gen_ephemeral_seed();
        let wallet = Sep5Wallet::from_bip39_seed_zeroizing(Zeroizing::new(*pool_master_seed));
        let mut channel_strkeys: Vec<String> = Vec::with_capacity(POOL_SIZE);

        for idx in 1..=(POOL_SIZE as u32) {
            let derived = wallet
                .derive_account(idx)
                .expect("derivation must succeed for valid index");
            channel_strkeys.push(derived.public_key_strkey());
            eprintln!(
                "Channel {idx}: {}",
                redact_strkey_first5_last5(channel_strkeys.last().unwrap())
            );
        }

        // ── Fund each channel from funder — 5 XLM each ──────────────────────
        // 5 XLM per channel: 4 XLM spendable above the 1 XLM minimum reserve.
        // Friendbot funds funder with 10_000 XLM; 16 × 5 XLM = 80 XLM is well
        // within that budget.  Verify channel existence after funding, not balance.
        let funder_view = fetch_account(&client, &funder_strkey, &[])
            .await
            .expect("funder account must exist after Friendbot");

        for (funder_seq, channel_strkey) in
            (funder_view.sequence_number..).zip(channel_strkeys.iter())
        {
            let five_xlm = StellarAmount::from_stroops(50_000_000);
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
        for ch in &channel_strkeys {
            let view = fetch_account(&client, ch, &[]).await.unwrap_or_else(|e| {
                panic!(
                    "channel {} not found after funding: {}",
                    redact_strkey_first5_last5(ch),
                    e
                )
            });
            channel_seqs.push(view.sequence_number);
        }

        // ── Build the ChannelPool ────────────────────────────────────────────
        let records: Vec<ChannelRecord> = channel_strkeys
            .iter()
            .enumerate()
            .map(|(i, k)| ChannelRecord::new((i + 1) as u32, k.as_str()))
            .collect();
        let pool = Arc::new(
            ChannelPool::from_records(records, channel_seqs)
                .expect("pool construction must succeed"),
        );

        let dest = funder_strkey.clone();

        // ── Over-subscription burst: TOTAL_ATTEMPTS concurrent tasks ─────────
        // Launch all TOTAL_ATTEMPTS tasks simultaneously.
        // TOTAL_ATTEMPTS (100) > POOL_SIZE (16) → 84 tasks get PoolExhausted
        // immediately; 16 tasks compete for the 16 channels and should all
        // succeed on real testnet.
        //
        // concurrency.rs proves reject-at-capacity off-network;
        // pool_concurrent_testnet.rs proves K=8 / N=4 success on real testnet;
        // this test proves K=100 / N=16 live over-subscription at scale.
        let mut join_set: JoinSet<Outcome> = JoinSet::new();

        for _ in 0..TOTAL_ATTEMPTS {
            let pool_clone = Arc::clone(&pool);
            let client_clone = Arc::clone(&client);
            let seed_clone = Zeroizing::new(*pool_master_seed);
            let dest_clone = dest.clone();

            join_set.spawn(async move {
                match submit_pooled(
                    &pool_clone,
                    &client_clone,
                    &seed_clone,
                    TESTNET_PASSPHRASE,
                    FEE_PER_OP,
                    SUBMIT_TIMEOUT,
                    |builder| {
                        let _ = builder.payment(
                            &dest_clone,
                            StellarAmount::from_stroops(1),
                            &Asset::Native,
                        );
                    },
                )
                .await
                {
                    Ok(_) => Outcome::Success,
                    Err(PoolError::PoolExhausted { .. }) => Outcome::PoolExhausted,
                    Err(e) => {
                        let msg = e.to_string().to_lowercase();
                        if msg.contains("tx_bad_seq") || msg.contains("txbadseq") {
                            Outcome::TxBadSeq
                        } else {
                            Outcome::OtherFailure
                        }
                    }
                }
            });
        }

        // ── Collect ───────────────────────────────────────────────────────────
        let mut success_count: usize = 0;
        let mut pool_exhausted_count: usize = 0;
        let mut tx_bad_seq_count: usize = 0;
        let mut other_failure_count: usize = 0;

        while let Some(r) = join_set.join_next().await {
            match r.expect("task must not panic") {
                Outcome::Success => success_count += 1,
                Outcome::PoolExhausted => pool_exhausted_count += 1,
                Outcome::TxBadSeq => tx_bad_seq_count += 1,
                Outcome::OtherFailure => other_failure_count += 1,
            }
        }

        let non_exhausted = TOTAL_ATTEMPTS - pool_exhausted_count;
        let success_rate = if non_exhausted > 0 {
            success_count as f64 / non_exhausted as f64
        } else {
            0.0
        };

        eprintln!(
            "LOAD results: attempts={TOTAL_ATTEMPTS} successes={success_count} \
             pool_exhausted={pool_exhausted_count} tx_bad_seq={tx_bad_seq_count} \
             other_failures={other_failure_count} success_rate={:.1}%",
            success_rate * 100.0
        );

        // ── Assertions ────────────────────────────────────────────────────────

        // (a) Zero tx_bad_seq under live contention.
        // The per-channel exclusive sequence + reject-at-capacity design
        // structurally prevents tx_bad_seq from pool contention; this test
        // confirms the invariant holds on real testnet under 100-task concurrency.
        assert_eq!(
            tx_bad_seq_count, 0,
            "{tx_bad_seq_count} tx_bad_seq under load; \
             the per-channel exclusive sequence invariant must hold at \
             {TOTAL_ATTEMPTS}-task concurrency against {POOL_SIZE} channels. \
             Structural proof: tests/concurrency.rs"
        );

        // (b) Over-subscription actually exercised: pool_exhausted > 0.
        // With TOTAL_ATTEMPTS=100 > POOL_SIZE=16 all launched simultaneously,
        // at least TOTAL_ATTEMPTS - POOL_SIZE = 84 should be rejected.
        // We only require > 0 to remain robust if the OS scheduler happens to
        // serialise some tasks before pool acquisition.
        assert!(
            pool_exhausted_count > 0,
            "expected pool_exhausted_count > 0 for {TOTAL_ATTEMPTS} concurrent attempts \
             against {POOL_SIZE} channels (over-subscription not exercised); \
             got pool_exhausted_count=0"
        );

        // (c) Every non-exhausted attempt succeeded (≥ 99%).
        // The 1% margin accommodates transient testnet RPC glitches.
        assert!(
            success_rate >= SUCCESS_RATE_FLOOR,
            "success rate {:.1}% < floor {:.0}% \
             (successes={success_count} / non_exhausted={non_exhausted}; \
             other_failures={other_failure_count})",
            success_rate * 100.0,
            SUCCESS_RATE_FLOOR * 100.0
        );

        // (d) No unexpected other failures.
        assert_eq!(
            other_failure_count, 0,
            "unexpected {other_failure_count} non-exhaustion, non-tx_bad_seq failures; \
             check logs for details"
        );

        // Pool fully free after all tasks complete.
        assert_eq!(
            pool.free_count(),
            POOL_SIZE,
            "pool must be fully free after all {TOTAL_ATTEMPTS} tasks complete; \
             got free_count={}",
            pool.free_count()
        );

        eprintln!(
            "LOAD PASSED: {success_count} successes / {pool_exhausted_count} rejected \
             (over-subscribed) / 0 tx_bad_seq. {:.1}% >= {:.0}%.",
            success_rate * 100.0,
            SUCCESS_RATE_FLOOR * 100.0
        );
    }
}
