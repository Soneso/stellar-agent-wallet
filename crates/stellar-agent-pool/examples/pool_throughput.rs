//! Throughput benchmark harness for `submit_pooled`.
//!
//! Measures sustainable submissions/sec for a channel pool against Stellar
//! testnet, with support for **over-subscription** (more concurrent attempts
//! than pool channels).  This is NOT a CI gate — it is a reproducible manual
//! benchmark.
//!
//! # Usage
//!
//! ```sh
//! # Minimal — default pool_size=16, concurrency=100:
//! cargo run -p stellar-agent-pool --example pool_throughput \
//!   --features testnet-acceptance
//!
//! # Explicit knobs:
//! cargo run -p stellar-agent-pool --example pool_throughput \
//!   --features testnet-acceptance -- \
//!   --pool-size 16 --concurrency 100
//! ```
//!
//! # CLI arguments
//!
//! | Flag | Default | Notes |
//! |------|---------|-------|
//! | `--pool-size N` | `16` | Channel count, clamped to 1–19 (`ChannelPool::MAX_SIZE`). |
//! | `--concurrency N` | `100` | Total concurrent attempt count per run.  Setting this higher than `pool_size` exercises the over-subscription (reject-at-capacity) path. |
//!
//! Concurrency > pool_size forces `PoolError::PoolExhausted` on the over-
//! subscription fraction, exercising the reject-at-capacity path under real
//! network load.
//!
//! # Metrics emitted
//!
//! ```text
//! === pool_throughput results ===
//!   pool_size:             16
//!   total_attempts:        100
//!   successes:             16
//!   pool_exhausted:        84       ← over-subscription rejects
//!   tx_bad_seq:            0        ← MUST be 0 (no cross-channel seq sharing)
//!   other_failures:        0
//!   success_rate:          16.00%
//!   total_elapsed:         6.31s
//!   throughput (success):  2.54 submissions/sec
//!   sustainable_tps_model: ~3.2/s (pool_size=16 / confirm_latency=5s)
//! ================================
//! (Sample values are illustrative, not a recorded run; the emitted field
//!  labels match the format strings below.)
//! ```
//!
//! # Throughput model
//!
//! Sustainable TPS per identity ≈ `pool_size / per-submission confirm latency`.
//! Testnet ledger close time averages ~5 s; with 16 channels that is ~3.2
//! submissions/sec in a fully pipelined steady state.
//!
//! # Redaction
//!
//! All log output is redacted: account IDs use first-5-last-5 (`GAAAA…ZZZZZ`),
//! transaction hashes use first-8-last-8.  No raw key material is ever logged.
//!
//! # Reproduction
//!
//! ```sh
//! cargo run -p stellar-agent-pool --example pool_throughput \
//!   --features testnet-acceptance 2>&1 | tee /tmp/pool_throughput.log
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::explicit_auto_deref,
    reason = "benchmark example binary; relaxed lints for clarity and diagnostics output"
)]

fn main() {
    // This example requires `--features testnet-acceptance` to build with
    // the live Stellar network code paths.  Without that feature it prints
    // a message and exits cleanly so `cargo build --all-targets` succeeds.
    #[cfg(not(feature = "testnet-acceptance"))]
    {
        eprintln!(
            "pool_throughput: this example requires --features testnet-acceptance \
             to run against testnet.  See the module docstring for usage."
        );
        std::process::exit(0);
    }

    #[cfg(feature = "testnet-acceptance")]
    {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime")
            .block_on(run_benchmark());
    }
}

#[cfg(feature = "testnet-acceptance")]
async fn run_benchmark() {
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
    use stellar_agent_pool::ChannelRecord;
    use stellar_agent_pool::pool::ChannelPool;
    use stellar_agent_pool::submit::submit_pooled;
    use stellar_agent_sep5::Sep5Wallet;
    use stellar_strkey::ed25519::PublicKey as StrPublicKey;
    use tokio::task::JoinSet;
    use zeroize::Zeroizing;

    // ── Parse arguments ──────────────────────────────────────────────────────
    // Simple --flag value pairs; no clap dep so the example has no new deps.
    let args: Vec<String> = std::env::args().collect();

    let requested_pool_size: usize = args
        .windows(2)
        .find(|w| w[0] == "--pool-size")
        .and_then(|w| w[1].parse().ok())
        .unwrap_or(16);

    // Clamp to MAX_SIZE; reject 0.
    let pool_size: usize = if requested_pool_size == 0 {
        eprintln!("pool-size must be >= 1; got 0");
        std::process::exit(1);
    } else if requested_pool_size > ChannelPool::MAX_SIZE {
        eprintln!(
            "pool-size {requested_pool_size} exceeds MAX_SIZE={max} (VecM 20-signature cap); \
             clamping to {max}",
            max = ChannelPool::MAX_SIZE,
        );
        ChannelPool::MAX_SIZE
    } else {
        requested_pool_size
    };

    // Total concurrent attempts.  Setting this > pool_size forces PoolExhausted
    // on the over-subscription fraction, exercising the reject-at-capacity path.
    let total_concurrency: usize = args
        .windows(2)
        .find(|w| w[0] == "--concurrency")
        .and_then(|w| w[1].parse().ok())
        .unwrap_or(100);

    if total_concurrency == 0 {
        eprintln!("concurrency must be >= 1; got 0");
        std::process::exit(1);
    }

    eprintln!(
        "pool_throughput: pool_size={pool_size} total_concurrency={total_concurrency} \
         (over-subscription ratio: {:.1}x)",
        total_concurrency as f64 / pool_size as f64
    );

    const TESTNET_RPC: &str = "https://soroban-testnet.stellar.org";
    const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";
    const FRIENDBOT_URL: &str = "https://friendbot.stellar.org";
    const FEE: u32 = 1000;
    const TIMEOUT: Duration = Duration::from_secs(90);

    // ── Ephemeral funder ─────────────────────────────────────────────────────
    fn gen_key() -> (String, SoftwareSigningKey) {
        let sk = DalekSigningKey::generate(&mut OsRng);
        let strkey = StrPublicKey(sk.verifying_key().to_bytes())
            .to_string()
            .as_str()
            .to_owned();
        (strkey, SoftwareSigningKey::new_from_bytes(sk.to_bytes()))
    }

    let client = Arc::new(StellarRpcClient::new(TESTNET_RPC).expect("valid URL"));
    let (funder, funder_signer) = gen_key();
    // Redact: first-5-last-5 of the G-strkey.
    eprintln!("Funder: {}", redact_strkey_first5_last5(&funder));

    match fund_with_friendbot(FRIENDBOT_URL, &funder, TESTNET_PASSPHRASE).await {
        Ok(r) => eprintln!(
            "Friendbot: tx_hash={}",
            stellar_agent_network::submit::redact_tx_hash(&r.tx_hash)
        ),
        Err(e) => {
            eprintln!("Friendbot failed: {e}");
            std::process::exit(1);
        }
    }

    // ── Derive and fund channels ─────────────────────────────────────────────
    // Generate pool master seed; derive channel public keys from it.
    let pool_master_seed: Zeroizing<[u8; 64]> = {
        let mut seed = [0u8; 64];
        use rand_core::RngCore as _;
        OsRng.fill_bytes(&mut seed);
        Zeroizing::new(seed)
    };

    // Clone seed for the wallet constructor; pool_master_seed stays alive for
    // submit_pooled.  from_bip39_seed_zeroizing so no bare [u8;64] temporary.
    let wallet = Sep5Wallet::from_bip39_seed_zeroizing(Zeroizing::new(*pool_master_seed));
    let mut channel_strkeys: Vec<String> = Vec::with_capacity(pool_size);

    for idx in 1..=(pool_size as u32) {
        let derived = wallet.derive_account(idx).expect("derivation must succeed");
        channel_strkeys.push(derived.public_key_strkey());
    }

    let funder_view = fetch_account(&*client, &funder, &[])
        .await
        .expect("funder must exist after Friendbot");

    for (funder_seq, (i, ch)) in
        (funder_view.sequence_number..).zip(channel_strkeys.iter().enumerate())
    {
        // 5 XLM per channel: 4 XLM spendable above the 1 XLM minimum reserve.
        // Funding at exactly 1 XLM leaves zero spendable balance; 5 XLM gives
        // 40_000_000 stroop headroom which covers many concurrent rounds.
        let mut builder =
            ClassicOpBuilder::new(funder.as_str(), funder_seq, TESTNET_PASSPHRASE, FEE);
        builder
            .create_account(ch, StellarAmount::from_stroops(50_000_000))
            .expect("create_account must succeed");
        let xdr = builder
            .build_and_sign(&funder_signer)
            .await
            .expect("sign must succeed");
        let r = submit_transaction_and_wait(&*client, &xdr, TIMEOUT, TESTNET_PASSPHRASE, None)
            .await
            .unwrap_or_else(|e| panic!("channel {} funding failed: {e}", i + 1));
        // Redact channel public keys (first-5-last-5).
        eprintln!(
            "Channel {}: {} (ledger {})",
            i + 1,
            redact_strkey_first5_last5(ch),
            r.ledger
        );
    }

    // ── Fetch sequences ───────────────────────────────────────────────────────
    let mut seqs: Vec<i64> = Vec::with_capacity(pool_size);
    for ch in &channel_strkeys {
        let v = fetch_account(&*client, ch, &[])
            .await
            .unwrap_or_else(|e| panic!("channel fetch failed: {e}"));
        seqs.push(v.sequence_number);
    }

    // ── Build pool ────────────────────────────────────────────────────────────
    let records: Vec<ChannelRecord> = channel_strkeys
        .iter()
        .enumerate()
        .map(|(i, k)| ChannelRecord::new((i + 1) as u32, k.as_str()))
        .collect();
    let pool = Arc::new(ChannelPool::from_records(records, seqs).expect("pool must build"));

    // ── Single-submission baseline ────────────────────────────────────────────
    let dest = funder.clone();
    let single_start = Instant::now();
    let single_result = submit_pooled(
        &pool,
        &*client,
        &pool_master_seed,
        TESTNET_PASSPHRASE,
        FEE,
        TIMEOUT,
        |builder| {
            let _ = builder.payment(&dest, StellarAmount::from_stroops(1), &Asset::Native);
        },
    )
    .await;
    let single_elapsed = single_start.elapsed();
    match &single_result {
        Ok(r) => eprintln!(
            "Baseline single submit: channel_index={}, elapsed={:.2}s",
            r.channel_index,
            single_elapsed.as_secs_f64()
        ),
        Err(e) => {
            eprintln!("Baseline single submit failed: {e}");
            std::process::exit(1);
        }
    }

    // ── Over-subscription burst ───────────────────────────────────────────────
    // Launch total_concurrency tasks simultaneously — more than pool_size.
    // Excess tasks receive PoolError::PoolExhausted immediately.
    let bench_start = Instant::now();
    let mut join_set: JoinSet<SubmitOutcome> = JoinSet::new();

    for _ in 0..total_concurrency {
        let pool_clone = Arc::clone(&pool);
        let client_clone = Arc::clone(&client);
        let seed_clone = Zeroizing::new(*pool_master_seed);
        let dest_clone = dest.clone();

        join_set.spawn(async move {
            use stellar_agent_pool::PoolError;
            match submit_pooled(
                &pool_clone,
                &client_clone,
                &seed_clone,
                TESTNET_PASSPHRASE,
                FEE,
                TIMEOUT,
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
                Ok(_) => SubmitOutcome::Success,
                Err(PoolError::PoolExhausted { .. }) => SubmitOutcome::PoolExhausted,
                Err(e) => {
                    let msg = e.to_string().to_lowercase();
                    if msg.contains("tx_bad_seq") || msg.contains("txbadseq") {
                        SubmitOutcome::TxBadSeq
                    } else {
                        SubmitOutcome::OtherFailure
                    }
                }
            }
        });
    }

    // ── Collect results ───────────────────────────────────────────────────────
    let mut successes: usize = 0;
    let mut pool_exhausted: usize = 0;
    let mut tx_bad_seq: usize = 0;
    let mut other_failures: usize = 0;

    while let Some(r) = join_set.join_next().await {
        match r.expect("task must not panic") {
            SubmitOutcome::Success => successes += 1,
            SubmitOutcome::PoolExhausted => pool_exhausted += 1,
            SubmitOutcome::TxBadSeq => tx_bad_seq += 1,
            SubmitOutcome::OtherFailure => other_failures += 1,
        }
    }

    let elapsed = bench_start.elapsed();
    let success_rate = if total_concurrency > 0 {
        successes as f64 / total_concurrency as f64 * 100.0
    } else {
        0.0
    };
    let tps = successes as f64 / elapsed.as_secs_f64();
    // Derived sustainable TPS model: pool_size / confirm_latency.
    // Confirm latency approximated from the single baseline.
    let confirm_latency_secs = single_elapsed.as_secs_f64();
    let sustainable_tps_model = pool_size as f64 / confirm_latency_secs.max(0.001);

    eprintln!();
    eprintln!("=== pool_throughput results ===");
    eprintln!("  pool_size:             {pool_size}");
    eprintln!("  total_attempts:        {total_concurrency}");
    eprintln!("  successes:             {successes}");
    eprintln!("  pool_exhausted:        {pool_exhausted}");
    eprintln!("  tx_bad_seq:            {tx_bad_seq}        (MUST be 0)");
    eprintln!("  other_failures:        {other_failures}");
    eprintln!("  success_rate:          {success_rate:.2}%");
    eprintln!("  total_elapsed:         {:.2}s", elapsed.as_secs_f64());
    eprintln!("  throughput (success):  {tps:.2} submissions/sec");
    eprintln!(
        "  sustainable_tps_model: ~{sustainable_tps_model:.1}/s \
         (pool_size={pool_size} / confirm_latency={confirm_latency_secs:.2}s)"
    );
    eprintln!("================================");

    if tx_bad_seq > 0 {
        eprintln!(
            "FAIL: {tx_bad_seq} tx_bad_seq error(s) — per-channel sequence invariant violated"
        );
        std::process::exit(1);
    }

    if other_failures > 0 {
        eprintln!("WARN: {other_failures} other submission error(s) — check logs");
        std::process::exit(1);
    }

    if total_concurrency > pool_size && pool_exhausted == 0 {
        eprintln!(
            "WARN: launched {total_concurrency} concurrent tasks against a {pool_size}-channel \
             pool but got 0 PoolExhausted — over-subscription path was not exercised"
        );
    }

    eprintln!("pool_throughput: DONE");
}

/// Classified outcome of a single `submit_pooled` attempt.
#[cfg(feature = "testnet-acceptance")]
#[derive(Debug)]
enum SubmitOutcome {
    Success,
    PoolExhausted,
    TxBadSeq,
    OtherFailure,
}
