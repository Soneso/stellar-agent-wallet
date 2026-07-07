//! Pool testnet acceptance test (feature `testnet-acceptance`).
//!
//! Against testnet, funds a funder via Friendbot, calls `pool init --size 4`
//! (one sponsored sandwich), and asserts all 4 channels exist on-chain via
//! `fetch_account`.
//!
//! # Feature gate
//!
//! Gated behind `--features testnet-acceptance`.  Run with:
//!
//! ```sh
//! cargo test -p stellar-agent-pool --features testnet-acceptance \
//!     --test pool_testnet_init
//! ```
//!
//! # Skip policy
//!
//! - `"skipped: testnet RPC unreachable"` — RPC HEAD probe failed.
//! - `"skipped: Friendbot funding failed"` — Friendbot unreachable or rejected.
//!
//! No balance or funding-threshold checks; existence/reachability only.
//!
//! # No committed secrets
//!
//! The funder and channel keypairs are generated ephemerally at test time via
//! `ed25519-dalek` + `OsRng`.  No `S...` strkey is committed in this file.
//! Channel keys are derived from a fresh in-memory pool master seed.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    reason = "test-only; panics, unwraps, and eprintln are acceptable in acceptance tests"
)]

#[cfg(feature = "testnet-acceptance")]
mod live {
    use ed25519_dalek::SigningKey as DalekSigningKey;
    use rand_core::OsRng;
    use secrecy::ExposeSecret;
    use stellar_agent_core::observability::redact_strkey_first5_last5;
    use stellar_agent_network::{
        SoftwareSigningKey, StellarRpcClient, fetch_account, fund_with_friendbot,
    };
    use stellar_agent_pool::init::{InitParams, init_pool};
    use stellar_strkey::ed25519::PublicKey as StrPublicKey;
    use zeroize::Zeroizing;

    use stellar_agent_sep5::Sep5Wallet;

    const TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";
    const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";
    const TESTNET_FRIENDBOT_URL: &str = "https://friendbot.stellar.org";

    /// Number of channels to initialise for this acceptance test.
    ///
    /// Small N for CI throughput: 4 channels = 12 ops per sandwich.
    const POOL_SIZE: usize = 4;

    /// Generate an ephemeral ed25519 keypair and return (strkey, SoftwareSigningKey).
    ///
    /// No `S...` seed is committed — the key is generated fresh each test run.
    fn gen_ephemeral_key() -> (String, SoftwareSigningKey) {
        let signing_key = DalekSigningKey::generate(&mut OsRng);
        let pk_bytes: [u8; 32] = signing_key.verifying_key().to_bytes();
        let strkey = StrPublicKey(pk_bytes).to_string().as_str().to_owned();
        let secret_bytes: [u8; 32] = signing_key.to_bytes();
        let key = SoftwareSigningKey::new_from_bytes(secret_bytes);
        (strkey, key)
    }

    /// Generate an ephemeral 64-byte BIP-39 seed (random, not a real mnemonic).
    ///
    /// Used as the pool master seed.  No committed seed — derived fresh each run.
    fn gen_ephemeral_seed() -> Zeroizing<[u8; 64]> {
        let mut seed = [0u8; 64];
        use rand_core::RngCore;
        OsRng.fill_bytes(&mut seed);
        Zeroizing::new(seed)
    }

    /// Pool init --size 4 creates 4 funded channels on testnet.
    ///
    /// Steps:
    /// 1. Generate ephemeral funder keypair.
    /// 2. Fund funder via Friendbot.
    /// 3. Derive 4 channel keypairs from an ephemeral pool master seed.
    /// 4. Fetch funder sequence number.
    /// 5. Build + submit the CAP-33 sandwich.
    /// 6. Assert all 4 channels exist on-chain (fetch_account).
    #[tokio::test(flavor = "multi_thread")]
    async fn pool_init_size_4_creates_channels_on_testnet() {
        // ── RPC reachability probe ────────────────────────────────────────────
        let client = StellarRpcClient::new(TESTNET_RPC_URL).expect("testnet RPC URL must be valid");

        // Simple HEAD probe using reqwest directly.
        let reachable = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .ok()
            .and_then(|c| {
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current()
                        .block_on(c.head(TESTNET_RPC_URL).send())
                        .ok()
                })
            })
            .is_some();

        if !reachable {
            eprintln!(
                "ACCEPTANCE TEST SKIPPED: testnet RPC unreachable ({})",
                TESTNET_RPC_URL
            );
            return;
        }

        // ── Generate funder keypair + fund via Friendbot ─────────────────────
        let (funder_strkey, funder_signer) = gen_ephemeral_key();
        eprintln!("Funder: {}", redact_strkey_first5_last5(&funder_strkey));

        let friendbot_result =
            fund_with_friendbot(TESTNET_FRIENDBOT_URL, &funder_strkey, TESTNET_PASSPHRASE).await;

        match friendbot_result {
            Ok(r) => {
                eprintln!("Friendbot funded funder; tx_hash={}", r.tx_hash);
            }
            Err(e) => {
                eprintln!("ACCEPTANCE TEST SKIPPED: Friendbot funding failed: {}", e);
                return;
            }
        }

        // ── Fetch funder sequence ─────────────────────────────────────────────
        let funder_view = fetch_account(&client, &funder_strkey, &[])
            .await
            .expect("funder account must exist after Friendbot funding");
        let funder_sequence = funder_view.sequence_number;
        eprintln!("Funder sequence: {funder_sequence}");

        // ── Derive channel keypairs from ephemeral pool master seed ───────────
        let pool_master_seed = gen_ephemeral_seed();
        // Clone for the wallet; pool_master_seed may be needed afterwards.
        // Use from_bip39_seed_zeroizing to avoid a bare [u8;64] stack temp.
        let wallet = Sep5Wallet::from_bip39_seed_zeroizing(Zeroizing::new(*pool_master_seed));

        // Channel indices: 1..=POOL_SIZE (index 0 reserved for primary wallet account).
        let mut channel_strkeys: Vec<String> = Vec::with_capacity(POOL_SIZE);
        let mut channel_signers: Vec<SoftwareSigningKey> = Vec::with_capacity(POOL_SIZE);
        let mut channel_indices: Vec<u32> = Vec::with_capacity(POOL_SIZE);

        for idx in 1..=(POOL_SIZE as u32) {
            let derived = wallet
                .derive_account(idx)
                .expect("derivation must succeed for valid index");
            let strkey = derived.public_key_strkey();
            // Re-derive signer from the raw seed (SecretBox → Zeroizing → SoftwareSigningKey).
            let raw_seed: Zeroizing<[u8; 32]> =
                Zeroizing::new(*derived.secret_seed().expose_secret());
            let signer = SoftwareSigningKey::new_from_zeroizing(raw_seed);

            eprintln!("Channel {idx}: {}", redact_strkey_first5_last5(&strkey));
            channel_strkeys.push(strkey);
            channel_signers.push(signer);
            channel_indices.push(idx);
        }

        // ── Build + submit the sponsored sandwich ─────────────────────────────
        let params = InitParams {
            funder_strkey: &funder_strkey,
            funder_sequence,
            funder_signer: &funder_signer,
            channel_signers,
            channel_strkeys: channel_strkeys.clone(),
            channel_indices,
            network_passphrase: TESTNET_PASSPHRASE,
            fee_per_op: 1000, // generous fee for testnet
        };

        let result = init_pool(&client, params).await;

        match result {
            Ok(r) => {
                eprintln!(
                    "Pool init succeeded: {} channels, tx={}, ledger={}",
                    r.channel_records.len(),
                    r.tx_hash,
                    r.ledger
                );
            }
            Err(e) => {
                panic!("pool init failed: {e}");
            }
        }

        // ── Assert all channels exist on-chain ────────────────────────────────
        // Verify channel existence, not balance thresholds.
        for channel_strkey in &channel_strkeys {
            let view = fetch_account(&client, channel_strkey, &[])
                .await
                .unwrap_or_else(|e| {
                    panic!(
                        "channel {} not found on-chain: {}",
                        redact_strkey_first5_last5(channel_strkey),
                        e
                    )
                });
            assert_eq!(
                &view.account_id, channel_strkey,
                "channel account_id must match"
            );
            eprintln!(
                "Channel {} exists on-chain (seq={})",
                redact_strkey_first5_last5(channel_strkey),
                view.sequence_number
            );
        }

        eprintln!("POOL INIT PASSED: {POOL_SIZE} channel accounts on-chain.");
    }
}
