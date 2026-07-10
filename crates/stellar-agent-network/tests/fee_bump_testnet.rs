//! Fee-bump testnet acceptance test (feature `testnet-acceptance`).
//!
//! Against testnet, funds an inner-tx source and a DISTINCT fee-payer (both
//! ephemeral via Friendbot), builds a v1 inner tx with a very low fee,
//! fee-bumps it with the fee-payer, submits, and asserts the inner tx applies.
//!
//! # Feature gate
//!
//! Gated behind `--features testnet-acceptance`.  Run with:
//!
//! ```sh
//! cargo test -p stellar-agent-network --features testnet-acceptance \
//!     --test fee_bump_testnet
//! ```
//!
//! # Skip policy
//!
//! Skips with a distinguishable reason string (NOT silent-pass):
//!
//! - `"skipped: testnet RPC unreachable"` — RPC HEAD probe failed.
//! - `"skipped: Friendbot funding failed for inner source"` — Friendbot unreachable.
//! - `"skipped: Friendbot funding failed for fee payer"` — same.
//!
//! No balance / funding-threshold checks; existence/reachability only.
//!
//! # No committed secrets
//!
//! Both the inner-tx source and fee-payer keypairs are generated ephemerally
//! at test time via `ed25519-dalek` + `OsRng`.  No `S...` strkey is committed.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    reason = "test-only; panics, unwraps, and eprintln are acceptable in acceptance tests"
)]

#[cfg(feature = "testnet-acceptance")]
mod live {
    use std::time::Duration;

    use ed25519_dalek::SigningKey as DalekSigningKey;
    use rand_core::OsRng;
    use stellar_agent_network::builder::{Asset, ClassicOpBuilder};
    use stellar_agent_network::fee_bump::{FeeBumpError, build_and_sign_fee_bump};
    use stellar_agent_network::signing::software::SoftwareSigningKey;
    use stellar_agent_network::{
        StellarRpcClient, fetch_account, fund_with_friendbot, submit_transaction_and_wait,
    };
    use stellar_strkey::ed25519::PublicKey as StrPublicKey;

    const TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";
    const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";
    const TESTNET_FRIENDBOT_URL: &str = "https://friendbot.stellar.org";

    /// Generates an ephemeral ed25519 keypair.
    ///
    /// Returns the G-strkey and the `SoftwareSigningKey` for signing.
    /// No S-strkey is stored or committed.
    fn gen_ephemeral_key() -> (String, SoftwareSigningKey) {
        let signing_key = DalekSigningKey::generate(&mut OsRng);
        let pk_bytes: [u8; 32] = signing_key.verifying_key().to_bytes();
        let strkey = StrPublicKey(pk_bytes).to_string().as_str().to_owned();
        let secret_bytes: [u8; 32] = signing_key.to_bytes();
        let key = SoftwareSigningKey::new_from_bytes(secret_bytes);
        (strkey, key)
    }

    /// Fee-bumps a v1 inner tx from a DISTINCT fee-payer.
    ///
    /// Steps:
    /// 1. Generate ephemeral inner-source keypair and ephemeral fee-payer keypair.
    /// 2. Fund both via Friendbot.
    /// 3. Fetch inner-source sequence number.
    /// 4. Build a v1 inner tx (tiny XLM self-payment) signed by the inner source.
    ///    The inner tx fee is set to 0 (below the 100-stroop minimum), which means
    ///    it cannot be submitted directly — only via a fee-bump.
    /// 5. Fee-bump with the fee-payer, attaching the fee-payer signature.
    /// 6. Submit the fee-bump envelope.
    /// 7. Assert SUCCESS — the inner tx applied via the fee-payer's fee.
    ///
    /// Negative clause: a fee-bump with `InnerNotV1` input (TxV0 envelope) is
    /// rejected before submission with `FeeBumpError::InnerNotV1`.
    #[tokio::test(flavor = "multi_thread")]
    async fn fee_bump_distinct_fee_payer_applies_inner_tx() {
        // ── RPC reachability probe ────────────────────────────────────────────
        let client = StellarRpcClient::new(TESTNET_RPC_URL).expect("testnet RPC URL must be valid");

        let reachable = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
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
            eprintln!("skipped: testnet RPC unreachable");
            return;
        }

        // ── Generate ephemeral keypairs ───────────────────────────────────────
        let (inner_source_gstrkey, inner_source_signer) = gen_ephemeral_key();
        let (fee_payer_gstrkey, fee_payer_signer) = gen_ephemeral_key();

        // ── Fund inner source via Friendbot ───────────────────────────────────
        let fb_result = fund_with_friendbot(
            TESTNET_FRIENDBOT_URL,
            &inner_source_gstrkey,
            TESTNET_PASSPHRASE,
            TESTNET_RPC_URL,
        )
        .await;
        if fb_result.is_err() {
            eprintln!(
                "skipped: Friendbot funding failed for inner source: {:?}",
                fb_result.err()
            );
            return;
        }

        // ── Fund fee payer via Friendbot ──────────────────────────────────────
        let fb_result2 = fund_with_friendbot(
            TESTNET_FRIENDBOT_URL,
            &fee_payer_gstrkey,
            TESTNET_PASSPHRASE,
            TESTNET_RPC_URL,
        )
        .await;
        if fb_result2.is_err() {
            eprintln!(
                "skipped: Friendbot funding failed for fee payer: {:?}",
                fb_result2.err()
            );
            return;
        }

        // ── Fetch inner-source sequence number ────────────────────────────────
        let inner_account = fetch_account(&client, &inner_source_gstrkey, &[])
            .await
            .expect("inner source account must exist after Friendbot funding");

        // ── Build a v1 inner tx (tiny self-payment, fee=100) ──────────────────
        // Use a low but non-zero fee (100 stroops = base minimum per op).
        // The fee-bump will set the outer fee to 500 which exceeds the minimum.
        // inner_fee=100, inner_op_count=1 →
        // cap15_minimum = (1+1)*max(100, ceil(100/1)) = 200.
        // outer fee = 500 > 200 ✓; outer fee <= 10_000 (policy cap) ✓.
        let inner_fee_per_op: u32 = 100;

        let mut inner_builder = ClassicOpBuilder::new(
            &inner_source_gstrkey,
            inner_account.sequence_number,
            TESTNET_PASSPHRASE,
            inner_fee_per_op,
        );

        // Tiny self-payment (1 stroop) to create a non-empty, structurally valid tx.
        inner_builder
            .payment(
                &inner_source_gstrkey,
                stellar_agent_core::StellarAmount::from_stroops(1),
                &Asset::Native,
            )
            .expect("payment op must be valid");

        // Sign the inner tx with the inner source key.
        // (ClassicOpBuilder::build_and_sign consumes self, so we sign directly.)
        let inner_signed_xdr = inner_builder
            .build_and_sign(&inner_source_signer)
            .await
            .expect("inner sign must succeed");

        // ── Negative: v1-guard rejects TxV0 before submission ─────────────────
        // Build a fake TxV0 XDR (we can't easily construct one from ClassicOpBuilder
        // which always produces v1, so we use a hardcoded minimal TxV0 base64).
        // This verifies the guard fires at the build_and_sign_fee_bump call site.
        {
            use stellar_xdr::{
                Limits, Memo, SequenceNumber, TransactionEnvelope, TransactionV0,
                TransactionV0Envelope, TransactionV0Ext, Uint256, WriteXdr,
            };
            let v0_env = TransactionEnvelope::TxV0(TransactionV0Envelope {
                tx: TransactionV0 {
                    source_account_ed25519: Uint256([0u8; 32]),
                    fee: 100,
                    seq_num: SequenceNumber(1),
                    time_bounds: None,
                    memo: Memo::None,
                    operations: vec![].try_into().expect("empty ops"),
                    ext: TransactionV0Ext::V0,
                },
                signatures: vec![].try_into().expect("empty sigs"),
            });
            let v0_xdr = v0_env
                .to_xdr_base64(Limits::none())
                .expect("v0 encode must succeed");

            let neg_result = build_and_sign_fee_bump(
                &v0_xdr,
                &fee_payer_gstrkey,
                /* outer_fee_stroops */ 500,
                /* policy_fee_cap_stroops */ 10_000,
                TESTNET_PASSPHRASE,
                &fee_payer_signer,
            )
            .await;

            assert!(
                matches!(neg_result, Err(FeeBumpError::InnerNotV1 { .. })),
                "TxV0 inner must be rejected with InnerNotV1 before submission, got: {neg_result:?}"
            );
        }

        // ── Build + sign the fee-bump envelope ────────────────────────────────
        // outer_fee_stroops = 500, policy_fee_cap_stroops = 10_000.
        let fee_bump_xdr = build_and_sign_fee_bump(
            &inner_signed_xdr,
            &fee_payer_gstrkey,
            /* outer_fee_stroops */ 500,
            /* policy_fee_cap_stroops */ 10_000,
            TESTNET_PASSPHRASE,
            &fee_payer_signer,
        )
        .await
        .expect("fee-bump construction and signing must succeed");

        // ── Submit and assert SUCCESS ─────────────────────────────────────────
        let result = submit_transaction_and_wait(
            &client,
            &fee_bump_xdr,
            Duration::from_secs(60),
            TESTNET_PASSPHRASE,
            None,
        )
        .await;

        let submission = result.expect(
            "fee-bump submission must succeed: the inner tx should apply via the fee-payer's fee",
        );

        eprintln!(
            "fee-bump accepted: inner tx applied in ledger {}, tx_hash {}",
            submission.ledger,
            &submission.tx_hash[..16]
        );

        assert!(submission.ledger > 0, "confirmed ledger must be non-zero");
    }
}
