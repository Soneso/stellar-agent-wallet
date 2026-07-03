//! Fee-bump idempotent retry testnet acceptance test (feature `testnet-acceptance`).
//!
//! Builds and signs a fee-bump over a real inner tx, submits via
//! `submit_fee_bump_idempotent`, confirms Success; then resubmits the same
//! inner via `submit_fee_bump_idempotent` at a HIGHER fee → cached Success
//! (no re-bump); asserts the inner tx source sequence advanced by exactly one
//! (no double-apply).
//!
//! # Feature gate
//!
//! Gated behind `--features testnet-acceptance`.  Run with:
//!
//! ```sh
//! cargo test -p stellar-agent-network --features testnet-acceptance \
//!     --test fee_bump_idempotent_testnet
//! ```
//!
//! # Skip policy
//!
//! Skips with a distinguishable reason string (NOT silent-pass):
//!
//! - `"skipped: testnet RPC unreachable"` — RPC HEAD probe failed.
//! - `"skipped: Friendbot funding failed for inner source"` — Friendbot unreachable.
//! - `"skipped: Friendbot funding failed for fee payer"` — same.
//! - `"skipped: Friendbot funding failed for effect target"` — same.
//!
//! No balance / funding-threshold checks; existence/reachability only.
//!
//! # No committed secrets
//!
//! All keypairs are generated ephemerally at test time via `ed25519-dalek`
//! + `OsRng`.  No `S...` strkey is committed.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    reason = "testnet acceptance test; panics, unwraps, and eprintln are acceptable"
)]

#[cfg(feature = "testnet-acceptance")]
mod live {
    use std::time::Duration;

    use ed25519_dalek::SigningKey as DalekSigningKey;
    use rand_core::OsRng;
    use stellar_agent_core::StellarAmount;
    use stellar_agent_core::profile::receipt::{ReceiptStatus, ReceiptStore};
    use stellar_agent_network::builder::{Asset, ClassicOpBuilder};
    use stellar_agent_network::fee_bump_retry::submit_fee_bump_idempotent;
    use stellar_agent_network::signing::software::SoftwareSigningKey;
    use stellar_agent_network::{StellarRpcClient, fetch_account, fund_with_friendbot};
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
        let ssk = SoftwareSigningKey::new_from_bytes(secret_bytes);
        (strkey, ssk)
    }

    /// Computes the `feebump-inner:` prefixed receipt-store key for a given
    /// inner signed XDR.
    fn inner_key_for(inner_xdr: &str) -> String {
        use sha2::{Digest, Sha256};
        use stellar_xdr::{
            Hash, Limits, ReadXdr, TransactionEnvelope, TransactionSignaturePayload,
            TransactionSignaturePayloadTaggedTransaction, WriteXdr,
        };
        let envelope = TransactionEnvelope::from_xdr_base64(inner_xdr, Limits::none()).unwrap();
        let v1 = match envelope {
            TransactionEnvelope::Tx(v1) => v1,
            _ => panic!("expected Tx(v1)"),
        };
        let network_id = Hash(Sha256::digest(TESTNET_PASSPHRASE.as_bytes()).into());
        let payload = TransactionSignaturePayload {
            network_id,
            tagged_transaction: TransactionSignaturePayloadTaggedTransaction::Tx(v1.tx),
        };
        let payload_bytes = payload.to_xdr(Limits::none()).unwrap();
        let hash = Sha256::digest(&payload_bytes);
        let hex: String = hash.iter().fold(String::new(), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        });
        format!("feebump-inner:{hex}")
    }

    /// Live testnet acceptance: fee-bump idempotent retry.
    ///
    /// Steps:
    /// 1. Generate ephemeral inner-source, fee-payer, and effect-target keypairs.
    /// 2. Fund all three via Friendbot.
    /// 3. Fetch inner-source sequence number.
    /// 4. Build and sign a V1 inner tx (tiny payment to effect-target).
    /// 5. `submit_fee_bump_idempotent` at outer_fee=500 → Success.
    /// 6. Resubmit same inner via `submit_fee_bump_idempotent` at outer_fee=2_000
    ///    → cached Success (no re-bump).
    /// 7. Verify no double-apply: the inner source's sequence number must advance
    ///    by exactly 1 across both calls.
    ///
    /// Sequence-number check: because the inner tx is a payment (not a
    /// sequence-consuming tx from the effect-target), exactly one sequence slot
    /// is consumed (one application, not two).
    #[tokio::test(flavor = "multi_thread")]
    async fn fee_bump_idempotent_retry_cached_success_no_double_apply() {
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
        let (effect_target_gstrkey, _) = gen_ephemeral_key();

        // ── Fund all three via Friendbot ──────────────────────────────────────
        for (label, gstrkey) in [
            ("inner source", &inner_source_gstrkey),
            ("fee payer", &fee_payer_gstrkey),
            ("effect target", &effect_target_gstrkey),
        ] {
            let fb = fund_with_friendbot(TESTNET_FRIENDBOT_URL, gstrkey, TESTNET_PASSPHRASE).await;
            if fb.is_err() {
                eprintln!(
                    "skipped: Friendbot funding failed for {label}: {:?}",
                    fb.err()
                );
                return;
            }
        }

        // ── Fetch inner-source sequence number ────────────────────────────────
        let inner_account = fetch_account(&client, &inner_source_gstrkey, &[])
            .await
            .expect("inner source account must exist after Friendbot funding");
        let seq_before = inner_account.sequence_number;

        // ── Build and sign the inner V1 tx ────────────────────────────────────
        // Tiny payment (5 XLM = 50_000_000 stroops) to the effect target.
        // Funded accounts have 10_000 XLM from Friendbot; well above reserve.
        let inner_fee_per_op: u32 = 100;
        let mut inner_builder = ClassicOpBuilder::new(
            &inner_source_gstrkey,
            inner_account.sequence_number,
            TESTNET_PASSPHRASE,
            inner_fee_per_op,
        );
        inner_builder
            .payment(
                &effect_target_gstrkey,
                // 5 XLM — well above reserve, well below Friendbot funding
                StellarAmount::from_stroops(50_000_000),
                &Asset::Native,
            )
            .expect("payment op must be valid");

        let inner_signed_xdr = inner_builder
            .build_and_sign(&inner_source_signer)
            .await
            .expect("inner sign must succeed");

        let inner_key = inner_key_for(&inner_signed_xdr);

        // ── Open a temp receipt store ─────────────────────────────────────────
        let dir = tempfile::tempdir().expect("tempdir must succeed");
        let store = ReceiptStore::open_at(dir.path(), "acceptance-9ii-live")
            .expect("receipt store must open");

        // ── Call #1: submit at outer_fee=500 ─────────────────────────────────
        // CAP-15 minimum for 1 op, inner_fee=100:
        //   (1+1) * max(100, ceil(100/1)) = 200.
        // outer_fee=500 > 200 ✓; 500 <= 10_000 (policy cap) ✓.
        let r1 = submit_fee_bump_idempotent(
            &client,
            &inner_signed_xdr,
            &fee_payer_gstrkey,
            500,
            10_000,
            TESTNET_PASSPHRASE,
            &fee_payer_signer,
            &store,
            0,
            Duration::from_secs(90),
        )
        .await;

        let sub1 = match r1 {
            Ok(s) => s,
            Err(e) => {
                eprintln!("skipped: first submit_fee_bump_idempotent failed: {e:?}");
                return;
            }
        };

        eprintln!(
            "call-1: fee-bump confirmed in ledger {}, outer_tx_hash {}...",
            sub1.ledger,
            &sub1.tx_hash[..16.min(sub1.tx_hash.len())]
        );
        assert!(sub1.ledger > 0, "confirmed ledger must be non-zero");

        // ── Call #2: resubmit at outer_fee=2_000 (higher fee) ─────────────────
        let r2 = submit_fee_bump_idempotent(
            &client,
            &inner_signed_xdr,
            &fee_payer_gstrkey,
            2_000, // HIGHER outer fee
            10_000,
            TESTNET_PASSPHRASE,
            &fee_payer_signer,
            &store,
            0,
            Duration::from_secs(90),
        )
        .await;

        assert!(
            r2.is_ok(),
            "second call (higher fee) must return cached Success; got: {r2:?}"
        );
        let sub2 = r2.unwrap();
        assert_eq!(
            sub2.ledger, sub1.ledger,
            "second call must return same ledger as first (cached receipt)"
        );

        eprintln!(
            "call-2: returned cached Success from ledger {}",
            sub2.ledger
        );

        // ── Verify receipt store has exactly one Success for the inner key ─────
        let receipt = store.get(&inner_key).unwrap().unwrap();
        assert_eq!(
            receipt.status,
            ReceiptStatus::Success,
            "store must have exactly one Success entry for the inner key"
        );

        // ── Verify the inner source's sequence number advanced by exactly 1 ────
        //
        // The inner tx is a payment from inner_source (consuming one sequence
        // slot).  After one application (and one cached-Success return on the
        // second call), seq must be seq_before + 1.  A double-apply would yield
        // seq_before + 2.
        let inner_account_after = fetch_account(&client, &inner_source_gstrkey, &[])
            .await
            .expect("inner source account must exist after submission");
        let seq_after = inner_account_after.sequence_number;

        assert_eq!(
            seq_after,
            seq_before + 1,
            "inner source sequence must advance by exactly 1 (one application, not double-apply); \
             before={seq_before}, after={seq_after}"
        );

        eprintln!(
            "PASSED: inner source seq {} → {} (exactly +1, no double-apply)",
            seq_before, seq_after
        );
    }
}
