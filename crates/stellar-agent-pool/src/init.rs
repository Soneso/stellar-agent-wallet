//! Sponsored-reserve pool initialisation — the CAP-33 sandwich builder + submit.
//!
//! `init_pool` builds a single Stellar classic transaction containing
//! N (Begin, CreateAccount, End) operation triples — one per channel — and
//! submits it to the network.  After a successful submission all N channel
//! accounts exist on-chain with the funder as their reserve sponsor.
//!
//! # CAP-33 sandwich shape
//!
//! For each channel `i` in `1..=N`, the transaction contains:
//!
//! ```text
//! op[3i-3]: BeginSponsoringFutureReserves { source=funder, sponsoredID=channel_i }
//! op[3i-2]: CreateAccount { source=funder, dest=channel_i, starting_balance=0 }
//! op[3i-1]: EndSponsoringFutureReserves { source=channel_i }
//! ```
//!
//! The full transaction is signed by:
//!
//! - The **funder** (`Profile.mcp_signer_default` keyring entry): one signature
//!   covering the transaction sequence + all Begin/Create ops.
//! - **Each channel** (`pool_master`-derived key at `m/44'/148'/i'`): one
//!   signature each covering only its own `EndSponsoringFutureReserves`.
//!
//! Triples are strictly sequential — NOT grouped — to comply with CAP-33:
//! `txBAD_SPONSORSHIP` fires if any Begin is open when a second Begin appears.
//! The invariant is `cap-0033.md`: 1:1 Begin/End within a transaction.
//!
//! # Byte-layout citations
//!
//! - CAP-33 §"Sponsoring Account Creation".
//! - `startingBalance >= 0` permitted per CAP-33.
//! - 1:1 Begin/End required: `cap-0033.md`.
//! - No nested sponsorship: `cap-0033.md`.

use std::time::Duration;

use stellar_agent_core::observability::redact_strkey_first5_last5;
use stellar_agent_network::StellarRpcClient;
use stellar_agent_network::signing::Signer;
use stellar_agent_network::{ClassicOpBuilder, SoftwareSigningKey, submit_transaction_and_wait};

use crate::config::PoolChannelRecord;
use crate::error::PoolError;
use crate::pool::ChannelPool;
use PoolChannelRecord as ChannelRecord;

/// Default submission timeout for the init transaction.
const INIT_SUBMIT_TIMEOUT: Duration = Duration::from_secs(120);

/// Parameters for `init_pool`.
///
/// All secrets are passed as `Zeroizing` wrappers so they are cleared on drop.
pub struct InitParams<'a> {
    /// Funder's G-strkey (transaction source + Begin/Create op source).
    pub funder_strkey: &'a str,
    /// Funder's current on-chain sequence number.
    pub funder_sequence: i64,
    /// Funder signing key (`Profile.mcp_signer_default` keyring entry).
    pub funder_signer: &'a dyn Signer,
    /// Per-channel signing keys, one per channel in derivation-index order.
    ///
    /// Each key is used to sign the channel's `EndSponsoringFutureReserves` op.
    pub channel_signers: Vec<SoftwareSigningKey>,
    /// Per-channel G-strkeys, in derivation-index order.
    ///
    /// Derived from the pool master at `m/44'/148'/<index>'` before calling.
    pub channel_strkeys: Vec<String>,
    /// BIP-44 derivation indices for the channels, in order.
    ///
    /// Pool channels use indices `1..=N`.
    pub channel_indices: Vec<u32>,
    /// Stellar network passphrase.
    pub network_passphrase: &'a str,
    /// Base fee in stroops per operation (total = fee × op_count).
    pub fee_per_op: u32,
}

/// The result of a successful `init_pool` call.
pub struct InitResult {
    /// The `G...` strkeys of the newly-created channel accounts.
    pub channel_records: Vec<ChannelRecord>,
    /// The transaction hash of the confirmed sandwich transaction.
    pub tx_hash: String,
    /// The ledger sequence at which the transaction was confirmed.
    pub ledger: u32,
}

/// Builds and submits the CAP-33 sponsored-reserve sandwich transaction.
///
/// Creates N channel accounts on-chain with the funder as their reserve
/// sponsor.  The transaction is multi-signed by the funder and each channel.
///
/// # Errors
///
/// Returns [`PoolError::SizeOutOfRange`] if the number of channels is `0` or
/// `> ChannelPool::MAX_SIZE` (currently 19 — bounded by the 20-signature `VecM`
/// cap).
///
/// Returns [`PoolError::InitFailed`] if the transaction is rejected or times
/// out.
///
/// # Panics
///
/// Never panics.
pub async fn init_pool(
    client: &StellarRpcClient,
    params: InitParams<'_>,
) -> Result<InitResult, PoolError> {
    let n = params.channel_strkeys.len();
    if n == 0 || n > ChannelPool::MAX_SIZE {
        return Err(PoolError::SizeOutOfRange { requested: n });
    }
    if params.channel_signers.len() != n || params.channel_indices.len() != n {
        return Err(PoolError::InitFailed {
            detail: format!(
                "channel_signers.len() ({}) or channel_indices.len() ({}) \
                 does not match channel_strkeys.len() ({})",
                params.channel_signers.len(),
                params.channel_indices.len(),
                n,
            ),
        });
    }

    // Each channel contributes 3 operations.
    // Total fee = fee_per_op × (N × 3).
    let op_count = n as u32 * 3;
    let total_fee = params.fee_per_op.saturating_mul(op_count);

    let mut builder = ClassicOpBuilder::new(
        params.funder_strkey,
        params.funder_sequence,
        params.network_passphrase,
        total_fee,
    );

    // Build N strictly-sequential (Begin, Create, End) triples.
    //
    // CAP-33 invariant: Begin MUST be immediately followed by a matching End
    // before the next Begin.  Triples are NOT grouped (all-Begins first would
    // fail with BEGIN_SPONSORING_FUTURE_RESERVES_RECURSIVE on the second Begin).
    //
    // Byte-layout: cap-0033.md (See module-level docs).
    for channel_strkey in params.channel_strkeys.iter() {
        // op[3i-3]: Begin — source=funder, sponsoredID=channel_i
        builder
            .begin_sponsoring_future_reserves(params.funder_strkey, channel_strkey)
            .map_err(|e| PoolError::InitFailed {
                detail: format!(
                    "begin_sponsoring_future_reserves({}) failed: {}",
                    redact_strkey_first5_last5(channel_strkey),
                    e
                ),
            })?;

        // op[3i-2]: CreateAccount — source=funder, dest=channel_i, balance=0
        // cap-0033.md: startingBalance >= 0 permitted when sponsored.
        builder
            .create_account_sponsored(params.funder_strkey, channel_strkey)
            .map_err(|e| PoolError::InitFailed {
                detail: format!(
                    "create_account_sponsored({}) failed: {}",
                    redact_strkey_first5_last5(channel_strkey),
                    e
                ),
            })?;

        // op[3i-1]: End — source=channel_i (the newly created account)
        builder
            .end_sponsoring_future_reserves(channel_strkey)
            .map_err(|e| PoolError::InitFailed {
                detail: format!(
                    "end_sponsoring_future_reserves({}) failed: {}",
                    redact_strkey_first5_last5(channel_strkey),
                    e
                ),
            })?;
    }

    // Build the signer list: funder first, then each channel in order.
    // The funder signs the transaction sequence + all Begin/Create ops.
    // Each channel signs only its own EndSponsoringFutureReserves op.
    // All signers produce one DecoratedSignature each; the multi-sign loop
    // appends them to the envelope in sequence.
    let mut signer_refs: Vec<&dyn Signer> = Vec::with_capacity(1 + n);
    signer_refs.push(params.funder_signer);
    for channel_signer in &params.channel_signers {
        signer_refs.push(channel_signer);
    }

    // Build and multi-sign.
    let signed_xdr = builder
        .build_and_sign_multi(&signer_refs)
        .await
        .map_err(|e| PoolError::InitFailed {
            detail: format!("sandwich build_and_sign_multi failed: {e}"),
        })?;

    // Submit and wait for confirmation.
    let submission = submit_transaction_and_wait(
        client,
        &signed_xdr,
        INIT_SUBMIT_TIMEOUT,
        params.network_passphrase,
        None,
    )
    .await
    .map_err(|e| PoolError::InitFailed {
        detail: format!("sandwich submission failed: {e}"),
    })?;

    // Build channel records (public keys + indices).
    let channel_records: Vec<ChannelRecord> = params
        .channel_strkeys
        .iter()
        .zip(params.channel_indices.iter().copied())
        .map(|(pk, idx)| ChannelRecord::new(idx, pk.clone()))
        .collect();

    Ok(InitResult {
        channel_records,
        tx_hash: submission.tx_hash,
        ledger: submission.ledger,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Sandwich structure verifier (for tests)
// ─────────────────────────────────────────────────────────────────────────────

/// Verifies that a base64 XDR envelope contains exactly `n` sequential
/// (Begin, CreateAccount, End) triples with the correct per-operation sources.
///
/// Returns `Ok(())` if the structure is valid, or an error string describing
/// the first violation.
///
/// Used by `tests/init_structure.rs` to assert the sandwich structure
/// pre-submit (without a live network).
///
/// # Errors
///
/// Returns `Err(String)` with a description of the first structural violation
/// found (wrong op count, wrong op kind, wrong source account, or wrong
/// destination / starting balance on `CreateAccount` ops).
///
/// # Feature gate
///
/// Available only under `#[cfg(any(test, feature = "test-helpers"))]`.
#[cfg(any(test, feature = "test-helpers"))]
pub fn assert_sandwich_structure(
    envelope_xdr_b64: &str,
    funder_strkey: &str,
    channel_strkeys: &[String],
) -> Result<(), String> {
    use stellar_xdr::{
        Limits, MuxedAccount, OperationBody, PublicKey, ReadXdr, TransactionEnvelope,
    };

    let envelope = TransactionEnvelope::from_xdr_base64(envelope_xdr_b64, Limits::none())
        .map_err(|e| format!("failed to decode envelope: {e}"))?;

    let ops = match &envelope {
        TransactionEnvelope::Tx(v1) => v1.tx.operations.to_vec(),
        other => {
            return Err(format!(
                "expected Tx envelope, got {:?}",
                other.discriminant()
            ));
        }
    };

    let n = channel_strkeys.len();
    let expected_op_count = n * 3;
    if ops.len() != expected_op_count {
        return Err(format!(
            "expected {} ops ({}×3), got {}",
            expected_op_count,
            n,
            ops.len()
        ));
    }

    // Helper: extract G-strkey from a MuxedAccount source.
    let source_strkey = |muxed: &Option<MuxedAccount>| -> Option<String> {
        match muxed {
            Some(MuxedAccount::Ed25519(k)) => Some(
                stellar_strkey::ed25519::PublicKey(k.0)
                    .to_string()
                    .as_str()
                    .to_owned(),
            ),
            _ => None,
        }
    };

    // Helper: extract G-strkey from a PublicKey.
    let pk_strkey = |pk: &PublicKey| -> String {
        match pk {
            PublicKey::PublicKeyTypeEd25519(k) => stellar_strkey::ed25519::PublicKey(k.0)
                .to_string()
                .as_str()
                .to_owned(),
        }
    };

    for (i, channel_strkey) in channel_strkeys.iter().enumerate() {
        let base = i * 3;

        // op[base+0]: BeginSponsoringFutureReserves
        // source=funder, sponsoredID=channel_i
        let op0 = &ops[base];
        let op0_source = source_strkey(&op0.source_account)
            .ok_or_else(|| format!("op[{}] (Begin): missing source", base))?;
        if op0_source != funder_strkey {
            return Err(format!(
                "op[{}] (Begin): expected source={}, got {}",
                base, funder_strkey, op0_source
            ));
        }
        match &op0.body {
            OperationBody::BeginSponsoringFutureReserves(b) => {
                let sponsored = pk_strkey(&b.sponsored_id.0);
                if &sponsored != channel_strkey {
                    return Err(format!(
                        "op[{}] (Begin): expected sponsoredID={}, got {}",
                        base, channel_strkey, sponsored
                    ));
                }
            }
            other => {
                return Err(format!(
                    "op[{}]: expected BeginSponsoringFutureReserves, got {:?}",
                    base,
                    other.discriminant()
                ));
            }
        }

        // op[base+1]: CreateAccount
        // source=funder, destination=channel_i, starting_balance=0
        let op1 = &ops[base + 1];
        let op1_source = source_strkey(&op1.source_account)
            .ok_or_else(|| format!("op[{}] (Create): missing source", base + 1))?;
        if op1_source != funder_strkey {
            return Err(format!(
                "op[{}] (Create): expected source={}, got {}",
                base + 1,
                funder_strkey,
                op1_source
            ));
        }
        match &op1.body {
            OperationBody::CreateAccount(ca) => {
                let dest = pk_strkey(&ca.destination.0);
                if &dest != channel_strkey {
                    return Err(format!(
                        "op[{}] (Create): expected destination={}, got {}",
                        base + 1,
                        channel_strkey,
                        dest
                    ));
                }
                if ca.starting_balance != 0 {
                    return Err(format!(
                        "op[{}] (Create): expected starting_balance=0, got {}",
                        base + 1,
                        ca.starting_balance
                    ));
                }
            }
            other => {
                return Err(format!(
                    "op[{}]: expected CreateAccount, got {:?}",
                    base + 1,
                    other.discriminant()
                ));
            }
        }

        // op[base+2]: EndSponsoringFutureReserves
        // source=channel_i
        let op2 = &ops[base + 2];
        let op2_source = source_strkey(&op2.source_account)
            .ok_or_else(|| format!("op[{}] (End): missing source", base + 2))?;
        if &op2_source != channel_strkey {
            return Err(format!(
                "op[{}] (End): expected source={}, got {}",
                base + 2,
                channel_strkey,
                op2_source
            ));
        }
        match &op2.body {
            OperationBody::EndSponsoringFutureReserves => {}
            other => {
                return Err(format!(
                    "op[{}]: expected EndSponsoringFutureReserves, got {:?}",
                    base + 2,
                    other.discriminant()
                ));
            }
        }
    }

    Ok(())
}
