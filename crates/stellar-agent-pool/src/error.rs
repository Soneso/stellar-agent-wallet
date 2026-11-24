//! Pool error type.
//!
//! All public-facing errors from the channel-account pool are expressed as
//! [`PoolError`] variants.  Internal operations use [`stellar_agent_core::WalletError`]
//! and map into `PoolError` at the pool boundary.

use thiserror::Error;

/// Errors produced by the channel-account pool.
///
/// `#[non_exhaustive]` because new error cases may be added as the pool API
/// evolves.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PoolError {
    /// All pool channels are currently in-flight; no free channel is available.
    ///
    /// Returned IMMEDIATELY at capacity — the pool NEVER queues beyond its
    /// size.  The caller should retry after releasing a lease or reduce
    /// concurrent submission throughput.
    ///
    /// Wire code: `resource.pool_exhausted`.
    #[error("resource.pool_exhausted: all {pool_size} pool channels are in-flight")]
    PoolExhausted {
        /// Total number of channels in the pool (for diagnostic context).
        pool_size: usize,
    },

    /// Pool initialisation failed — the sponsored-reserve sandwich transaction
    /// was rejected by the network or timed out.
    ///
    /// The `detail` field contains a redacted error description (no keys,
    /// no raw RPC URL).
    #[error("pool.init_failed: {detail}")]
    InitFailed {
        /// Redacted detail string (no key material).
        detail: String,
    },

    /// Fetching the on-chain sequence number for a channel failed.
    ///
    /// Occurs during pool refresh or `tx_bad_seq` reconciliation.
    #[error("pool.sequence_fetch_failed: channel[{channel_index}] {channel_redacted}: {reason}")]
    SequenceFetchFailed {
        /// BIP-44 derivation index of the channel whose fetch failed.
        ///
        /// Carried for diagnostics so the operator can identify which channel
        /// needs attention without decoding the redacted strkey.
        channel_index: u32,
        /// Redacted channel G-strkey (first-5-last-5).
        channel_redacted: String,
        /// Redacted reason string.
        reason: String,
    },

    /// The requested pool size is out of range.
    ///
    /// Valid range: `1..=19`.  The upper bound is the 20-signature `VecM` cap
    /// on the sandwich envelope: N+1 signatures (funder + each channel) must fit
    /// within 20, so N ≤ 19.
    ///
    /// Wire code: `pool.size_out_of_range`.
    #[error(
        "pool.size_out_of_range: pool size (--size) must be an integer from 1 through 19 so all \
         transaction signatures fit"
    )]
    SizeOutOfRange,

    /// The per-operation fee times the sandwich's operation count does not
    /// fit the transaction's `u32` fee field.
    ///
    /// Returned by `init_pool` before anything is built, signed, or sent.
    #[error(
        "pool.fee_overflow: classic_fee_per_op_stroops multiplied by the operation count must \
         fit in u32; lower classic_fee_per_op_stroops."
    )]
    FeeOverflow {
        /// Operations in the sandwich transaction.
        op_count: u32,
    },

    /// Pool has not been initialised.
    ///
    /// Returned when acquire is called on a pool that has not been funded via
    /// `pool init`.
    #[error("pool.not_initialised: run `pool init --size N` first")]
    NotInitialised,

    /// Pool is already initialised for this profile.
    ///
    /// `pool init` refuses to overwrite an existing pool master because doing
    /// so would orphan all previously funded channel accounts.  To re-initialise,
    /// pass `--force` explicitly.
    ///
    /// Wire code: `pool.already_initialised`.
    #[error(
        "pool.already_initialised: a pool master key already exists for this profile; \
         use --force to overwrite (this orphans existing funded channels)"
    )]
    AlreadyInitialised,

    /// The channel index is outside the hardened derivation range.
    ///
    /// The variant keeps neither the refused index nor the derivation error
    /// that holds it.
    #[error("pool.derive_failed: channel index must be less than 2147483648")]
    DeriveFailed,

    /// An underlying wallet error propagated from network / signing / core.
    #[error("pool.wallet_error: {0}")]
    Wallet(#[from] stellar_agent_core::WalletError),
}
