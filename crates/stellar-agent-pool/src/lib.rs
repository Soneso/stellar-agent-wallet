//! Channel-account pool for the Stellar agent wallet.
//!
//! ## What this crate does
//!
//! Provides a set of pre-funded Stellar accounts (`channels`) whose sequence
//! numbers are managed in-pool to allow concurrent transaction submission
//! without `tx_bad_seq` errors.  The pool is SEP-5-derived
//! (`m/44'/148'/<index>'` via `stellar-agent-sep5`) from a pool master seed
//! held in the OS keyring.
//!
//! Key operations:
//!
//! - **`pool init --size N`**: funds N channel accounts on-chain via a single
//!   CAP-33 sponsored-reserve sandwich transaction.
//! - **`acquire()`**: allocates a free channel and returns a `ChannelLease`
//!   IMMEDIATELY, or returns `resource.pool_exhausted` if all channels are
//!   in-flight.
//! - **`release(lease, outcome)`**: returns the channel to `Free`, advancing
//!   the cached sequence on success or scheduling a re-fetch on `tx_bad_seq`.
//! - **`submit_pooled(pool, client, seed, passphrase, fee, timeout, ops)`**:
//!   acquires a channel, signs and submits a transaction with the caller-supplied
//!   operations, then releases.  Safe to call from N concurrent tasks with no
//!   `tx_bad_seq` from pool contention.
//!
//! ## Primary consumers
//!
//! - `stellar-agent-cli` — `pool init` / `pool list` / `pool status` subcommands.
//!
//! ## What this crate does NOT do
//!
//! - Does not submit transactions; submission is `stellar-agent-network`'s
//!   responsibility.
//! - Does not generate mnemonics; derivation is `stellar-agent-sep5`'s
//!   responsibility.
//! - Does not hold channel secrets persistently; secrets are re-derived on
//!   demand from the pool master in the OS keyring.
//!
//! ## Sibling crates
//!
//! - `stellar-agent-network` — RPC transport, submission, account fetch.
//! - `stellar-agent-sep5` — SEP-5 HD-path derivation.
//! - `stellar-agent-core` — profile, audit log, error taxonomy.

#![deny(unsafe_code)]
#![deny(missing_docs)]

pub mod allocator;
pub mod config;
pub mod derive;
pub mod error;
pub mod init;
pub mod pool;
pub mod submit;

// Re-export the core types from config (which re-exports from stellar-agent-core).
pub use config::{PoolChannelRecord, PoolConfig};
pub use error::PoolError;
pub use pool::{ChannelLease, ChannelPool, ChannelSnapshot, TerminalOutcome};
/// Alias: `ChannelRecord` is `PoolChannelRecord` (the same type from core).
///
/// Type identity: both refer to the same `stellar_agent_core::profile::schema::PoolChannelRecord`.
pub use stellar_agent_core::profile::schema::PoolChannelRecord as ChannelRecord;
pub use submit::{PoolSubmitResult, submit_pooled};
