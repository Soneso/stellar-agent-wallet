//! Per-profile wallet configuration.
//!
//! This module provides the schema, loader, and migration machinery for
//! per-profile TOML configuration files.
//!
//! # Modules
//!
//! - `caip2` — CAIP-2 chain-ID enum (`stellar:testnet`, `stellar:mainnet`)
//!   and network-passphrase / RPC-URL resolution helpers.
//! - `schema` — [`crate::profile::schema::Profile`] struct (schema version 2)
//!   and supporting types including [`crate::profile::schema::PolicyEngineKind`]
//!   and [`crate::profile::schema::PolicyConfig`].
//! - `loader` — figment-backed loader (TOML + env-var + CLI overlay).
//! - `migrate` — version-dispatched migration command (`v1 → v2`).
//!
//! # Schema version 2
//!
//! Schema version 2 adds six fields to [`crate::profile::schema::Profile`]
//! beyond the v1 baseline:
//!
//! 1. `audit_log_hash_chain_key_id` — hash-chain audit-log root-signature key.
//! 2. `policy_owner_key_id` — policy-file owner ed25519 key.
//! 3. `attestation_key_id` — approval-spine HMAC key.
//! 4. `counterparty_cache_key_id` — `stellar.toml` cache-integrity HMAC key.
//! 5. `oracle_provider_url` — optional independent RPC URL for high-value
//!    cross-check.
//! 6. `policy.engine` — active [`crate::profile::schema::PolicyEngineKind`]
//!    (`Noop` or `V1`).
//!
//! # Loader dependency choice
//!
//! `figment` is used instead of the `config` crate because its source-merging
//! API is more idiomatic for the three-layer model (TOML file → env-var overlay
//! → CLI overlay) used here.  `figment` integrates natively with `serde` and
//! supports `Env` + ad-hoc overlay sources without additional glue.
//!
//! # Secret-material discipline
//!
//! No field in [`crate::profile::schema::Profile`] holds a secret.  The nonce
//! key and signer seed live in the platform keyring;
//! [`crate::profile::schema::KeyringEntryRef`] names the keyring entry without
//! holding the secret itself.  Profile TOML files are safe to include in
//! backups (with the understanding that the keyring backend provides the actual
//! secret-material defence).

pub mod caip2;
pub mod loader;
pub mod migrate;
pub mod receipt;
pub mod schema;

pub use caip2::{ChainIdValidationError, validate_chain_id_matches_profile};
pub use receipt::{
    BeginOutcome, ReceiptStatus, ReceiptStore, ReceiptStoreError, SubmissionReceipt,
};
pub use schema::{
    KeyringEntryRef, PolicyConfig, PolicyEngineKind, PoolChannelRecord, PoolConfig, Profile,
};
