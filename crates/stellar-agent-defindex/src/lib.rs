//! DeFindex vault adapter for the Stellar agent wallet.
//!
//! # What this crate does
//!
//! Implements the `stellar-agent-defi` `DefiAdapter` trait for the DeFindex
//! vault protocol, delivering these capabilities:
//!
//! - **Deposit/withdraw** — typed `VaultDepositArgs` + `VaultWithdrawArgs`
//!   preview and submit, no raw-vector or opaque-calldata signing; `min_out`
//!   required (absence = structural pre-sign refuse).
//! - **Roles** — four roles disclosed (Manager, EmergencyManager,
//!   RebalanceManager, VaultFeeReceiver) plus self-managed vs delegated detection
//!   and Blend-strategy detection by WASM hash.
//! - **Upgradable** — ordered trust gate refuses when
//!   `Upgradable:true`; opt-in override with distinct audit event.
//!
//! # Behavior
//!
//! - Deposit into a DeFindex vault with role disclosure and
//!   self-managed/delegated handling.
//! - Upgradable-true refusal; named override → distinct audit event.
//!
//! # Primary consumers
//!
//! - `stellar-agent-mcp` / `stellar-agent-cli` — dispatch the `vault` verb
//!   through the seam.
//!
//! # What this crate does NOT do
//!
//! - Flash-loan, zapper, or `rebalance` are out of scope.
//! - No new RPC client, simulate loop, or envelope builder — all reuse the
//!   existing submit and simulate paths.
//!
//! # Dependency direction
//!
//! `stellar-agent-defindex → stellar-agent-defi` (adapter/preview/pins/dispatch),
//! `→ stellar-agent-network` (RPC, WASM-hash fetch),
//! `→ stellar-agent-smart-account` (submit path),
//! `→ stellar-agent-core` (Criterion/EvalContext/redaction).
//!
//! NEVER `stellar-agent-defindex → stellar-agent-blend`.  The oracle-staleness
//! substrate is consumed from `stellar-agent-defi::oracle_staleness` directly.
//!
//! # ABI provenance
//!
//! DeFindex vault ABI bound from the DeFindex vault contract
//! `apps/contracts/vault/src/interface.rs`
//! (GPL-3.0, interface-bind only — NO source vendored).
//!
//! ## WASM hash source
//!
//! Testnet hashes sourced from root-level `public/testnet.contracts.json`
//! in the DeFindex contracts repository and confirmed on-chain via
//! `stellar contract invoke -- vault_wasm_hash`.
//! Pubnet hashes sourced from `apps/contracts/public/mainnet.contracts.json`.
//! The subdirectory `apps/contracts/public/testnet.contracts.json` contains
//! a pre-deployment hash and is NOT the authoritative testnet source.
//!
//! # `DataKey::Upgradable` ScVal encoding
//!
//! `DataKey::Upgradable` is a unit variant of a `#[contracttype]` enum.
//! Encoding per `soroban-sdk-macros 22.0.3` `derive_enum`
//! (unit-variant `into_xdr`): `ScVal::Symbol("Upgradable")` wrapped as
//! `(val,).try_into()` → `ScVal::Vec([ScVal::Symbol("Upgradable")])`.
//! The full key is therefore `ScVal::LedgerKey::ContractData { durability:
//! Instance, key: ScVal::Vec([Symbol("Upgradable")]) }`.
//!
//! # `RolesDataKey` ScVal encoding
//!
//! `RolesDataKey` is also a `#[contracttype]` enum with unit variants.
//! Same encoding: e.g. `RolesDataKey::Manager` →
//! `ScVal::Vec([ScVal::Symbol("Manager")])`.
//!
//! # Trust posture
//!
//! Upgradable:true delegated vaults are refused by default.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod abi;
pub mod adapter;
pub mod criteria;
pub mod pins;
pub mod preview;
pub mod roles;
pub mod scval;
pub mod storage;
pub mod value;
