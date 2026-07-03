//! Shared constants used across wallet crates.
//!
//! Constants in this module are public, non-secret values whose duplication
//! across production and test code would make audit trails harder to maintain.

/// All-zeros G-strkey used as a simulate-only fee-payer sentinel.
///
/// Used when no real fee-paying account is available before user approval.
/// The value is public: it is a Stellar account address whose Ed25519 public
/// key bytes are all zero. Soroban RPC `simulateTransaction` accepts it with a
/// synthetic sequence number for read-only simulations.
pub const SIMULATE_SENTINEL_G: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";

/// Wallet-wide high-value threshold in stroops.
///
/// Used as the diversification enforce-default trigger threshold: rules whose
/// policy criteria declare a `value_threshold` above this constant require
/// at least two distinct verifier wasm hashes. Rules whose criteria return
/// `Undetermined` from the value-threshold extractor are also treated as
/// above this threshold (fail-closed).
///
/// Derived from USD 10,000 at XLM = USD 0.10 (conservative — actual XLM
/// price is typically higher, so this threshold is lenient and minimises false
/// positives on legitimate low-value single-verifier rules):
///
/// 100,000 XLM × 10,000,000 stroops/XLM = 1,000,000,000,000 stroops.
pub const HIGH_VALUE_THRESHOLD_STROOPS: i64 = 1_000_000_000_000;
