//! Canonical Stellar protocol constants shared across all crates.
//!
//! Centralises `STROOPS_PER_XLM`, `BASE_RESERVE_STROOPS`, and
//! `DEFAULT_CLASSIC_FEE_STROOPS` so every tool handler, pre-flight check, and
//! test imports from a single authoritative location.

/// The number of stroops in one XLM (10,000,000).
///
/// Physically defined in [`crate::amount`] alongside the compile-time
/// assertion that ties it to `STELLAR_DECIMALS`; re-exported here so callers
/// can import all three Stellar protocol constants from one location without
/// depending on the `amount` module path.
pub use crate::amount::STROOPS_PER_XLM;

/// The Stellar protocol base reserve in stroops (0.5 XLM per reserve unit).
///
/// Per [CAP-0033](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0033.md)
/// the base reserve governs the minimum XLM an account must hold for each
/// subentry it owns (signers, trustlines, offers, data entries).  The value
/// is currently fixed at 0.5 XLM = 5_000_000 stroops; the Stellar Foundation
/// can adjust it via a ledger upgrade (Protocol 19+).
///
/// Every Stellar account has an implicit minimum reserve of
/// `(2 + subentry_count) * BASE_RESERVE_STROOPS` stroops that is not spendable.
/// The available native balance for transfers and fees is
/// `balance - (2 + subentry_count) * BASE_RESERVE_STROOPS`.
///
pub const BASE_RESERVE_STROOPS: i64 = 5_000_000;

/// Default classic-operation fee in stroops (100 stroops = 0.00001 XLM).
///
/// The Stellar protocol minimum base fee per operation is 100 stroops per
/// [CAP-0005](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0005.md).
/// Classic single-operation transactions (CreateAccount, Payment) submit with
/// this exact fee at normal network load.
///
/// The type is `u32` because the XDR `Transaction::fee` field is `Uint32`;
/// sub-stroop precision is not representable in the Stellar protocol.
///
pub const DEFAULT_CLASSIC_FEE_STROOPS: u32 = 100;
