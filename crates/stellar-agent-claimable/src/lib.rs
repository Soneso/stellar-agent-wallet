//! Claimable-balance domain logic for the Stellar agent wallet.
//!
//! Provides balance-id normalization ([`id`]), RPC fetch of a
//! `ClaimableBalanceEntry` and the claiming account's trustline state
//! ([`entry`]), `ClaimPredicate` evaluation ([`predicate`]), and a typed,
//! XDR-free claim preview with pure guard functions ([`preview`]).
//!
//! # Primary consumers
//!
//! The `claim` verb in `stellar-agent-cli` and the `stellar_claim` /
//! `stellar_claim_commit` tool pair in `stellar-agent-mcp`. This crate
//! provides only the substrate — no MCP tool or CLI verb is wired here.
//!
//! # Non-goals
//!
//! - No MCP tool registration.
//! - No CLI subcommand.
//! - No on-chain submission logic. Envelope construction for the
//!   `ClaimClaimableBalance` operation is
//!   [`stellar_agent_network::builder::ClassicOpBuilder::claim_claimable_balance`],
//!   which takes [`id::BalanceId::to_hex64`]'s output.
//! - No listing of claimable balances by claimant. Soroban RPC cannot
//!   enumerate ledger entries by claimant; that is a Horizon-only query, and
//!   this wallet is deliberately RPC-only. The verb this crate supports
//!   takes a balance id the agent already has (from the sender, an anchor
//!   SEP-24/6 response, or a `CreateClaimableBalance` transaction result).
//!
//! # Wall-clock preview vs. apply-ledger close time
//!
//! [`preview::ClaimPreview::build`] evaluates the claimant's predicate
//! against a caller-supplied `now`, typically the local wall-clock time at
//! preview build. The Stellar network evaluates `BeforeAbsoluteTime` /
//! `BeforeRelativeTime` predicates against the **apply ledger's close
//! time**, which lags wall-clock time by the network's block interval and
//! any submission latency. A claim previewed as satisfied when the
//! predicate's absolute-time boundary is only seconds away can still be
//! rejected on submit if the apply ledger closes after that boundary. This
//! crate does not attempt to compensate for that skew; a driver that wants
//! tighter guarantees should re-fetch the entry and re-evaluate immediately
//! before submission (see the crate's guard functions in [`preview`]).
//!
//! # No claimant reserve check
//!
//! Unlike creating a trustline or an account, claiming a balance does not
//! require the claiming account to hold additional minimum-reserve XLM. The
//! claimable balance's base reserve is paid by its *sponsor* at creation
//! time and returns to that sponsor when the balance is claimed or removed —
//! the claimant's own reserve requirement is unaffected. This crate
//! therefore has no reserve-affordability guard analogous to the trustline
//! verb's.
//!
//! # No SEP-29 memo check
//!
//! SEP-29 ("Account Memo Required") governs payments *to* an account that
//! has opted into requiring a memo. Claiming a balance credits the
//! claimant's *own* account via a `ClaimClaimableBalance` operation, not a
//! `Payment` to a third party, so SEP-29 does not apply here.

#![deny(missing_docs)]

pub mod entry;
pub mod error;
pub mod id;
pub mod predicate;
pub mod preview;
