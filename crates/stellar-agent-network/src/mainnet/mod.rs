//! Mainnet write authorization: the proofs network produces, the shared
//! digests, the one clock, and the authorization types that compose the
//! proofs into signing authority.
//!
//! - [`audit_readiness`]: the audit readiness proof and its producer.
//! - [`authorization`]: the five mainnet authorization types and their
//!   checks.
//! - [`clock`]: the clock the ledger, the signing points, and the submit gate
//!   share.
//! - [`consumed`]: the proof a mainnet send depends on, that the submission
//!   consumed its authorization.
//! - [`digest`]: the content, entries, and bindings digests, and the shared
//!   subjects and labels by the names their consumers use.
//! - [`message`]: the SEP-10 message facts, the message use receipt, and the
//!   check of a challenge against the receipt before the ephemeral key signs.
//! - [`soroban`]: the check of a Soroban authorization preimage against an
//!   intent authorization.
//!
//! The authorization ledger lives in the window-state store,
//! [`crate::policy_state::ledger`]. The proofs core owns are in
//! `stellar_agent_core::mainnet` and `stellar_agent_core::approval::witness`.

pub mod audit_readiness;
pub mod authorization;
pub mod clock;
pub mod consumed;
pub mod digest;
#[cfg(all(test, feature = "mainnet-write"))]
pub(crate) mod fixtures;
pub mod message;
#[cfg(feature = "mainnet-write")]
pub(crate) mod mint;
pub(crate) mod refusal;
pub mod resolve;
pub mod soroban;
pub(crate) mod types;

pub use refusal::{MainnetAuthorizationError, MainnetPrecondition};
pub use types::{
    AuditFacts, AuthorizationDomain, AuthorizationId, ConsumeBindingKind, HoldOwner,
    MainnetConsumer, MessageDomain, RecomputedFacts, SignerRole,
};
