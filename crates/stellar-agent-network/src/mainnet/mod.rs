//! Mainnet write authorization: the proofs network produces, the shared
//! digests, the one clock, and the authorization types that compose the
//! proofs into signing authority.
//!
//! - [`audit_readiness`]: the audit readiness proof and its producer.
//! - [`authorization`]: the five mainnet authorization types and their
//!   checks.
//! - [`clock`]: the clock the ledger, the signing points, and the submit gate
//!   share.
//! - [`digest`]: the content, entries, and bindings digests, and the shared
//!   subjects and labels by the names their consumers use.
//!
//! The authorization ledger lives in the window-state store,
//! [`crate::policy_state::ledger`]. The proofs core owns are in
//! `stellar_agent_core::mainnet` and `stellar_agent_core::approval::witness`.

pub mod audit_readiness;
pub mod authorization;
pub mod clock;
pub mod digest;
pub(crate) mod refusal;
pub(crate) mod types;

pub use refusal::{MainnetAuthorizationError, MainnetPrecondition};
pub use types::{
    AuditFacts, AuthorizationDomain, AuthorizationId, ConsumeBindingKind, HoldOwner,
    MainnetConsumer, MessageDomain, RecomputedFacts, SignerRole,
};
