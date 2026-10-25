//! Mainnet proof types that live in core: the verified signed policy, the
//! verified enablement record, and the fact-digest layout every mainnet proof
//! shares.
//!
//! The authorization types that compose these proofs, and the proofs that
//! need the network crate (endpoint identity, enrolled signer, cross-check
//! witness, window reservation, audit readiness), live in
//! `stellar_agent_network::mainnet`. The approval witness lives in
//! [`crate::approval::witness`].

/// The verified mainnet enablement of a profile.
pub mod enablement;

/// The fact-digest layout and labels of the mainnet proofs.
pub mod fact;

/// The verified signed policy of a mainnet profile and its mainnet section.
pub mod verified_policy;
