//! Smart-account primitives for Soroban C-account authorisation.
//!
//! This module provides the foundational types and functions for building
//! and verifying smart-account authorisation flows on top of the OpenZeppelin
//! `stellar-accounts` context-rule model.
//!
//! # Key types
//!
//! - [`rule_id::ContextRuleId`] — `u32` per-context rule identifier,
//!   mirroring the OZ v0.7.2 on-chain representation
//!   (`AuthPayload::context_rule_ids: Vec<u32>`).
//! - [`auth_digest::AuthDigest`] — 32-byte SHA-256 auth digest.
//!
//! # Key functions
//!
//! - [`rule_id::encode_context_rule_ids`] — encodes a
//!   `&[ContextRuleId]` to the on-chain XDR byte layout
//!   (`ScVal::Vec(Some(ScVec([ScVal::U32(...)])))`) via `stellar-xdr`.
//! - [`auth_digest::compute_auth_digest`] — computes
//!   `sha256(signature_payload || context_rule_ids_xdr)`, the preimage
//!   that signers MUST sign to close the rule-ID downgrade attack.
//!
//! Together these types and functions implement the off-chain signing layer
//! that matches the on-chain computation in
//! OpenZeppelin `stellar-contracts` v0.7.2 (`smart_account/storage.rs`).
//! The byte layout produced by
//! [`rule_id::encode_context_rule_ids`] is verified against the OZ on-chain
//! call site.

pub mod auth_digest;
pub mod rule_id;
